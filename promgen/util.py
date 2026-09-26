# Copyright (c) 2017 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE

import argparse
import hashlib
import ipaddress
import math
import socket
from urllib.parse import urlsplit, urlunsplit

import requests
import requests.adapters
from django.conf import settings
from django.db.models import F
from django.http import HttpResponse

# Wrappers around request api to ensure we always attach our user agent
# https://github.com/requests/requests/blob/master/requests/api.py


USER_AGENT = f"promgen/{settings.PROMGEN_VERSION}"
ACCEPT_HEADER = (
    "application/openmetrics-text; version=0.0.1,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"
)


def post(url, data=None, json=None, **kwargs):
    session = kwargs.pop("session", requests)
    headers = kwargs.setdefault("headers", {})
    headers["User-Agent"] = USER_AGENT
    return session.post(url, data=data, json=json, **kwargs)


def get(url, params=None, **kwargs):
    headers = kwargs.setdefault("headers", {})
    headers["User-Agent"] = USER_AGENT
    return requests.get(url, params=params, **kwargs)


def delete(url, **kwargs):
    headers = kwargs.setdefault("headers", {})
    headers["User-Agent"] = USER_AGENT
    return requests.delete(url, **kwargs)


def scrape(url, params=None, **kwargs):
    """
    Scrape Prometheus target

    Light wrapper around requests.get so that we add required
    Accept headers that a target might expect
    """
    headers = kwargs.setdefault("headers", {})
    headers["Accept"] = ACCEPT_HEADER
    headers["User-Agent"] = USER_AGENT
    headers["X-Prometheus-Scrape-Timeout-Seconds"] = "10.0"
    # According to the spec, having the host with a port is optional, though
    # so by default, many clients/servers drop the port if it's known (http/https)
    # in the case of Prometheus it always forces the port in the Host header which
    # then sometimes fail for servers that do not expect it. Here we force the port
    # in the Host header to make it match how Prometheus scrapes
    # https://github.com/prometheus/prometheus/blob/2b55017379786873dc00315ffe65e22ad7026abb/scrape/target.go#L375-L387
    headers["Host"] = urlsplit(url).netloc
    session = kwargs.pop("session", requests)
    return session.get(url, params=params, **kwargs)


EGRESS_SCHEMES = ("http", "https")


class EgressError(ValueError):
    """
    Raised when a user supplied destination URL is not allowed to be requested
    """


def resolve_hostname(hostname):
    """
    Resolve a hostname to the list of IP addresses it points at
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise EgressError(f"Unable to resolve host {hostname}") from e
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _egress_blocked(address, allow_private):
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    ):
        return True
    return address.is_private and not allow_private


def validate_egress_url(url):
    """
    Validate a user supplied destination before Promgen makes a request to it

    Only http(s) URLs without embedded credentials are allowed, and the host
    must not resolve to loopback, link-local, or (unless configured via the
    ``egress:allow_private`` setting) private addresses. Hosts listed under
    ``egress:allowed_hosts`` are always permitted.

    Returns the list of addresses that were validated so that callers can pin
    the connection to one of them (empty for allowlisted hosts).
    """
    if not isinstance(url, str):
        raise EgressError("Invalid URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise EgressError(f"Invalid URL: {e}") from e

    if parts.scheme not in EGRESS_SCHEMES:
        raise EgressError(f"Unsupported scheme: {parts.scheme or 'none'}")
    if parts.username is not None or parts.password is not None:
        raise EgressError("Credentials in URL are not allowed")
    if port is not None and not 0 < port < 65536:
        raise EgressError(f"Invalid port: {port}")

    hostname = parts.hostname
    if not hostname:
        raise EgressError("Missing host")

    if hostname in setting("egress:allowed_hosts", default=[]):
        return []

    allow_private = bool(setting("egress:allow_private", default=False))
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        addresses = resolve_hostname(hostname)

    for address in addresses:
        if _egress_blocked(address, allow_private):
            raise EgressError(f"Destination {hostname} ({address}) is not allowed")
    return addresses


class PinnedAdapter(requests.adapters.HTTPAdapter):
    """
    Transport adapter that connects to a previously resolved address

    Connecting to the address that was validated (instead of resolving the
    hostname a second time) prevents DNS rebinding from redirecting the
    request to a blocked destination. The original hostname is kept for the
    Host header, SNI and certificate verification.
    """

    def __init__(self, hostname, address, **kwargs):
        self.hostname = hostname
        self.address = address
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        parts = urlsplit(request.url)
        host = f"[{self.address}]" if self.address.version == 6 else str(self.address)
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        request.headers.setdefault("Host", parts.netloc)
        request.url = urlunsplit(parts._replace(netloc=netloc))
        return super().send(request, **kwargs)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(
            request, verify, cert
        )
        if host_params["scheme"] == "https":
            pool_kwargs["server_hostname"] = self.hostname
            pool_kwargs["assert_hostname"] = self.hostname
        return host_params, pool_kwargs


def egress_session(url):
    """
    Validate a user supplied destination and return a session pinned to the
    address that passed validation
    """
    addresses = validate_egress_url(url)
    session = requests.Session()
    if addresses:
        hostname = urlsplit(url).hostname
        adapter = PinnedAdapter(hostname, addresses[0])
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


def egress_post(url, **kwargs):
    """
    POST to a user supplied destination after validating it
    """
    session = egress_session(url)
    kwargs.setdefault("allow_redirects", False)
    return post(url, session=session, **kwargs)


def egress_scrape(url, **kwargs):
    """
    Scrape a user supplied target after validating it
    """
    session = egress_session(url)
    kwargs.setdefault("allow_redirects", False)
    return scrape(url, session=session, **kwargs)


def setting(key, default=None, domain=None):
    """
    Settings helper based on saltstack's query

    Allows a simple way to query settings from YAML
    using the style `path:to:key` to represent

    path:
      to:
        key: value
    """
    rtn = settings.PROMGEN
    lookup = key.split(":")

    if domain:
        lookup.insert(0, domain)

    for index in lookup:
        try:
            rtn = rtn[index]
        except KeyError:
            if default is not KeyError:
                return default
            raise KeyError(f"Missing required setting: {key}")
    return rtn


def inc_for_pk(model, pk, **kwargs):
    # key=F('key') + value
    model.objects.filter(pk=pk).update(**{key: F(key) + kwargs[key] for key in kwargs})


def cast(klass):
    """
    Used with argparse to cast to a Django model

    Example:
    parser.add_argument("project", type=util.cast(models.Project))
    """

    def wrapped(value):
        try:
            return klass.objects.get(name=value)
        except klass.DoesNotExist:
            raise argparse.ArgumentTypeError("Unable to find :%s" % value)

    return wrapped


def help_text(klass):
    """
    Used with argparse to lookup help_text for a Django model

    Example:
    help_text = util.help_text(models.Host)
    parser.add_argument("host", help=help_text("name"))
    """

    def wrapped(field):
        return klass._meta.get_field(field).help_text

    return wrapped


def proxy_error(response: requests.Response) -> HttpResponse:
    """
    Return a wrapped proxy error

    Taking a request.response object as input, return it slightly modified
    with an extra header for debugging so that we can see where the request
    failed
    """
    r = HttpResponse(
        response.content,
        content_type=response.headers["content-type"],
        status=response.status_code,
    )
    r.setdefault("X-PROMGEN-PROXY", response.url)
    return r


# Convert Prometheus's Histogram/Quantile float representation to Go string
# https://github.com/prometheus/client_python/blob/master/prometheus_client/utils.py#L9
def float_to_go_string(d):
    d = float(d)
    if d == float("inf"):
        return "+Inf"
    elif d == float("-inf"):
        return "-Inf"
    elif math.isnan(d):
        return "NaN"
    else:
        s = repr(d)
        dot = s.find(".")
        # Go switches to exponents sooner than Python.
        # We only need to care about positive values for le/quantile.
        if d > 0 and dot > 6:
            mantissa = f"{s[0]}.{s[1:dot]}{s[dot + 1 :]}".rstrip("0.")
            return f"{mantissa}e+0{dot - 1}"
        return s


def categorize_error(e: Exception) -> str:
    """
    Categorize an exception into a string label
    """
    if isinstance(e, ImportError):
        return "import_error"
    elif isinstance(e, requests.HTTPError):
        return (
            str(e.response.status_code) + "_http_error" if e.response is not None else "other_error"
        )
    else:
        return "other_error"


def fingerprint(body):
    buff = ""
    for k, v in sorted(body.get("groupLabels", {}).items()):
        buff += k
        buff += v

    return hashlib.sha1(buff.encode("utf8")).hexdigest()


def truncate_json_fields(data, default_limits=128):
    """
    Recursively truncate fields in a JSON object.

    Args:
        data: The JSON to process.
        default_limits (int): Default maximum length for fields not specified.

    Returns:
        A new JSON with truncated fields.
    """
    # A given field-length mapping for specifying the maximum lengths of fields in Promgen models
    LOG_FIELD_LIMITS = {
        "clause": 8192,  # Rule
    }

    if isinstance(data, list):
        return [
            truncate_json_fields(item, default_limits)
            if isinstance(item, (dict, list))
            else item[:default_limits]
            + ("..." if isinstance(item, str) and len(item) > default_limits else "")
            if isinstance(item, str)
            else item
            for item in data
        ]

    truncated_data = {}
    if getattr(data, "items", None) is None:
        return None
    for field, value in data.items():
        if isinstance(value, (dict, list)):
            truncated_data[field] = truncate_json_fields(value, default_limits)
        elif field in LOG_FIELD_LIMITS and isinstance(value, str):
            truncated_data[field] = value[: LOG_FIELD_LIMITS[field]] + (
                "..." if len(value) > LOG_FIELD_LIMITS[field] else ""
            )
        elif isinstance(value, str):
            truncated_data[field] = value[:default_limits] + (
                "..." if len(value) > default_limits else ""
            )
        else:
            truncated_data[field] = value
    return truncated_data


# Comment wrappers to get the docstrings from the upstream functions
get.__doc__ = requests.get.__doc__
post.__doc__ = requests.post.__doc__
delete.__doc__ = requests.delete.__doc__
