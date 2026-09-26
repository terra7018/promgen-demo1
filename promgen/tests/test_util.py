# Copyright (c) 2026 LY Corporation
# These sources are released under the terms of the MIT license: see LICENSE

import ipaddress
from unittest import mock

from django.test import SimpleTestCase, override_settings
from requests import HTTPError
from requests.models import Response

from promgen import util


class UtilTest(SimpleTestCase):
    def test_categorize_error(self):
        response = Response()
        response.status_code = 404

        cases = [
            (ImportError("missing dependency"), "import_error"),
            (HTTPError(response=response), "404_http_error"),
            (HTTPError(), "other_error"),
            (ValueError("bad input"), "other_error"),
        ]

        for error, expected in cases:
            with self.subTest(error=type(error).__name__, expected=expected):
                self.assertEqual(util.categorize_error(error), expected)


class EgressTest(SimpleTestCase):
    PUBLIC = [ipaddress.ip_address("93.184.216.34")]

    def test_rejects_blocked_destinations(self):
        cases = [
            "ftp://example.com/",
            "file:///etc/passwd",
            "http://",
            "http://user:pass@example.com/",
            "http://example.com:99999/",
            "http://127.0.0.1:6379/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
        ]
        for url in cases:
            with self.subTest(url=url):
                with self.assertRaises(util.EgressError):
                    util.validate_egress_url(url)

    @mock.patch("promgen.util.resolve_hostname")
    def test_rejects_hostname_resolving_to_internal(self, mock_resolve):
        mock_resolve.return_value = [ipaddress.ip_address("169.254.169.254")]
        with self.assertRaises(util.EgressError):
            util.validate_egress_url("http://metadata.example.com/")

    @mock.patch("promgen.util.resolve_hostname")
    def test_allows_public(self, mock_resolve):
        mock_resolve.return_value = self.PUBLIC
        self.assertEqual(util.validate_egress_url("https://hooks.example.com/x"), self.PUBLIC)
        self.assertEqual(util.validate_egress_url("http://93.184.216.34:8080/metrics"), self.PUBLIC)

    @override_settings(PROMGEN={"egress": {"allow_private": True}})
    def test_allow_private_setting(self):
        util.validate_egress_url("http://10.0.0.5:9100/metrics")
        with self.assertRaises(util.EgressError):
            util.validate_egress_url("http://169.254.169.254/")
        with self.assertRaises(util.EgressError):
            util.validate_egress_url("http://127.0.0.1/")

    @override_settings(PROMGEN={"egress": {"allowed_hosts": ["localhost"]}})
    def test_allowed_hosts_setting(self):
        util.validate_egress_url("http://localhost:9090/")
        with self.assertRaises(util.EgressError):
            util.validate_egress_url("http://127.0.0.1/")

    @mock.patch("promgen.util.resolve_hostname")
    @mock.patch("promgen.util.post")
    def test_egress_post(self, mock_post, mock_resolve):
        mock_resolve.return_value = self.PUBLIC
        util.egress_post("http://hooks.example.com/", json={})
        mock_post.assert_called_once_with(
            "http://hooks.example.com/", json={}, allow_redirects=False, session=mock.ANY
        )
        session = mock_post.call_args[1]["session"]
        self.assertIsInstance(session.get_adapter("http://x"), util.PinnedAdapter)

        with self.assertRaises(util.EgressError):
            util.egress_post("http://127.0.0.1/", json={})
        mock_post.assert_called_once()

    @staticmethod
    def _response(*args, **kwargs):
        response = Response()
        response.status_code = 200
        response._content = b""
        return response

    @mock.patch("promgen.util.resolve_hostname")
    @mock.patch("requests.adapters.HTTPAdapter.send")
    def test_pinned_to_validated_address(self, mock_send, mock_resolve):
        # The connection must go to the address that passed validation even if
        # the hostname would resolve to something else by the time we connect
        mock_resolve.return_value = self.PUBLIC
        mock_send.side_effect = self._response
        util.egress_post("https://hooks.example.com:8443/x", json={})
        request = mock_send.call_args[0][0]
        self.assertEqual(request.url, "https://93.184.216.34:8443/x")
        self.assertEqual(request.headers["Host"], "hooks.example.com:8443")

        adapter = util.PinnedAdapter("hooks.example.com", self.PUBLIC[0])
        _, pool_kwargs = adapter.build_connection_pool_key_attributes(request, verify=True)
        self.assertEqual(pool_kwargs["server_hostname"], "hooks.example.com")
        self.assertEqual(pool_kwargs["assert_hostname"], "hooks.example.com")

    @mock.patch("promgen.util.resolve_hostname")
    @mock.patch("requests.adapters.HTTPAdapter.send")
    def test_egress_scrape(self, mock_send, mock_resolve):
        mock_resolve.return_value = self.PUBLIC
        mock_send.side_effect = self._response
        util.egress_scrape("http://node.example.com:9100/metrics")
        request = mock_send.call_args[0][0]
        self.assertEqual(request.url, "http://93.184.216.34:9100/metrics")
        self.assertEqual(request.headers["Host"], "node.example.com:9100")
