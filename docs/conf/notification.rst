Configuring Notification Plugins
================================

Different settings for the Notification Plugins can be defined in the ``promgen.yml`` file.

Email
---------------------

An SMTP server for sending outgoing mail can be configured by adding Django email settings
(see :ref:`smtp_config`).
The **email's sender address** either can be set using the ``DEFAULT_FROM_EMAIL`` Django setting
or by setting the ``sender`` configuration as shown below. If both are set, the ``sender``
configuration will take precedence.

.. code-block:: yaml

    promgen.notification.email:
      sender: promgen@example.com

PagerDuty
---------------------

PagerDuty API-compatible URLs and alert severity mapping can be configured this way:

.. code-block:: yaml

    promgen.notification.pagerduty:
      urls:
        PagerDuty: https://events.pagerduty.com/v2/enqueue
        OtherServer: https://compatible.pagerduty.server/api/enqueue
      severity_mapping:
        debug: info
        major: error
        minor: warning

Slack
---------------------

The proxy configuration specifies the proxy server that Promgen should use when sending
notifications to Slack. This is useful if your environment requires outgoing requests to go
through a proxy for security or network policy reasons. If your environment does not require a
proxy, you can basically ignore this setting or set it to an empty string.

.. code-block:: yaml

    promgen.notification.slack:
      proxy: http://slack-proxy.example.com:8080

Outbound Request Policy
---------------------

User supplied destinations (webhook, Slack and Alertmanager notifier URLs, and the
exporter scrape test) are validated before Promgen sends a request to them. Only
``http`` and ``https`` URLs without embedded credentials are allowed, redirects are not
followed, and the destination host must not resolve to a loopback, link-local or
private (RFC1918) address. The request is sent to the address that passed validation
(the hostname is not resolved a second time) so that DNS rebinding cannot redirect it.
Deployments that need to notify or scrape hosts on a private network can relax this with
the ``egress`` section:

.. code-block:: yaml

    egress:
      # Allow destinations that resolve to RFC1918 / private addresses.
      # Loopback and link-local (e.g. cloud metadata) addresses are always blocked.
      allow_private: true
      # Hostnames that are always allowed regardless of the address they resolve to.
      allowed_hosts:
        - alertmanager.internal
