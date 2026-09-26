# Copyright (c) 2019 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE
from unittest import mock

from django.test import override_settings
from django.urls import reverse

from promgen import tests

URLS = ["/api/v1/config", "/api/v1/rules", "/api/v1/targets", "/api/v1/urls"]


class LegacyApiAuthTest(tests.PromgenTest):
    @override_settings(PROMGEN=tests.SETTINGS)
    def test_anonymous_get_denied(self):
        for url in URLS:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 401)

    @override_settings(PROMGEN=tests.SETTINGS)
    def test_anonymous_post_denied(self):
        for url in ["/api/v1/config", "/api/v1/urls"]:
            with self.subTest(url=url):
                response = self.client.post(url, data="{}", content_type="application/json")
                self.assertEqual(response.status_code, 401)

    @override_settings(PROMGEN=tests.SETTINGS)
    def test_authenticated_get_allowed(self):
        self.force_login(username="demo")
        for url in URLS:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    @override_settings(PROMGEN=tests.SETTINGS)
    def test_accept_header_ignored(self):
        self.force_login(username="demo")
        response = self.client.get("/api/v1/rules", HTTP_ACCEPT="application/x-yaml")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-yaml")

    @override_settings(PROMGEN=tests.SETTINGS)
    @mock.patch("promgen.tasks.write_urls")
    def test_non_superuser_post_denied(self, mock_write):
        self.force_login(username="demo")
        for url in ["/api/v1/config", "/api/v1/urls"]:
            with self.subTest(url=url):
                response = self.client.post(url, data="{}", content_type="application/json")
                self.assertEqual(response.status_code, 403)
        mock_write.assert_not_called()

    @override_settings(PROMGEN=tests.SETTINGS)
    @mock.patch("promgen.tasks.write_urls")
    def test_superuser_post_allowed(self, mock_write):
        self.force_login(username="admin")
        response = self.client.post(reverse("config-urls"))
        self.assertEqual(response.status_code, 202)
        mock_write.assert_called_once()

        response = self.client.post(
            reverse("config-targets"), data="[]", content_type="application/json"
        )
        self.assertEqual(response.status_code, 202)
