# Copyright (c) 2026 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE
from http import HTTPStatus
from unittest import mock

from django.urls import reverse

from promgen import models, tests

QUERY_RESPONSE = {
    "status": "success",
    "data": {"resultType": "vector", "result": [{"metric": {"job": "a"}, "value": [0, "1"]}]},
}

PROXY_URLS = [
    "/api/v1/labels",
    "/api/v1/label/job/values",
    "/api/v1/series?match[]=up",
    "/api/v1/query_range?query=up",
    "/api/v1/query?query=up",
]


class ProxyAuthTest(tests.PromgenTest):
    fixtures = ["testcases.yaml", "extras.yaml"]

    @mock.patch("promgen.util.get")
    def test_anonymous_rejected(self, mock_get):
        for url in PROXY_URLS:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        mock_get.assert_not_called()

    def test_graph_requires_login(self):
        response = self.client.get("/graph")
        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        self.assertTrue(response.url.startswith(reverse("login")))

    @mock.patch("promgen.util.get")
    def test_session_authenticated(self, mock_get):
        mock_get.return_value.json.return_value = QUERY_RESPONSE
        self.force_login(username="demo")
        response = self.client.get(reverse("proxy-query"), {"query": "up"})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), QUERY_RESPONSE)
        mock_get.assert_called_once()

        response = self.client.get("/graph")
        self.assertEqual(response.status_code, HTTPStatus.OK)

    @mock.patch("promgen.util.get")
    def test_token_authenticated(self, mock_get):
        mock_get.return_value.json.return_value = QUERY_RESPONSE
        token = models.AuthToken.objects.filter(user__username="demo").first().token_key
        response = self.client.get(
            reverse("proxy-query"), {"query": "up"}, HTTP_AUTHORIZATION=f"Token {token}"
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), QUERY_RESPONSE)

    @mock.patch("promgen.util.get")
    def test_rule_test_queries_shards_directly(self, mock_get):
        mock_get.return_value.json.return_value = QUERY_RESPONSE
        self.force_login(username="demo")
        response = self.client.post(
            reverse("rule-test", kwargs={"pk": 1}), {"query": "up", "target": "#result"}
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        mock_get.assert_called_once()
        self.assertTrue(
            mock_get.call_args.args[0].startswith("http://prometheus.example.com/api/v1/query?")
        )
