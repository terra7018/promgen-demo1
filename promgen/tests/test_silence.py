# Copyright (c) 2017 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE

import datetime
from unittest import mock

from django.test import override_settings
from django.urls import reverse

from promgen import errors, forms, tests

TEST_SETTINGS = tests.Data("examples", "promgen.yml").yaml()
TEST_DURATION = tests.Data("examples", "silence.duration.json").json()
TEST_RANGE = tests.Data("examples", "silence.range.json").json()

# Explicitly set a timezone for our test to try to catch conversion errors
TEST_SETTINGS["timezone"] = "Asia/Tokyo"


class SilenceTest(tests.PromgenTest):
    fixtures = ["testcases.yaml", "extras.yaml"]

    def setUp(self):
        self.user = self.force_login(username="admin")

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_duration(self, mock_post):
        mock_post.return_value.status_code = 200

        with mock.patch("django.utils.timezone.now") as mock_now:
            mock_now.return_value = datetime.datetime(2017, 12, 14, tzinfo=datetime.timezone.utc)
            # I would prefer to be able to test with multiple labels, but since
            # it's difficult to test a list of dictionaries (the order is non-
            # deterministic) we just test with a single label for now
            self.client.post(
                reverse("proxy-silence"),
                data={
                    "duration": "1m",
                    "labels": {"instance": "example.com:[0-9]*"},
                },
                content_type="application/json",
            )
        mock_post.assert_called_with("http://alertmanager:9093/api/v2/silences", json=TEST_DURATION)

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_range(self, mock_post):
        mock_post.return_value.status_code = 200

        with mock.patch("django.utils.timezone.now") as mock_now:
            mock_now.return_value = datetime.datetime(2017, 12, 14, tzinfo=datetime.timezone.utc)
            self.client.post(
                reverse("proxy-silence"),
                data={
                    "startsAt": "2017-12-14 00:01",
                    "endsAt": "2017-12-14 00:05",
                    "labels": {"instance": "example.com:[0-9]*"},
                },
                content_type="application/json",
            )

        mock_post.assert_called_with("http://alertmanager:9093/api/v2/silences", json=TEST_RANGE)

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_v2_requires_authentication(self, mock_post):
        self.client.logout()
        response = self.client.post(
            reverse("proxy-silence-v2"),
            data={
                "duration": "1m",
                "matchers": [
                    {"name": "project", "value": "unknown", "isRegex": False, "isEqual": True}
                ],
            },
            content_type="application/json",
        )
        self.assertIn(response.status_code, [401, 403])
        mock_post.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_v2_denies_user_without_project_permission(self, mock_post):
        self.force_login(username="demo")
        response = self.client.post(
            reverse("proxy-silence-v2"),
            data={
                "duration": "1m",
                "matchers": [
                    {"name": "project", "value": "test-project", "isRegex": False, "isEqual": True}
                ],
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        mock_post.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_v1_requires_authentication(self, mock_post):
        self.client.logout()
        response = self.client.post(
            reverse("proxy-silence"),
            data={"duration": "1m", "labels": {"project": "unknown"}},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("messages", response.json())
        mock_post.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_v1_enforces_csrf_for_session_clients(self, mock_post):
        self.client = self.client_class(enforce_csrf_checks=True)
        self.force_login(username="admin")
        response = self.client.post(
            reverse("proxy-silence"),
            data={"duration": "1m", "labels": {"instance": "example.com"}},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        mock_post.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.delete")
    @mock.patch("promgen.util.get")
    def test_delete_enforces_csrf_for_session_clients(self, mock_get, mock_delete):
        self.client = self.client_class(enforce_csrf_checks=True)
        self.force_login(username="admin")
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"matchers": []}
        response = self.client.delete(reverse("proxy-silence-delete", args=["abc"]))
        self.assertEqual(response.status_code, 403)
        mock_delete.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.delete")
    @mock.patch("promgen.util.get")
    def test_delete_requires_authentication(self, mock_get, mock_delete):
        self.client.logout()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "matchers": [{"name": "project", "value": "unknown", "isRegex": False, "isEqual": True}]
        }
        response = self.client.delete(reverse("proxy-silence-delete", args=["abc"]))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("messages", response.json())
        mock_delete.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.delete")
    @mock.patch("promgen.util.get")
    def test_delete_denies_unmatched_silence_for_non_superuser(self, mock_get, mock_delete):
        self.force_login(username="demo")
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "matchers": [{"name": "project", "value": "unknown", "isRegex": False, "isEqual": True}]
        }
        response = self.client.delete(reverse("proxy-silence-delete", args=["abc"]))
        self.assertEqual(response.status_code, 403)
        mock_delete.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.delete")
    @mock.patch("promgen.util.get")
    def test_delete_denies_silence_without_project_or_service_for_non_superuser(
        self, mock_get, mock_delete
    ):
        self.force_login(username="demo")
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "matchers": [
                {"name": "instance", "value": "example.com", "isRegex": False, "isEqual": True}
            ]
        }
        response = self.client.delete(reverse("proxy-silence-delete", args=["abc"]))
        self.assertEqual(response.status_code, 403)
        mock_delete.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.delete")
    @mock.patch("promgen.util.get")
    def test_delete_allows_superuser_for_unmatched_silence(self, mock_get, mock_delete):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "matchers": [{"name": "project", "value": "unknown", "isRegex": False, "isEqual": True}]
        }
        mock_delete.return_value.status_code = 200
        mock_delete.return_value.text = "{}"
        response = self.client.delete(reverse("proxy-silence-delete", args=["abc"]))
        self.assertEqual(response.status_code, 200)
        mock_delete.assert_called_once()

    @override_settings(PROMGEN=TEST_SETTINGS)
    @mock.patch("promgen.util.post")
    def test_v2_denies_unmatched_silence_for_non_superuser(self, mock_post):
        self.force_login(username="demo")
        response = self.client.post(
            reverse("proxy-silence-v2"),
            data={
                "duration": "1m",
                "matchers": [
                    {"name": "project", "value": "unknown", "isRegex": False, "isEqual": True}
                ],
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        mock_post.assert_not_called()

    @override_settings(PROMGEN=TEST_SETTINGS)
    def test_site_silence_errors(self):
        form = forms.SilenceForm(
            data={"labels": {}, "duration": "1m", "createdBy": self.user.username}
        )
        self.assertEqual(
            form.errors.as_data(),
            {"__all__": [errors.SilenceError.NOLABEL.error()]},
        )

        form = forms.SilenceForm(
            data={
                "labels": {"alertname": "example-rule"},
                "duration": "1m",
                "createdBy": self.user.username,
            }
        )
        self.assertEqual(
            form.errors.as_data(),
            {"__all__": [errors.SilenceError.GLOBALSILENCE.error()]},
        )

        form = forms.SilenceForm(
            data={
                "labels": {"alertname": "example-rule", "foo": "bar"},
                "duration": "1m",
                "createdBy": self.user.username,
            }
        )
        self.assertEqual(
            form.errors.as_data(),
            {"__all__": [errors.SilenceError.GLOBALSILENCE.error()]},
        )

        form = forms.SilenceForm(
            data={
                "labels": {"alertname": "example-rule", "service": "foo"},
                "duration": "1m",
                "createdBy": self.user.username,
            }
        )
        self.assertEqual(form.errors, {}, "Expected no errors")
        self.assertEqual(
            form.cleaned_data,
            {
                "comment": "Silenced from Promgen",
                "createdBy": self.user.username,
                "duration": "1m",
                "endsAt": "",
                "labels": {"alertname": "example-rule", "service": "foo"},
                "startsAt": "",
            },
        )
