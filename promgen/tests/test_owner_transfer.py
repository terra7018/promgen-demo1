# Copyright (c) 2026 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE
from django.contrib.auth.models import User
from django.urls import reverse
from guardian.shortcuts import assign_perm, get_user_perms

from promgen import models, permissions, tests


class OwnerTransferTest(tests.PromgenTest):
    def setUp(self):
        self.previous_owner = User.objects.get(username="demo")
        self.new_owner = User.objects.create_user(username="new-owner")
        self.admin = User.objects.get(username="admin")

    def test_api_project_transfer_retains_parent_service_access(self):
        service = models.Service.objects.create(name="Transfer Service", owner=self.previous_owner)
        project = models.Project.objects.create(
            name="Transfer Project",
            owner=self.previous_owner,
            service=service,
            shard_id=1,
        )
        token = models.AuthToken.objects.get(user=self.admin).token_key
        url = reverse("api-v2:project-detail", kwargs={"id": project.pk})

        response = self.client.patch(
            url,
            data={"owner": self.new_owner.pk},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {token}",
        )

        self.assertEqual(response.status_code, 200)
        project.refresh_from_db()
        self.assertEqual(project.owner, self.new_owner)
        self.assertNotIn("project_admin", get_user_perms(self.previous_owner, project))
        self.assertIn("project_admin", get_user_perms(self.new_owner, project))
        self.assertTrue(permissions.has_perm(self.previous_owner, ["service_admin"], project))

        response = self.client.patch(
            url,
            data={"description": "Updated without transfer"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {token}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("project_admin", get_user_perms(self.new_owner, project))

    def test_api_service_transfer_retains_group_access(self):
        service = models.Service.objects.create(name="Transfer Service", owner=self.previous_owner)
        group = models.Group.objects.create(name="Transfer Admins")
        group.user_set.add(self.previous_owner)
        assign_perm("service_admin", group, service)
        token = models.AuthToken.objects.get(user=self.admin).token_key

        response = self.client.patch(
            reverse("api-v2:service-detail", kwargs={"id": service.pk}),
            data={"owner": self.new_owner.pk},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {token}",
        )

        self.assertEqual(response.status_code, 200)
        service.refresh_from_db()
        self.assertEqual(service.owner, self.new_owner)
        self.assertNotIn("service_admin", get_user_perms(self.previous_owner, service))
        self.assertIn("service_admin", get_user_perms(self.new_owner, service))
        self.assertTrue(permissions.has_perm(self.previous_owner, ["service_admin"], service))

    def test_web_project_transfer_revokes_previous_admin(self):
        service = models.Service.objects.create(name="Transfer Service", owner=self.admin)
        project = models.Project.objects.create(
            name="Transfer Project",
            owner=self.previous_owner,
            service=service,
            shard_id=1,
        )
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("project-update", kwargs={"pk": project.pk}),
            {
                "name": project.name,
                "owner": self.new_owner.pk,
                "service": service.pk,
                "shard": project.shard_id,
            },
        )

        self.assertEqual(response.status_code, 302)
        project.refresh_from_db()
        self.assertEqual(project.owner, self.new_owner)
        self.assertNotIn("project_admin", get_user_perms(self.previous_owner, project))
        self.assertIn("project_admin", get_user_perms(self.new_owner, project))
        self.assertFalse(
            permissions.has_perm(self.previous_owner, ["project_admin", "service_admin"], project)
        )

    def test_web_service_transfer_revokes_previous_admin(self):
        service = models.Service.objects.create(name="Transfer Service", owner=self.previous_owner)
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("service-update", kwargs={"pk": service.pk}),
            {"name": service.name, "owner": self.new_owner.pk},
        )

        self.assertEqual(response.status_code, 302)
        service.refresh_from_db()
        self.assertEqual(service.owner, self.new_owner)
        self.assertNotIn("service_admin", get_user_perms(self.previous_owner, service))
        self.assertIn("service_admin", get_user_perms(self.new_owner, service))
        self.assertFalse(permissions.has_perm(self.previous_owner, ["service_admin"], service))
