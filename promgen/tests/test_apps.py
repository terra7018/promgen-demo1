# Copyright (c) 2026 LINE Corporation
# These sources are released under the terms of the MIT license: see LICENSE
from django.apps import apps
from django.contrib.auth.models import User
from django.core.management.sql import emit_post_migrate_signal
from django.test import TestCase


class PostMigrateTest(TestCase):
    def test_post_migrate_does_not_create_superuser(self):
        self.assertFalse(User.objects.filter(is_superuser=True).exists())
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default", apps=apps, plan=[])
        self.assertFalse(User.objects.filter(is_superuser=True).exists())
