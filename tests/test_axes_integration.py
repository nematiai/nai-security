from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, RequestFactory
from django.conf import settings as django_settings

from nai_security.models import SecuritySettings
from nai_security.handlers.axes_integration import (
    DynamicAxesHandler,
    get_dynamic_failure_limit,
)


class DynamicFailureLimitTest(TestCase):
    """Test the dynamic failure limit callable."""

    def setUp(self):
        self.factory = RequestFactory()
        cache.clear()
        # Reset singleton to defaults
        SecuritySettings.objects.update_or_create(
            pk=1,
            defaults={
                'max_login_attempts': 5,
                'axes_cooloff_minutes': 0,
                'axes_attempt_expiry_enabled': False,
            }
        )
        self.settings = SecuritySettings.get_settings()

    def test_returns_default_from_settings(self):
        request = self.factory.get('/')
        self.assertEqual(get_dynamic_failure_limit(request), 5)

    def test_returns_custom_limit(self):
        self.settings.max_login_attempts = 10
        self.settings.save()
        request = self.factory.get('/')
        self.assertEqual(get_dynamic_failure_limit(request), 10)

    def test_fallback_on_exception(self):
        django_settings.AXES_FAILURE_LIMIT_DEFAULT = 7
        with patch(
            'nai_security.models.SecuritySettings.get_settings',
            side_effect=Exception('db error'),
        ):
            request = self.factory.get('/')
            self.assertEqual(get_dynamic_failure_limit(request), 7)


class DynamicAxesHandlerConfigTest(TestCase):
    """Test configure_dynamic_settings."""

    def test_configure_sets_callable(self):
        DynamicAxesHandler.configure_dynamic_settings()
        self.assertTrue(callable(django_settings.AXES_FAILURE_LIMIT))

    def test_configure_preserves_original_as_fallback(self):
        django_settings.AXES_FAILURE_LIMIT = 3
        DynamicAxesHandler.configure_dynamic_settings()
        self.assertEqual(django_settings.AXES_FAILURE_LIMIT_DEFAULT, 3)


class CooloffTimeTest(TestCase):
    """Test cooloff time propagation via SecuritySettings.save()."""

    def test_zero_cooloff_sets_none(self):
        s = SecuritySettings.get_settings()
        s.axes_cooloff_minutes = 0
        s.save()
        self.assertIsNone(django_settings.AXES_COOLOFF_TIME)

    def test_nonzero_cooloff_sets_timedelta(self):
        s = SecuritySettings.get_settings()
        s.axes_cooloff_minutes = 30
        s.save()
        self.assertEqual(django_settings.AXES_COOLOFF_TIME, timedelta(minutes=30))

    def test_configure_reads_cooloff_from_db(self):
        s = SecuritySettings.get_settings()
        s.axes_cooloff_minutes = 15
        s.save()
        DynamicAxesHandler.configure_dynamic_settings()
        self.assertEqual(django_settings.AXES_COOLOFF_TIME, timedelta(minutes=15))


class AttemptExpiryTest(TestCase):
    """Test attempt expiry propagation via SecuritySettings.save()."""

    def setUp(self):
        cache.clear()
        SecuritySettings.objects.update_or_create(
            pk=1,
            defaults={
                'max_login_attempts': 5,
                'axes_cooloff_minutes': 0,
                'axes_attempt_expiry_enabled': False,
            }
        )

    def test_default_disabled(self):
        s = SecuritySettings.get_settings()
        self.assertFalse(s.axes_attempt_expiry_enabled)

    def test_save_propagates_enabled(self):
        s = SecuritySettings.get_settings()
        s.axes_attempt_expiry_enabled = True
        s.save()
        self.assertTrue(django_settings.AXES_USE_ATTEMPT_EXPIRATION)

    def test_save_propagates_disabled(self):
        s = SecuritySettings.get_settings()
        s.axes_attempt_expiry_enabled = False
        s.save()
        self.assertFalse(django_settings.AXES_USE_ATTEMPT_EXPIRATION)

    def test_configure_reads_expiry_from_db(self):
        s = SecuritySettings.get_settings()
        s.axes_attempt_expiry_enabled = True
        s.save()
        DynamicAxesHandler.configure_dynamic_settings()
        self.assertTrue(django_settings.AXES_USE_ATTEMPT_EXPIRATION)
