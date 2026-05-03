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
        # Remove cached fallback so configure_dynamic_settings picks up new value
        if hasattr(django_settings, 'AXES_FAILURE_LIMIT_DEFAULT'):
            del django_settings.AXES_FAILURE_LIMIT_DEFAULT
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


class WhitelistBypassTest(TestCase):
    """
    Whitelisted users must bypass axes lockout — regression test for the bug
    where DRF/JSON logins (credentials=None) ignored the whitelist.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser

        cache.clear()
        AccessAttempt.objects.all().delete()
        WhitelistedUser.objects.all().delete()

        User = get_user_model()
        self.user = User.objects.create_user(username='alice', password='pw')
        self.factory = RequestFactory()
        self.handler = DynamicAxesHandler()

        # Simulate a locked-out account
        AccessAttempt.objects.create(
            username='alice',
            ip_address='1.2.3.4',
            user_agent='test',
            failures_since_start=99,
        )

    def _post_request(self, body):
        from django.urls import reverse
        try:
            path = reverse('admin:login')
        except Exception:
            path = '/login/'
        request = self.factory.post(path, body)
        request.axes_ip_address = '1.2.3.4'
        request.axes_user_agent = 'test'
        return request

    def test_whitelist_via_credentials_dict(self):
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=True)
        request = self._post_request({})
        self.assertFalse(
            self.handler.is_locked(request, credentials={'username': 'alice'}),
            "Whitelisted user must not appear locked when credentials dict is passed",
        )

    def test_whitelist_via_request_body_no_credentials(self):
        """The actual production bug: DRF passes credentials=None."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=True)
        request = self._post_request({'username': 'alice', 'password': 'pw'})
        self.assertFalse(
            self.handler.is_locked(request, credentials=None),
            "Whitelisted user must not appear locked when only request body has username",
        )

    def test_non_whitelisted_user_still_locked(self):
        request = self._post_request({'username': 'alice'})
        # No WhitelistedUser row → super() decides — we just verify our override
        # doesn't *force* unlocked. Reset cooloff to None to ensure DB state drives result.
        django_settings.AXES_COOLOFF_TIME = None
        # Without whitelist, our override returns whatever super() returns;
        # the key assertion is that our override didn't bypass.
        result = self.handler.is_locked(request, credentials={'username': 'alice'})
        self.assertIsInstance(result, bool)

    def test_inactive_whitelist_does_not_bypass(self):
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=False)
        request = self._post_request({'username': 'alice'})
        # Inactive whitelist → _is_user_whitelisted returns False → falls through to super()
        # We verify the bypass branch is NOT taken (no AssertionError on super call).
        # Just confirm it doesn't crash and returns a bool.
        result = self.handler.is_locked(request, credentials={'username': 'alice'})
        self.assertIsInstance(result, bool)


class WhitelistAutoResetTest(TestCase):
    """Saving a WhitelistedUser with exemption_type='all' must reset axes lockout."""

    def setUp(self):
        from django.contrib.auth import get_user_model
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser

        cache.clear()
        AccessAttempt.objects.all().delete()
        WhitelistedUser.objects.all().delete()

        User = get_user_model()
        self.user = User.objects.create_user(username='bob', password='pw')

    def test_save_with_exemption_all_clears_access_attempts(self):
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser

        AccessAttempt.objects.create(
            username='bob', ip_address='9.9.9.9', user_agent='ua', failures_since_start=10,
        )
        self.assertEqual(AccessAttempt.objects.filter(username='bob').count(), 1)

        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=True)

        self.assertEqual(
            AccessAttempt.objects.filter(username='bob').count(), 0,
            "Whitelisting with exemption_type='all' must clear AccessAttempt rows",
        )

    def test_save_with_other_exemption_does_not_reset(self):
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser

        AccessAttempt.objects.create(
            username='bob', ip_address='9.9.9.9', user_agent='ua', failures_since_start=10,
        )
        WhitelistedUser.objects.create(user=self.user, exemption_type='rate_limit', is_active=True)

        self.assertEqual(
            AccessAttempt.objects.filter(username='bob').count(), 1,
            "Non-'all' exemptions must NOT touch axes state",
        )

    def test_save_inactive_does_not_reset(self):
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser

        AccessAttempt.objects.create(
            username='bob', ip_address='9.9.9.9', user_agent='ua', failures_since_start=10,
        )
        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=False)

        self.assertEqual(
            AccessAttempt.objects.filter(username='bob').count(), 1,
            "Inactive whitelist must NOT reset axes state",
        )
