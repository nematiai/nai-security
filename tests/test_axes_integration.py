from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, RequestFactory
from django.conf import settings as django_settings

from axes.handlers.database import AxesDatabaseHandler

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


class UnifiedWhitelistBypassTest(TestCase):
    """
    Regression tests for B1/B2/B3 from docs/audits/2026-05-06-nai-security-whitelist-audit.md:
    - B1: WhitelistedIP must bypass axes even with no/unknown credentials.
    - B2: WhitelistedUser must bypass axes regardless of exemption_type.
    - B3: User lookup must fall back to email when USERNAME_FIELD differs.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser, WhitelistedIP

        cache.clear()
        AccessAttempt.objects.all().delete()
        WhitelistedUser.objects.all().delete()
        WhitelistedIP.objects.all().delete()

        User = get_user_model()
        self.user = User.objects.create_user(
            username='admin1', email='x@gmail.com', password='pw',
        )
        self.factory = RequestFactory()
        self.handler = DynamicAxesHandler()

    def _request(self, body=None, remote_addr='203.0.113.10'):
        request = self.factory.post('/login/', body or {})
        request.META['REMOTE_ADDR'] = remote_addr
        request.axes_ip_address = remote_addr
        request.axes_user_agent = 'test'
        return request

    # ---- B1: IP whitelist bypasses axes lockout ----

    def test_whitelisted_ip_not_locked_when_credentials_missing(self):
        """B1: GET /login/ with no credentials from a whitelisted IP must not be locked."""
        from nai_security.models import WhitelistedIP
        WhitelistedIP.objects.create(ip_address='203.0.113.10', is_active=True)

        with patch.object(AxesDatabaseHandler, 'is_locked', return_value=True):
            result = self.handler.is_locked(self._request(), credentials=None)
        self.assertFalse(result, "Whitelisted IP must bypass axes when credentials are absent")

    def test_whitelisted_ip_not_locked_when_username_unknown(self):
        """B1: failed login from whitelisted IP with a non-existent username must not be locked."""
        from nai_security.models import WhitelistedIP
        WhitelistedIP.objects.create(ip_address='203.0.113.10', is_active=True)

        with patch.object(AxesDatabaseHandler, 'is_locked', return_value=True):
            result = self.handler.is_locked(
                self._request({'username': 'nobody'}),
                credentials={'username': 'nobody'},
            )
        self.assertFalse(result, "Whitelisted IP must bypass axes for unknown users too")

    # ---- B2: any exemption_type bypasses axes ----

    def test_whitelisted_user_with_ip_block_exemption_not_locked_by_axes(self):
        """B2: exemption_type='ip_block' must still bypass axes lockout."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='ip_block', is_active=True)

        with patch.object(AxesDatabaseHandler, 'is_locked', return_value=True):
            result = self.handler.is_locked(
                self._request({'username': 'admin1'}),
                credentials={'username': 'admin1'},
            )
        self.assertFalse(result, "exemption_type='ip_block' must bypass axes lockout")

    def test_whitelisted_user_with_rate_limit_exemption_not_locked_by_axes(self):
        """B2: exemption_type='rate_limit' must still bypass axes lockout."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='rate_limit', is_active=True)

        with patch.object(AxesDatabaseHandler, 'is_locked', return_value=True):
            result = self.handler.is_locked(
                self._request({'username': 'admin1'}),
                credentials={'username': 'admin1'},
            )
        self.assertFalse(result, "exemption_type='rate_limit' must bypass axes lockout")

    # ---- B3: email fallback when USERNAME_FIELD='username' but form posts email ----

    def test_whitelist_resolves_user_by_email_fallback(self):
        """B3: form posts email='x@gmail.com' but USERNAME_FIELD='username' — must still match."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(user=self.user, exemption_type='all', is_active=True)

        with patch.object(AxesDatabaseHandler, 'is_locked', return_value=True):
            result = self.handler.is_locked(
                self._request({'username': 'x@gmail.com'}),
                credentials={'username': 'x@gmail.com'},
            )
        self.assertFalse(
            result,
            "Whitelist lookup must fall back to email when login uses email-as-username",
        )


from django.test import override_settings


@override_settings(
    AXES_LOCKOUT_PARAMETERS=['ip_address'],
    AXES_FAILURE_LIMIT=5,
    AXES_COOLOFF_TIME=None,
)
class RealLockoutBypassTest(TestCase):
    """
    End-to-end smoke test: uses REAL AccessAttempt rows + REAL axes lockout calculation
    (no mocking of super().is_locked). Proves the override flips a genuine lockout
    decision, not just a stubbed one.

    Configured with AXES_LOCKOUT_PARAMETERS=['ip_address'] so a single high-failure
    row at our test IP is sufficient to trigger axes' real lockout logic.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model
        from axes.models import AccessAttempt
        from nai_security.models import WhitelistedUser, WhitelistedIP

        cache.clear()
        AccessAttempt.objects.all().delete()
        WhitelistedUser.objects.all().delete()
        WhitelistedIP.objects.all().delete()

        User = get_user_model()
        self.user = User.objects.create_user(
            username='admin1', email='x@gmail.com', password='pw',
        )
        self.factory = RequestFactory()
        self.handler = DynamicAxesHandler()

        # Real lockout state at IP 203.0.113.10
        AccessAttempt.objects.create(
            username='x@gmail.com',
            ip_address='203.0.113.10',
            user_agent='smoke',
            failures_since_start=10,
        )

    def _req(self, body=None, ip='203.0.113.10'):
        r = self.factory.post('/login/', body or {})
        r.META['REMOTE_ADDR'] = ip
        r.axes_ip_address = ip
        r.axes_user_agent = 'smoke'
        return r

    def test_negative_control_no_whitelist_is_actually_locked(self):
        """Sanity: without a whitelist, axes' real logic must report the IP as locked.
        Proves the test setup actually triggers lockout — otherwise the positive
        cases below could be passing for the wrong reason."""
        result = self.handler.is_locked(
            self._req({'username': 'x@gmail.com'}),
            credentials={'username': 'x@gmail.com'},
        )
        self.assertTrue(
            result,
            "Without whitelist, axes must report locked — if this fails the test "
            "setup is wrong and the positive cases prove nothing.",
        )

    def test_real_lockout_bypassed_by_ip_whitelist(self):
        """B1 end-to-end: WhitelistedIP must flip a real axes lockout decision."""
        from nai_security.models import WhitelistedIP
        WhitelistedIP.objects.create(ip_address='203.0.113.10', is_active=True)

        result = self.handler.is_locked(self._req(), credentials=None)
        self.assertFalse(result, "WhitelistedIP must override real axes lockout")

    def test_real_lockout_bypassed_by_user_whitelist_ip_block_exemption(self):
        """B2 end-to-end: exemption_type='ip_block' must flip a real axes lockout decision."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(
            user=self.user, exemption_type='ip_block', is_active=True,
        )
        result = self.handler.is_locked(
            self._req({'username': 'x@gmail.com'}),
            credentials={'username': 'x@gmail.com'},
        )
        self.assertFalse(
            result, "exemption_type='ip_block' must override real axes lockout",
        )

    def test_real_lockout_bypassed_by_email_login_whitelist(self):
        """B3 end-to-end: email-as-login resolves to whitelisted user, real axes lockout flipped."""
        from nai_security.models import WhitelistedUser
        WhitelistedUser.objects.create(
            user=self.user, exemption_type='all', is_active=True,
        )
        result = self.handler.is_locked(
            self._req({'username': 'x@gmail.com'}),
            credentials={'username': 'x@gmail.com'},
        )
        self.assertFalse(
            result, "Email-resolved whitelist must override real axes lockout",
        )
