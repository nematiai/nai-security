from django.test import TestCase
from django.contrib.auth import get_user_model
from nai_security.models import (
    BlockedIP, BlockedCountry, BlockedEmail, BlockedDomain,
    BlockedUserAgent, WhitelistedIP, WhitelistedUser,
    AllowedCountry, SecuritySettings, SecurityLog,
    LoginHistory, RateLimitRule,
)

User = get_user_model()


class BlockedIPTest(TestCase):
    def test_create_and_expire(self):
        from django.utils import timezone
        from datetime import timedelta

        ip = BlockedIP.objects.create(ip_address='1.2.3.4', reason='test')
        self.assertTrue(ip.is_active)
        self.assertFalse(ip.is_expired())

        ip.expires_at = timezone.now() - timedelta(hours=1)
        ip.save()
        self.assertTrue(ip.is_expired())

    def test_str(self):
        ip = BlockedIP.objects.create(ip_address='5.6.7.8', is_auto_blocked=True)
        self.assertIn('AUTO', str(ip))


class BlockedEmailTest(TestCase):
    def test_is_blocked(self):
        BlockedEmail.objects.create(email='bad@test.com')
        self.assertTrue(BlockedEmail.is_email_blocked('bad@test.com'))
        self.assertTrue(BlockedEmail.is_email_blocked('BAD@TEST.COM'))
        self.assertFalse(BlockedEmail.is_email_blocked('good@test.com'))

    def test_normalizes_to_lowercase(self):
        e = BlockedEmail.objects.create(email='UPPER@TEST.COM')
        e.refresh_from_db()
        self.assertEqual(e.email, 'upper@test.com')


class BlockedDomainTest(TestCase):
    def test_is_domain_blocked(self):
        BlockedDomain.objects.create(domain='tempmail.com')
        self.assertTrue(BlockedDomain.is_domain_blocked('user@tempmail.com'))
        self.assertFalse(BlockedDomain.is_domain_blocked('user@gmail.com'))

    def test_normalizes_domain(self):
        d = BlockedDomain.objects.create(domain='  TEMPMAIL.COM  ')
        d.refresh_from_db()
        self.assertEqual(d.domain, 'tempmail.com')


class BlockedUserAgentTest(TestCase):
    def test_contains_match(self):
        BlockedUserAgent.objects.create(pattern='AhrefsBot', block_type='contains')
        blocked, pattern = BlockedUserAgent.is_user_agent_blocked('Mozilla/5.0 AhrefsBot/7.0')
        self.assertTrue(blocked)
        self.assertIsNotNone(pattern)

    def test_exact_match(self):
        BlockedUserAgent.objects.create(pattern='badbot', block_type='exact')
        blocked, _ = BlockedUserAgent.is_user_agent_blocked('badbot')
        self.assertTrue(blocked)
        blocked, _ = BlockedUserAgent.is_user_agent_blocked('badbot/1.0')
        self.assertFalse(blocked)

    def test_regex_match(self):
        BlockedUserAgent.objects.create(pattern=r'zgrab/\d+', block_type='regex')
        blocked, _ = BlockedUserAgent.is_user_agent_blocked('zgrab/2')
        self.assertTrue(blocked)

    def test_empty_ua(self):
        blocked, _ = BlockedUserAgent.is_user_agent_blocked('')
        self.assertFalse(blocked)


class BlockedCountryTest(TestCase):
    def test_auto_name(self):
        c = BlockedCountry.objects.create(code='US')
        self.assertEqual(c.name, 'United States')


class AllowedCountryTest(TestCase):
    def test_whitelist_mode(self):
        self.assertFalse(AllowedCountry.is_whitelist_mode())
        self.assertTrue(AllowedCountry.is_country_allowed('US'))

        AllowedCountry.objects.create(code='US', name='United States')
        self.assertTrue(AllowedCountry.is_whitelist_mode())
        self.assertTrue(AllowedCountry.is_country_allowed('US'))
        self.assertFalse(AllowedCountry.is_country_allowed('CN'))


class WhitelistedIPTest(TestCase):
    def test_is_whitelisted(self):
        WhitelistedIP.objects.create(ip_address='10.0.0.1')
        self.assertTrue(WhitelistedIP.is_whitelisted('10.0.0.1'))
        self.assertFalse(WhitelistedIP.is_whitelisted('10.0.0.2'))


class WhitelistedUserTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='pass')

    def test_is_whitelisted(self):
        WhitelistedUser.objects.create(user=self.user, exemption_type='all')
        self.assertTrue(WhitelistedUser.is_whitelisted(self.user))
        self.assertTrue(WhitelistedUser.is_whitelisted(self.user, 'rate_limit'))

    def test_expired(self):
        from django.utils import timezone
        from datetime import timedelta
        WhitelistedUser.objects.create(
            user=self.user,
            exemption_type='all',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertFalse(WhitelistedUser.is_whitelisted(self.user))

    def test_anonymous_user(self):
        from django.contrib.auth.models import AnonymousUser
        self.assertFalse(WhitelistedUser.is_whitelisted(AnonymousUser()))


class SecuritySettingsTest(TestCase):
    def test_singleton(self):
        s1 = SecuritySettings.get_settings()
        s2 = SecuritySettings.get_settings()
        self.assertEqual(s1.pk, s2.pk)
        self.assertEqual(s1.pk, 1)

    def test_defaults(self):
        s = SecuritySettings.get_settings()
        self.assertEqual(s.max_login_attempts, 5)
        self.assertTrue(s.ip_blocking_enabled)

    def test_axes_defaults(self):
        s = SecuritySettings.get_settings()
        self.assertEqual(s.axes_cooloff_minutes, 0)
        self.assertFalse(s.axes_attempt_expiry_enabled)

    def test_clean_attempt_expiry_requires_cooloff(self):
        from django.core.exceptions import ValidationError
        s = SecuritySettings.get_settings()
        s.axes_attempt_expiry_enabled = True
        s.axes_cooloff_minutes = 0
        with self.assertRaises(ValidationError) as ctx:
            s.full_clean()
        self.assertIn('axes_attempt_expiry_enabled', ctx.exception.message_dict)

    def test_clean_attempt_expiry_with_cooloff_passes(self):
        s = SecuritySettings.get_settings()
        s.axes_attempt_expiry_enabled = True
        s.axes_cooloff_minutes = 30
        s.full_clean()  # Should not raise


class SecurityLogTest(TestCase):
    def test_log_event(self):
        log = SecurityLog.log_event(
            ip_address='1.2.3.4',
            action='IP_BLOCK',
            path='/test/',
            country_code='US',
        )
        self.assertEqual(log.severity, 'high')
        self.assertEqual(log.action, 'IP_BLOCK')


class LoginHistoryTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='pass')

    def test_new_country(self):
        self.assertTrue(LoginHistory.is_new_country(self.user, 'US'))
        LoginHistory.objects.create(user=self.user, ip_address='1.1.1.1', country_code='US')
        self.assertFalse(LoginHistory.is_new_country(self.user, 'US'))
        self.assertTrue(LoginHistory.is_new_country(self.user, 'GB'))

    def test_new_ip(self):
        self.assertTrue(LoginHistory.is_new_ip(self.user, '1.1.1.1'))
        LoginHistory.objects.create(user=self.user, ip_address='1.1.1.1', country_code='US')
        self.assertFalse(LoginHistory.is_new_ip(self.user, '1.1.1.1'))
