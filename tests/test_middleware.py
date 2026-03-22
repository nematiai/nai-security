from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import TestCase, RequestFactory, override_settings
from django.utils import timezone

from nai_security.middleware import SecurityMiddleware, RateLimitLoggingMiddleware
from nai_security.models import (
    BlockedIP, BlockedCountry, BlockedUserAgent, AllowedCountry,
    WhitelistedIP, WhitelistedUser, SecuritySettings, SecurityLog,
)

User = get_user_model()


class SecurityMiddlewareBaseTest(TestCase):
    """Base test class with shared setup for SecurityMiddleware tests."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SecurityMiddleware(lambda req: HttpResponse('OK'))
        SecuritySettings.get_settings()
        cache.clear()

    def _make_request(self, path='/', ip='8.8.8.8', user_agent='Mozilla/5.0', user=None):
        request = self.factory.get(path)
        request.META['REMOTE_ADDR'] = ip
        request.META['HTTP_USER_AGENT'] = user_agent
        request.user = user or AnonymousUser()
        return request


# ------------------------------------------------------------------
# Middleware ordering validation
# ------------------------------------------------------------------

class MiddlewareOrderValidationTest(TestCase):

    @override_settings(MIDDLEWARE=[
        'nai_security.middleware.SecurityMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    ])
    def test_raises_when_before_auth_middleware(self):
        with self.assertRaises(ImproperlyConfigured):
            SecurityMiddleware(lambda req: HttpResponse('OK'))

    @override_settings(MIDDLEWARE=[
        'nai_security.middleware.SecurityMiddleware',
    ])
    def test_raises_when_auth_middleware_missing(self):
        with self.assertRaises(ImproperlyConfigured):
            SecurityMiddleware(lambda req: HttpResponse('OK'))

    @override_settings(MIDDLEWARE=[
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'nai_security.middleware.SecurityMiddleware',
    ])
    def test_passes_when_after_auth_middleware(self):
        SecurityMiddleware(lambda req: HttpResponse('OK'))

    @override_settings(MIDDLEWARE=[
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'nai_security.middleware.security.SecurityMiddleware',
    ])
    def test_passes_with_full_module_path(self):
        SecurityMiddleware(lambda req: HttpResponse('OK'))


# ------------------------------------------------------------------
# Exempt paths
# ------------------------------------------------------------------

class ExemptPathTest(SecurityMiddlewareBaseTest):

    def test_default_exempt_paths(self):
        for path in ['/health/', '/health', '/ready/', '/ready', '/favicon.ico']:
            request = self._make_request(path=path)
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200, f"Path {path} should be exempt")

    @override_settings(NAI_SECURITY_EXEMPT_PATHS=['/custom/', '/api/status/'])
    def test_custom_exempt_paths(self):
        mw = SecurityMiddleware(lambda req: HttpResponse('OK'))
        request = self._make_request(path='/custom/')
        self.assertEqual(mw(request).status_code, 200)

    @override_settings(NAI_SECURITY_EXEMPT_PATHS=['/custom/'])
    def test_default_paths_not_exempt_when_overridden(self):
        mw = SecurityMiddleware(lambda req: HttpResponse('OK'))
        # /health/ is no longer exempt, but passes because no blocks apply
        request = self._make_request(path='/health/')
        self.assertEqual(mw(request).status_code, 200)


# ------------------------------------------------------------------
# Localhost bypass
# ------------------------------------------------------------------

class LocalhostBypassTest(SecurityMiddlewareBaseTest):

    def test_localhost_ipv4(self):
        request = self._make_request(ip='127.0.0.1')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_localhost_ipv6(self):
        request = self._make_request(ip='::1')
        self.assertEqual(self.middleware(request).status_code, 200)


# ------------------------------------------------------------------
# IP whitelist
# ------------------------------------------------------------------

class IPWhitelistTest(SecurityMiddlewareBaseTest):

    def test_whitelisted_ip_bypass(self):
        WhitelistedIP.objects.create(ip_address='10.0.0.1')
        request = self._make_request(ip='10.0.0.1')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_inactive_whitelist_does_not_bypass(self):
        WhitelistedIP.objects.create(ip_address='10.0.0.2', is_active=False)
        BlockedIP.objects.create(ip_address='10.0.0.2')
        request = self._make_request(ip='10.0.0.2')
        self.assertEqual(self.middleware(request).status_code, 403)


# ------------------------------------------------------------------
# IP blocking
# ------------------------------------------------------------------

class IPBlockTest(SecurityMiddlewareBaseTest):

    def test_blocked_ip(self):
        BlockedIP.objects.create(ip_address='6.6.6.6')
        request = self._make_request(ip='6.6.6.6')
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_expired_block_passes(self):
        BlockedIP.objects.create(
            ip_address='7.7.7.7',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        request = self._make_request(ip='7.7.7.7')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_ip_blocking_disabled(self):
        settings = SecuritySettings.get_settings()
        settings.ip_blocking_enabled = False
        settings.save()
        cache.clear()
        BlockedIP.objects.create(ip_address='6.6.6.6')
        request = self._make_request(ip='6.6.6.6')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_blocked_ip_logs_event(self):
        BlockedIP.objects.create(ip_address='6.6.6.6')
        request = self._make_request(ip='6.6.6.6')
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='IP_BLOCK').exists())


# ------------------------------------------------------------------
# User whitelist exemptions (core bug fix)
# ------------------------------------------------------------------

class UserWhitelistTest(SecurityMiddlewareBaseTest):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_all_exemption_bypasses_ip_block(self):
        WhitelistedUser.objects.create(user=self.user, exemption_type='all')
        BlockedIP.objects.create(ip_address='8.8.8.8')
        request = self._make_request(ip='8.8.8.8', user=self.user)
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_ip_block_exemption_bypasses_ip_block(self):
        WhitelistedUser.objects.create(user=self.user, exemption_type='ip_block')
        BlockedIP.objects.create(ip_address='8.8.8.8')
        request = self._make_request(ip='8.8.8.8', user=self.user)
        self.assertEqual(self.middleware(request).status_code, 200)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='RU')
    def test_geo_block_exemption_bypasses_country_block(self, mock_geo):
        WhitelistedUser.objects.create(user=self.user, exemption_type='geo_block')
        BlockedCountry.objects.create(code='RU', name='Russia')
        request = self._make_request(user=self.user)
        self.assertEqual(self.middleware(request).status_code, 200)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='RU')
    def test_ip_block_exemption_does_not_bypass_country_block(self, mock_geo):
        WhitelistedUser.objects.create(user=self.user, exemption_type='ip_block')
        BlockedCountry.objects.create(code='RU', name='Russia')
        request = self._make_request(user=self.user)
        self.assertEqual(self.middleware(request).status_code, 403)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='RU')
    def test_all_exemption_bypasses_country_block(self, mock_geo):
        WhitelistedUser.objects.create(user=self.user, exemption_type='all')
        BlockedCountry.objects.create(code='RU', name='Russia')
        request = self._make_request(user=self.user)
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_all_exemption_bypasses_user_agent_block(self):
        WhitelistedUser.objects.create(user=self.user, exemption_type='all')
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='BadBot/1.0', user=self.user)
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_expired_whitelist_does_not_bypass(self):
        WhitelistedUser.objects.create(
            user=self.user,
            exemption_type='all',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        BlockedIP.objects.create(ip_address='8.8.8.8')
        request = self._make_request(ip='8.8.8.8', user=self.user)
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_inactive_whitelist_does_not_bypass(self):
        WhitelistedUser.objects.create(
            user=self.user,
            exemption_type='all',
            is_active=False,
        )
        BlockedIP.objects.create(ip_address='8.8.8.8')
        request = self._make_request(ip='8.8.8.8', user=self.user)
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_anonymous_user_gets_no_exemption(self):
        BlockedIP.objects.create(ip_address='8.8.8.8')
        request = self._make_request(ip='8.8.8.8')
        self.assertEqual(self.middleware(request).status_code, 403)


# ------------------------------------------------------------------
# Country blocking
# ------------------------------------------------------------------

class CountryBlockTest(SecurityMiddlewareBaseTest):

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='CN')
    def test_blocked_country(self, mock_geo):
        BlockedCountry.objects.create(code='CN', name='China')
        request = self._make_request()
        self.assertEqual(self.middleware(request).status_code, 403)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='US')
    def test_non_blocked_country_passes(self, mock_geo):
        BlockedCountry.objects.create(code='CN', name='China')
        request = self._make_request()
        self.assertEqual(self.middleware(request).status_code, 200)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='US')
    def test_whitelist_mode_allowed_country(self, mock_geo):
        settings = SecuritySettings.get_settings()
        settings.country_whitelist_mode = True
        settings.save()
        cache.clear()
        AllowedCountry.objects.create(code='US', name='United States')
        request = self._make_request()
        self.assertEqual(self.middleware(request).status_code, 200)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='RU')
    def test_whitelist_mode_disallowed_country(self, mock_geo):
        settings = SecuritySettings.get_settings()
        settings.country_whitelist_mode = True
        settings.save()
        cache.clear()
        AllowedCountry.objects.create(code='US', name='United States')
        request = self._make_request()
        self.assertEqual(self.middleware(request).status_code, 403)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='CN')
    def test_country_blocking_disabled(self, mock_geo):
        settings = SecuritySettings.get_settings()
        settings.country_blocking_enabled = False
        settings.save()
        cache.clear()
        BlockedCountry.objects.create(code='CN', name='China')
        request = self._make_request()
        self.assertEqual(self.middleware(request).status_code, 200)

    @patch('nai_security.middleware.security.get_country_from_ip', return_value='CN')
    def test_country_block_logs_event(self, mock_geo):
        BlockedCountry.objects.create(code='CN', name='China')
        request = self._make_request()
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='COUNTRY_BLOCK').exists())


# ------------------------------------------------------------------
# User-agent blocking
# ------------------------------------------------------------------

class UserAgentBlockTest(SecurityMiddlewareBaseTest):

    def test_blocked_user_agent_contains(self):
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='BadBot/1.0')
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_blocked_user_agent_exact(self):
        BlockedUserAgent.objects.create(pattern='evilbot/2.0', block_type='exact')
        request = self._make_request(user_agent='EvilBot/2.0')
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_blocked_user_agent_regex(self):
        BlockedUserAgent.objects.create(pattern=r'curl/\d+', block_type='regex')
        request = self._make_request(user_agent='curl/7.68')
        self.assertEqual(self.middleware(request).status_code, 403)

    def test_normal_user_agent_passes(self):
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='Mozilla/5.0')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_empty_user_agent_passes(self):
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_user_agent_blocking_disabled(self):
        settings = SecuritySettings.get_settings()
        settings.user_agent_blocking_enabled = False
        settings.save()
        cache.clear()
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='BadBot/1.0')
        self.assertEqual(self.middleware(request).status_code, 200)

    def test_user_agent_block_logs_event(self):
        BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        request = self._make_request(user_agent='BadBot/1.0')
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='USER_AGENT_BLOCK').exists())


# ------------------------------------------------------------------
# UA block count batching
# ------------------------------------------------------------------

class UABlockCountBatchingTest(SecurityMiddlewareBaseTest):

    def test_count_accumulates_in_cache(self):
        pattern = BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        for _ in range(5):
            request = self._make_request(user_agent='BadBot/1.0')
            self.middleware(request)
        pattern.refresh_from_db()
        self.assertEqual(pattern.block_count, 0)
        self.assertEqual(cache.get(f"sec_ua_count:{pattern.pk}"), 5)

    def test_count_flushes_at_threshold(self):
        pattern = BlockedUserAgent.objects.create(pattern='BadBot', block_type='contains')
        cache.set(f"sec_ua_count:{pattern.pk}", 99, 3600)
        request = self._make_request(user_agent='BadBot/1.0')
        self.middleware(request)
        pattern.refresh_from_db()
        self.assertEqual(pattern.block_count, 100)
        self.assertIsNone(cache.get(f"sec_ua_count:{pattern.pk}"))


# ------------------------------------------------------------------
# Cache invalidation on model save/delete
# ------------------------------------------------------------------

class CacheInvalidationTest(TestCase):

    def setUp(self):
        cache.clear()

    def test_whitelisted_ip_save_clears_cache(self):
        cache.set('sec_whitelist:10.0.0.1', False, 300)
        WhitelistedIP.objects.create(ip_address='10.0.0.1')
        self.assertIsNone(cache.get('sec_whitelist:10.0.0.1'))

    def test_whitelisted_ip_delete_clears_cache(self):
        obj = WhitelistedIP.objects.create(ip_address='10.0.0.1')
        cache.set('sec_whitelist:10.0.0.1', True, 300)
        obj.delete()
        self.assertIsNone(cache.get('sec_whitelist:10.0.0.1'))

    def test_blocked_ip_save_clears_cache(self):
        cache.set('sec_blocked_ip:6.6.6.6', False, 300)
        BlockedIP.objects.create(ip_address='6.6.6.6')
        self.assertIsNone(cache.get('sec_blocked_ip:6.6.6.6'))

    def test_blocked_ip_delete_clears_cache(self):
        obj = BlockedIP.objects.create(ip_address='6.6.6.6')
        cache.set('sec_blocked_ip:6.6.6.6', True, 300)
        obj.delete()
        self.assertIsNone(cache.get('sec_blocked_ip:6.6.6.6'))

    def test_whitelisted_user_save_clears_cache(self):
        user = User.objects.create_user(username='cacheuser', password='pass')
        cache.set(f'sec_user_exempt:{user.pk}', '_none_', 300)
        WhitelistedUser.objects.create(user=user, exemption_type='all')
        self.assertIsNone(cache.get(f'sec_user_exempt:{user.pk}'))

    def test_whitelisted_user_delete_clears_cache(self):
        user = User.objects.create_user(username='cacheuser2', password='pass')
        obj = WhitelistedUser.objects.create(user=user, exemption_type='all')
        cache.set(f'sec_user_exempt:{user.pk}', 'all', 300)
        obj.delete()
        self.assertIsNone(cache.get(f'sec_user_exempt:{user.pk}'))

    def test_blocked_country_save_clears_cache(self):
        cache.set('sec_blocked_country:CN', False, 300)
        BlockedCountry.objects.create(code='CN')
        self.assertIsNone(cache.get('sec_blocked_country:CN'))

    def test_blocked_country_delete_clears_cache(self):
        obj = BlockedCountry.objects.create(code='CN')
        cache.set('sec_blocked_country:CN', True, 300)
        obj.delete()
        self.assertIsNone(cache.get('sec_blocked_country:CN'))

    def test_allowed_country_save_clears_cache(self):
        cache.set('sec_allowed_country:US', False, 300)
        AllowedCountry.objects.create(code='US')
        self.assertIsNone(cache.get('sec_allowed_country:US'))

    def test_allowed_country_delete_clears_cache(self):
        obj = AllowedCountry.objects.create(code='US')
        cache.set('sec_allowed_country:US', True, 300)
        obj.delete()
        self.assertIsNone(cache.get('sec_allowed_country:US'))


# ------------------------------------------------------------------
# RateLimitLoggingMiddleware
# ------------------------------------------------------------------

class RateLimitLoggingMiddlewareTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RateLimitLoggingMiddleware(lambda req: HttpResponse('OK'))
        SecuritySettings.get_settings()
        cache.clear()

    def _make_request(self, limited=False, user=None):
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '8.8.8.8'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0'
        request.limited = limited
        request.country_code = ''
        request.user = user or AnonymousUser()
        return request

    def test_not_limited_passes_through(self):
        request = self._make_request(limited=False)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(SecurityLog.objects.filter(action='RATE_LIMIT').exists())

    def test_limited_request_logs_event(self):
        request = self._make_request(limited=True)
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='RATE_LIMIT').exists())

    def test_rate_limit_exemption_bypasses_logging(self):
        user = User.objects.create_user(username='ratelimituser', password='pass')
        WhitelistedUser.objects.create(user=user, exemption_type='rate_limit')
        request = self._make_request(limited=True, user=user)
        self.middleware(request)
        self.assertFalse(SecurityLog.objects.filter(action='RATE_LIMIT').exists())

    def test_all_exemption_bypasses_rate_limit_logging(self):
        user = User.objects.create_user(username='allexemptrl', password='pass')
        WhitelistedUser.objects.create(user=user, exemption_type='all')
        request = self._make_request(limited=True, user=user)
        self.middleware(request)
        self.assertFalse(SecurityLog.objects.filter(action='RATE_LIMIT').exists())

    def test_ip_block_exemption_does_not_bypass_rate_limit(self):
        user = User.objects.create_user(username='ipblockrl', password='pass')
        WhitelistedUser.objects.create(user=user, exemption_type='ip_block')
        request = self._make_request(limited=True, user=user)
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='RATE_LIMIT').exists())

    def test_anonymous_limited_request_logs(self):
        request = self._make_request(limited=True)
        self.middleware(request)
        self.assertTrue(SecurityLog.objects.filter(action='RATE_LIMIT').exists())
