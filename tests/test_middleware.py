from django.test import TestCase, RequestFactory, override_settings
from nai_security.middleware import SecurityMiddleware
from nai_security.models import BlockedIP, WhitelistedIP, SecuritySettings


class SecurityMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SecurityMiddleware(lambda req: self._dummy_response())
        SecuritySettings.get_settings()

    def _dummy_response(self):
        from django.http import HttpResponse
        return HttpResponse('OK')

    def _make_request(self, path='/', ip='8.8.8.8', user_agent='Mozilla/5.0'):
        request = self.factory.get(path)
        request.META['REMOTE_ADDR'] = ip
        request.META['HTTP_USER_AGENT'] = user_agent
        return request

    def test_exempt_path(self):
        request = self._make_request(path='/health/')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_localhost_bypass(self):
        request = self._make_request(ip='127.0.0.1')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_whitelisted_ip_bypass(self):
        WhitelistedIP.objects.create(ip_address='10.0.0.1')
        request = self._make_request(ip='10.0.0.1')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_blocked_ip(self):
        BlockedIP.objects.create(ip_address='6.6.6.6')
        request = self._make_request(ip='6.6.6.6')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_expired_block_passes(self):
        from django.utils import timezone
        from datetime import timedelta
        BlockedIP.objects.create(
            ip_address='7.7.7.7',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        request = self._make_request(ip='7.7.7.7')
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
