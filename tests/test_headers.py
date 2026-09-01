from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from nai_security.middleware import ResponseHeaderMiddleware
from nai_security.middleware.headers import DEFAULT_FINGERPRINT_HEADERS


def leaky_view(request):
    response = HttpResponse('ok')
    response['Server'] = 'gunicorn/23.0.0'
    response['X-Powered-By'] = 'Django/5.2'
    response['X-Runtime'] = '0.031'
    response['X-Frame-Options'] = 'DENY'
    return response


class ResponseHeaderMiddlewareTest(TestCase):

    def setUp(self):
        self.request = RequestFactory().get('/')

    def _response(self, view=leaky_view):
        return ResponseHeaderMiddleware(view)(self.request)

    def test_strips_every_default_header(self):
        response = self._response()
        for header in ('Server', 'X-Powered-By', 'X-Runtime'):
            self.assertNotIn(header, response, header)

    def test_keeps_security_headers(self):
        self.assertEqual(self._response()['X-Frame-Options'], 'DENY')

    def test_body_and_status_untouched(self):
        response = self._response()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'ok')

    def test_absent_headers_are_not_an_error(self):
        response = ResponseHeaderMiddleware(lambda r: HttpResponse('bare'))(self.request)
        self.assertEqual(response.content, b'bare')

    def test_case_insensitive(self):
        def view(request):
            response = HttpResponse('ok')
            response['server'] = 'nginx'
            return response
        self.assertNotIn('Server', ResponseHeaderMiddleware(view)(self.request))

    @override_settings(NAI_SECURITY_STRIP_HEADERS=['X-Runtime'])
    def test_custom_list_replaces_the_default(self):
        response = self._response()
        self.assertNotIn('X-Runtime', response)
        self.assertEqual(response['Server'], 'gunicorn/23.0.0')

    @override_settings(NAI_SECURITY_STRIP_HEADERS=[])
    def test_empty_list_strips_nothing(self):
        self.assertEqual(self._response()['Server'], 'gunicorn/23.0.0')

    def test_default_list_covers_the_common_fingerprints(self):
        self.assertIn('Server', DEFAULT_FINGERPRINT_HEADERS)
        self.assertIn('X-Powered-By', DEFAULT_FINGERPRINT_HEADERS)
