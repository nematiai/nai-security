from unittest.mock import patch, MagicMock

from django.core.cache import cache
from django.test import TestCase, RequestFactory

from nai_security.utils import get_client_ip, get_country_from_ip, parse_user_agent


# ------------------------------------------------------------------
# get_client_ip
# ------------------------------------------------------------------

class GetClientIPTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _make_request(self, **meta):
        request = self.factory.get('/')
        request.META.update(meta)
        return request

    def test_remote_addr(self):
        request = self._make_request(REMOTE_ADDR='1.2.3.4')
        self.assertEqual(get_client_ip(request), '1.2.3.4')

    def test_x_forwarded_for_single(self):
        request = self._make_request(
            HTTP_X_FORWARDED_FOR='5.6.7.8',
            REMOTE_ADDR='127.0.0.1',
        )
        self.assertEqual(get_client_ip(request), '5.6.7.8')

    def test_x_forwarded_for_chain(self):
        request = self._make_request(
            HTTP_X_FORWARDED_FOR='5.6.7.8, 10.0.0.1, 10.0.0.2',
            REMOTE_ADDR='127.0.0.1',
        )
        self.assertEqual(get_client_ip(request), '5.6.7.8')

    def test_x_forwarded_for_with_spaces(self):
        request = self._make_request(
            HTTP_X_FORWARDED_FOR='  9.9.9.9 , 10.0.0.1',
        )
        self.assertEqual(get_client_ip(request), '9.9.9.9')

    def test_x_real_ip(self):
        request = self._make_request(
            HTTP_X_REAL_IP='3.3.3.3',
            REMOTE_ADDR='127.0.0.1',
        )
        self.assertEqual(get_client_ip(request), '3.3.3.3')

    def test_x_forwarded_for_takes_priority_over_x_real_ip(self):
        request = self._make_request(
            HTTP_X_FORWARDED_FOR='1.1.1.1',
            HTTP_X_REAL_IP='2.2.2.2',
            REMOTE_ADDR='127.0.0.1',
        )
        self.assertEqual(get_client_ip(request), '1.1.1.1')

    def test_fallback_to_default(self):
        request = self._make_request()
        # RequestFactory sets REMOTE_ADDR to 127.0.0.1 by default
        self.assertEqual(get_client_ip(request), '127.0.0.1')


# ------------------------------------------------------------------
# get_country_from_ip
# ------------------------------------------------------------------

class GetCountryFromIPTest(TestCase):

    def setUp(self):
        cache.clear()

    def test_localhost_returns_none(self):
        self.assertIsNone(get_country_from_ip('127.0.0.1'))
        self.assertIsNone(get_country_from_ip('::1'))
        self.assertIsNone(get_country_from_ip('localhost'))

    def test_empty_ip_returns_none(self):
        self.assertIsNone(get_country_from_ip(''))
        self.assertIsNone(get_country_from_ip(None))

    def test_cache_hit(self):
        cache.set('geoip_country:8.8.8.8', 'US', 3600)
        self.assertEqual(get_country_from_ip('8.8.8.8'), 'US')

    def test_cache_hit_none_sentinel(self):
        cache.set('geoip_country:8.8.8.8', '__NONE__', 3600)
        self.assertIsNone(get_country_from_ip('8.8.8.8'))

    @patch('nai_security.utils.get_geoip_reader', return_value=None)
    def test_no_reader_returns_none(self, mock_reader):
        self.assertIsNone(get_country_from_ip('8.8.8.8'))

    @patch('nai_security.utils.get_geoip_reader')
    def test_successful_lookup(self, mock_get_reader):
        mock_reader = MagicMock()
        mock_response = MagicMock()
        mock_response.country.iso_code = 'DE'
        mock_reader.country.return_value = mock_response
        mock_get_reader.return_value = mock_reader

        result = get_country_from_ip('8.8.4.4')
        self.assertEqual(result, 'DE')
        # Should be cached
        self.assertEqual(cache.get('geoip_country:8.8.4.4'), 'DE')

    @patch('nai_security.utils.get_geoip_reader')
    def test_lookup_exception_returns_none_and_caches(self, mock_get_reader):
        mock_reader = MagicMock()
        mock_reader.country.side_effect = Exception('GeoIP error')
        mock_get_reader.return_value = mock_reader

        result = get_country_from_ip('8.8.4.4')
        self.assertIsNone(result)
        self.assertEqual(cache.get('geoip_country:8.8.4.4'), '__NONE__')


# ------------------------------------------------------------------
# parse_user_agent
# ------------------------------------------------------------------

class ParseUserAgentTest(TestCase):

    def test_empty_string(self):
        result = parse_user_agent('')
        self.assertEqual(result['device_type'], 'unknown')
        self.assertEqual(result['browser'], '')
        self.assertEqual(result['os'], '')

    # Device type
    def test_desktop(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0'
        self.assertEqual(parse_user_agent(ua)['device_type'], 'desktop')

    def test_mobile_android(self):
        ua = 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Mobile Chrome/120.0'
        self.assertEqual(parse_user_agent(ua)['device_type'], 'mobile')

    def test_mobile_iphone(self):
        ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15'
        self.assertEqual(parse_user_agent(ua)['device_type'], 'mobile')

    def test_tablet_ipad(self):
        ua = 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
        self.assertEqual(parse_user_agent(ua)['device_type'], 'tablet')

    # Browser
    def test_chrome(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'
        self.assertEqual(parse_user_agent(ua)['browser'], 'Chrome')

    def test_firefox(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0'
        self.assertEqual(parse_user_agent(ua)['browser'], 'Firefox')

    def test_safari(self):
        ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15'
        self.assertEqual(parse_user_agent(ua)['browser'], 'Safari')

    def test_edge(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Edg/120.0'
        self.assertEqual(parse_user_agent(ua)['browser'], 'Edge')

    def test_opera(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 OPR/106.0'
        self.assertEqual(parse_user_agent(ua)['browser'], 'Opera')

    # OS
    def test_windows(self):
        ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.assertEqual(parse_user_agent(ua)['os'], 'Windows')

    def test_macos(self):
        ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15'
        self.assertEqual(parse_user_agent(ua)['os'], 'macOS')

    def test_linux(self):
        ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        self.assertEqual(parse_user_agent(ua)['os'], 'Linux')

    def test_android_os(self):
        ua = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile'
        self.assertEqual(parse_user_agent(ua)['os'], 'Android')

    def test_ios(self):
        ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
        self.assertEqual(parse_user_agent(ua)['os'], 'iOS')
