from unittest.mock import patch, MagicMock

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory

from nai_security.models import LoginHistory, SecurityLog, SecuritySettings

User = get_user_model()


class LoginSignalBaseTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='signaluser', password='pass')
        SecuritySettings.objects.update_or_create(
            pk=1,
            defaults={
                'login_history_enabled': True,
                'alert_on_new_country': True,
                'alert_on_new_ip': False,
                'max_countries_per_day': 3,
            }
        )

    def _make_request(self, ip='8.8.8.8', user_agent='Mozilla/5.0'):
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = ip
        request.META['HTTP_USER_AGENT'] = user_agent
        request.session = MagicMock()
        request.session.session_key = 'test-session-key'
        return request


class LoginHistoryCreationTest(LoginSignalBaseTest):

    @patch('nai_security.signals.get_country_from_ip', return_value='US')
    def test_login_creates_history_record(self, mock_geo):
        from nai_security.signals import log_successful_login

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        self.assertEqual(LoginHistory.objects.filter(user=self.user).count(), 1)
        record = LoginHistory.objects.get(user=self.user)
        self.assertEqual(record.ip_address, '8.8.8.8')
        self.assertEqual(record.country_code, 'US')
        self.assertEqual(record.session_key, 'test-session-key')

    @patch('nai_security.signals.get_country_from_ip', return_value='US')
    def test_login_disabled_does_not_create_record(self, mock_geo):
        from nai_security.signals import log_successful_login

        settings = SecuritySettings.get_settings()
        settings.login_history_enabled = False
        settings.save()

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        self.assertEqual(LoginHistory.objects.filter(user=self.user).count(), 0)


class SuspiciousLoginDetectionTest(LoginSignalBaseTest):

    @patch('nai_security.signals.get_country_from_ip', return_value='JP')
    def test_new_country_flagged_suspicious(self, mock_geo):
        from nai_security.signals import log_successful_login

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        record = LoginHistory.objects.get(user=self.user)
        self.assertTrue(record.is_suspicious)
        self.assertIn('New country', record.suspicious_reason)

    @patch('nai_security.signals.get_country_from_ip', return_value='US')
    def test_known_country_not_suspicious(self, mock_geo):
        from nai_security.signals import log_successful_login

        # First login from US — new country, suspicious
        LoginHistory.objects.create(
            user=self.user, ip_address='1.1.1.1', country_code='US'
        )

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        record = LoginHistory.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertFalse(record.is_suspicious)

    @patch('nai_security.signals.get_country_from_ip', return_value='US')
    def test_new_ip_flagged_when_enabled(self, mock_geo):
        from nai_security.signals import log_successful_login

        settings = SecuritySettings.get_settings()
        settings.alert_on_new_ip = True
        settings.alert_on_new_country = False
        settings.save()

        # Existing history from different IP
        LoginHistory.objects.create(
            user=self.user, ip_address='1.1.1.1', country_code='US'
        )

        request = self._make_request(ip='8.8.8.8')
        log_successful_login(sender=None, request=request, user=self.user)

        record = LoginHistory.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertTrue(record.is_suspicious)
        self.assertIn('New IP', record.suspicious_reason)

    @patch('nai_security.signals.get_country_from_ip', return_value='JP')
    def test_suspicious_login_creates_security_log(self, mock_geo):
        from nai_security.signals import log_successful_login

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        self.assertTrue(
            SecurityLog.objects.filter(action='SUSPICIOUS_LOGIN').exists()
        )

    @patch('nai_security.signals.get_country_from_ip', return_value='US')
    def test_multi_country_flagged(self, mock_geo):
        from nai_security.signals import log_successful_login
        from django.utils import timezone

        settings = SecuritySettings.get_settings()
        settings.alert_on_new_country = False
        settings.max_countries_per_day = 3
        settings.save()

        # Create logins from 3 different countries today
        now = timezone.now()
        for code in ['GB', 'DE', 'FR']:
            LoginHistory.objects.create(
                user=self.user,
                ip_address='1.1.1.1',
                country_code=code,
            )

        request = self._make_request()
        log_successful_login(sender=None, request=request, user=self.user)

        record = LoginHistory.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertTrue(record.is_suspicious)
        self.assertIn('Multiple countries', record.suspicious_reason)


class LoginSignalErrorHandlingTest(LoginSignalBaseTest):

    @patch('nai_security.signals.get_country_from_ip', side_effect=Exception('boom'))
    def test_exception_does_not_propagate(self, mock_geo):
        from nai_security.signals import log_successful_login

        request = self._make_request()
        # Should not raise
        log_successful_login(sender=None, request=request, user=self.user)
