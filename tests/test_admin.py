from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from nai_security.models import SecuritySettings

User = get_user_model()


class AdminAccessTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser('admin', 'admin@test.com', 'password')
        self.client.force_login(self.admin)

    def test_all_models_registered(self):
        from django.contrib.admin.sites import site
        registered = [m.__name__ for m in site._registry.keys()]
        expected = [
            'BlockedCountry', 'BlockedIP', 'BlockedEmail', 'BlockedDomain',
            'BlockedUserAgent', 'WhitelistedIP', 'WhitelistedUser',
            'AllowedCountry', 'RateLimitRule', 'LoginHistory',
            'SecurityLog', 'SecuritySettings',
        ]
        for model_name in expected:
            self.assertIn(model_name, registered, f'{model_name} not registered in admin')

    def test_security_settings_changelist(self):
        SecuritySettings.get_settings()
        response = self.client.get('/admin/nai_security/securitysettings/')
        self.assertEqual(response.status_code, 200)

    def test_blocked_ip_changelist(self):
        response = self.client.get('/admin/nai_security/blockedip/')
        self.assertEqual(response.status_code, 200)

    def test_security_log_readonly(self):
        response = self.client.get('/admin/nai_security/securitylog/add/')
        self.assertEqual(response.status_code, 403)

    def test_login_history_readonly(self):
        response = self.client.get('/admin/nai_security/loginhistory/add/')
        self.assertEqual(response.status_code, 403)
