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

    def test_axes_access_log_models_remain_registered(self):
        from django.contrib.admin.sites import site
        from axes.models import AccessAttempt, AccessLog, AccessFailureLog
        registered = set(site._registry.keys())
        self.assertIn(AccessAttempt, registered)
        self.assertIn(AccessLog, registered)
        self.assertIn(AccessFailureLog, registered)


class BadgeRenderingTest(TestCase):
    """Django rejects format_html() called with a lone literal and no args.

    Every badge below used to raise TypeError, which surfaced as a 500 on the
    changelist rather than as an import error, so nothing caught it until a
    page was actually opened.
    """

    def test_every_badge_helper_renders(self):
        from django.contrib import admin as dj_admin

        for model, model_admin in dj_admin.site._registry.items():
            if model._meta.app_label != 'nai_security':
                continue
            for name in getattr(model_admin, 'list_display', ()):
                # '__str__' is a legal list_display entry and resolves to the
                # ModelAdmin's own dunder, not to a badge helper.
                if name.startswith('_'):
                    continue
                attr = getattr(model_admin, name, None)
                if not callable(attr):
                    continue
                try:
                    attr(model())
                except (TypeError, ValueError) as broken:
                    self.fail(f"{model_admin.__class__.__name__}.{name} raised {broken!r}")
                except Exception:
                    pass
