import os
import subprocess
import sys

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

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
        from axes.models import AccessAttempt, AccessFailureLog, AccessLog
        from django.contrib.admin.sites import site
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

class BareInstallTest(TestCase):
    """`pip install nai-security` with no extras must still boot Django."""

    def _import_admin_without(self, *blocked):
        code = (
            "import sys\n"
            f"BLOCKED = {blocked!r}\n"
            "class Blocker:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] in BLOCKED:\n"
            "            raise ImportError(name)\n"
            "sys.meta_path.insert(0, Blocker())\n"
            "from django.conf import settings\n"
            "settings.configure(\n"
            "    SECRET_KEY='x'*60, DEBUG=False,\n"
            "    INSTALLED_APPS=['django.contrib.contenttypes','django.contrib.auth',\n"
            "                    'django.contrib.admin','django.contrib.sessions',\n"
            "                    'django.contrib.messages','nai_security'],\n"
            "    DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':':memory:'}},\n"
            "    USE_TZ=True,\n"
            ")\n"
            "import django; django.setup()\n"
            "import nai_security.admin\n"
            "print('IMPORT_OK')\n"
        )
        env = {k: v for k, v in os.environ.items() if k != 'DJANGO_SETTINGS_MODULE'}
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)

    def test_admin_imports_without_import_export(self):
        result = self._import_admin_without("import_export")
        self.assertIn("IMPORT_OK", result.stdout, result.stderr[-800:])

    def test_admin_imports_without_unfold_or_import_export(self):
        result = self._import_admin_without("import_export", "unfold")
        self.assertIn("IMPORT_OK", result.stdout, result.stderr[-800:])

    def test_fallback_bases_are_distinct(self):
        from nai_security.admin import IMPORT_EXPORT_BASES
        self.assertEqual(len(set(IMPORT_EXPORT_BASES)), len(IMPORT_EXPORT_BASES))
