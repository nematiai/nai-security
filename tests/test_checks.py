import sys
import types

from django.http import HttpResponse
from django.test import TestCase, override_settings

from nai_security.checks import (
    check_admin_route,
    check_dangerous_routes,
    check_static_serving,
)


def view(request):
    return HttpResponse('ok')


def urlconf(*patterns):
    """ROOT_URLCONF takes a module path; override_settings clears the URL caches for us."""
    name = f'tests._urls_{len(sys.modules)}'
    module = types.ModuleType(name)
    module.urlpatterns = list(patterns)
    sys.modules[name] = module
    return name


def ids(warnings):
    return [w.id for w in warnings]


class DangerousRouteCheckTest(TestCase):

    def test_flags_a_route_the_middleware_would_block(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('.git/config', view))):
            result = check_dangerous_routes(None)
        self.assertEqual(ids(result), ['nai_security.W001'])
        self.assertIn('.git/config', result[0].msg)

    def test_flags_a_leak_path_route(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('server-status', view))):
            self.assertEqual(ids(check_dangerous_routes(None)), ['nai_security.W001'])

    def test_silent_on_ordinary_routes(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('accounts/login/', view))):
            self.assertEqual(check_dangerous_routes(None), [])

    def test_descends_into_included_urlconfs(self):
        from django.urls import include, path
        nested = urlconf(path('.env', view))
        with override_settings(ROOT_URLCONF=urlconf(path('api/', include(nested)))):
            result = check_dangerous_routes(None)
        self.assertEqual(ids(result), ['nai_security.W001'])
        self.assertIn('api/.env', result[0].msg)

    def test_well_known_is_not_flagged(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('.well-known/acme-challenge/x', view))):
            self.assertEqual(check_dangerous_routes(None), [])


class AdminRouteCheckTest(TestCase):

    def test_flags_the_default_prefix(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('admin/', view))):
            self.assertEqual(ids(check_admin_route(None)), ['nai_security.W002'])

    def test_flags_the_other_default_prefix(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('django-admin/', view))):
            self.assertEqual(ids(check_admin_route(None)), ['nai_security.W002'])

    def test_silent_on_a_custom_prefix(self):
        from django.urls import path
        with override_settings(ROOT_URLCONF=urlconf(path('back-office-9f2/', view))):
            self.assertEqual(check_admin_route(None), [])


class StaticServingCheckTest(TestCase):

    def test_flags_static_served_by_django_in_production(self):
        from django.urls import path
        with override_settings(DEBUG=False, ROOT_URLCONF=urlconf(path('static/<path:p>', view))):
            self.assertEqual(ids(check_static_serving(None)), ['nai_security.W003'])

    def test_silent_in_debug(self):
        from django.urls import path
        with override_settings(DEBUG=True, ROOT_URLCONF=urlconf(path('static/<path:p>', view))):
            self.assertEqual(check_static_serving(None), [])

    def test_silent_without_a_static_route(self):
        from django.urls import path
        with override_settings(DEBUG=False, ROOT_URLCONF=urlconf(path('api/v1/health/', view))):
            self.assertEqual(check_static_serving(None), [])


class UnloadableUrlconfTest(TestCase):

    def test_checks_stay_silent_rather_than_crash_manage_py_check(self):
        with override_settings(ROOT_URLCONF='tests.does_not_exist'):
            self.assertEqual(check_dangerous_routes(None), [])
            self.assertEqual(check_admin_route(None), [])
            self.assertEqual(check_static_serving(None), [])


class CheckRegistrationTest(TestCase):

    def test_all_three_run_under_check_deploy(self):
        from django.core.checks import registry
        registered = {c.__name__ for c in registry.registry.get_checks(include_deployment_checks=True)}
        self.assertLessEqual(
            {'check_dangerous_routes', 'check_admin_route', 'check_static_serving'},
            registered,
        )
