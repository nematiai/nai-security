"""Deployment checks for the URL surface — the half `check --deploy` does not inspect."""

from django.conf import settings
from django.core.checks import Tags, Warning, register
from django.core.exceptions import ImproperlyConfigured
from django.urls import get_resolver
from django.urls.resolvers import URLPattern, URLResolver

from .paths import is_dangerous_path

DEFAULT_ADMIN_ROUTES = ("admin/", "django-admin/")


def _routes(resolver=None, prefix=""):
    resolver = resolver or get_resolver()
    for entry in resolver.url_patterns:
        route = prefix + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from _routes(entry, route)
        elif isinstance(entry, URLPattern):
            yield route


def _safe_routes():
    try:
        return list(_routes())
    except (ImproperlyConfigured, ImportError, AttributeError):
        return []


@register(Tags.security, deploy=True)
def check_dangerous_routes(app_configs, **kwargs):
    hits = sorted({r for r in _safe_routes() if is_dangerous_path("/" + r.lstrip("^/"))})
    if not hits:
        return []
    return [
        Warning(
            "URL patterns resolve to paths nai-security blocks as scanner targets: "
            + ", ".join(hits),
            hint="SecurityMiddleware returns 403 for these before the view runs, so they are "
                 "unreachable. Remove the routes, or add them to NAI_SECURITY_EXEMPT_PATHS.",
            id="nai_security.W001",
        )
    ]


@register(Tags.security, deploy=True)
def check_admin_route(app_configs, **kwargs):
    hits = [r for r in _safe_routes() if r.startswith(DEFAULT_ADMIN_ROUTES)]
    if not hits:
        return []
    return [
        Warning(
            "The Django admin is mounted at a default, guessable prefix.",
            hint="Scanners probe /admin/ and /django-admin/ first. Mount it at a non-obvious "
                 "prefix, or restrict it by IP with WhitelistedIP.",
            id="nai_security.W002",
        )
    ]


@register(Tags.security, deploy=True)
def check_static_serving(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    served = [r for r in _safe_routes() if r.startswith(("static/", "media/"))]
    if not served:
        return []
    return [
        Warning(
            "Django is serving static or media files through the URLconf with DEBUG=False.",
            hint="django.views.static.serve is not hardened for production. Serve these from "
                 "nginx or object storage instead.",
            id="nai_security.W003",
        )
    ]
