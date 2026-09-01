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


@register(Tags.security, deploy=True)
def check_fingerprint_headers(app_configs, **kwargs):
    installed = any(
        mw.endswith("ResponseHeaderMiddleware")
        for mw in getattr(settings, "MIDDLEWARE", [])
    )
    if installed:
        return []
    return [
        Warning(
            "Responses may advertise the stack to scanners.",
            hint="Add 'nai_security.middleware.ResponseHeaderMiddleware' to MIDDLEWARE to strip "
                 "Server, X-Powered-By and similar. Headers set by nginx or gunicorn must be "
                 "removed at that layer instead.",
            id="nai_security.W004",
        )
    ]


@register(Tags.security, deploy=True)
def check_allowed_hosts_wildcard(app_configs, **kwargs):
    hosts = list(getattr(settings, "ALLOWED_HOSTS", []))
    if "*" not in hosts:
        return []
    return [
        Warning(
            "ALLOWED_HOSTS accepts any Host header ('*').",
            hint="Django's security.W020 only fires on an empty list, so this passes it. An "
                 "attacker controls the Host header, which reaches password-reset links, "
                 "absolute URLs built with build_absolute_uri(), and cache keys. List the real "
                 "hostnames instead.",
            id="nai_security.W005",
        )
    ]


@register(Tags.security, deploy=True)
def check_cors_configuration(app_configs, **kwargs):
    allow_all = getattr(settings, "CORS_ALLOW_ALL_ORIGINS", None)
    if allow_all is None:
        allow_all = getattr(settings, "CORS_ORIGIN_ALLOW_ALL", False)
    wildcard_listed = "*" in list(getattr(settings, "CORS_ALLOWED_ORIGINS", []))
    if not (allow_all or wildcard_listed):
        return []

    if getattr(settings, "CORS_ALLOW_CREDENTIALS", False):
        return [
            Warning(
                "CORS allows every origin AND credentials.",
                hint="Any site can drive authenticated requests as your logged-in users. "
                     "Browsers reject the literal pair, so django-cors-headers echoes the "
                     "request origin back instead — which is the same thing without the "
                     "protection. Set CORS_ALLOWED_ORIGINS to the real origins.",
                id="nai_security.W006",
            )
        ]
    return [
        Warning(
            "CORS allows every origin.",
            hint="Any site can read responses from your API. Replace CORS_ALLOW_ALL_ORIGINS "
                 "with an explicit CORS_ALLOWED_ORIGINS list.",
            id="nai_security.W006",
        )
    ]
