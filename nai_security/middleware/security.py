import logging
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.db.models import F

from ..utils import get_client_ip, get_country_from_ip
from ..models import SecurityLog, SecuritySettings

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Main security middleware that checks:
    1. Whitelisted IPs (bypass all checks)
    2. Whitelisted Users (bypass based on exemption_type)
    3. Blocked IPs
    4. Blocked Countries / Allowed Countries
    5. Blocked User Agents

    MUST be placed AFTER django.contrib.auth.middleware.AuthenticationMiddleware
    in MIDDLEWARE settings. Raises ImproperlyConfigured on startup if misordered.
    """

    DEFAULT_EXEMPT_PATHS = ['/health/', '/health', '/ready/', '/ready', '/favicon.ico']

    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = set(
            getattr(django_settings, 'NAI_SECURITY_EXEMPT_PATHS', self.DEFAULT_EXEMPT_PATHS)
        )
        self._validate_middleware_order()

    def _validate_middleware_order(self):
        """Ensure this middleware runs after AuthenticationMiddleware."""
        middlewares = list(getattr(django_settings, 'MIDDLEWARE', []))
        auth_mw = 'django.contrib.auth.middleware.AuthenticationMiddleware'

        # Resolve our own dotted path to match against MIDDLEWARE entries
        our_path = f'{self.__class__.__module__}.{self.__class__.__name__}'
        # Also match the short form via __init__.py re-export
        our_paths = {
            our_path,
            'nai_security.middleware.SecurityMiddleware',
            'nai_security.middleware.security.SecurityMiddleware',
        }

        our_idx = None
        for idx, mw in enumerate(middlewares):
            if mw in our_paths:
                our_idx = idx
                break

        if our_idx is None:
            return  # Can't validate — middleware loaded dynamically

        if auth_mw not in middlewares:
            raise ImproperlyConfigured(
                "nai_security.middleware.SecurityMiddleware requires "
                "django.contrib.auth.middleware.AuthenticationMiddleware "
                "to be present in MIDDLEWARE settings."
            )

        auth_idx = middlewares.index(auth_mw)
        if our_idx < auth_idx:
            raise ImproperlyConfigured(
                "nai_security.middleware.SecurityMiddleware must be placed "
                "AFTER django.contrib.auth.middleware.AuthenticationMiddleware "
                "in MIDDLEWARE settings. Found SecurityMiddleware at index "
                f"{our_idx}, AuthenticationMiddleware at index {auth_idx}."
            )

    def __call__(self, request):
        settings = SecuritySettings.get_settings()

        # Skip exempt paths
        if request.path in self.exempt_paths:
            return self.get_response(request)

        ip_address = get_client_ip(request)

        # Skip localhost
        if ip_address in ('127.0.0.1', 'localhost', '::1'):
            return self.get_response(request)

        # Check IP whitelist first
        if self._is_ip_whitelisted(ip_address):
            return self.get_response(request)

        # Check user exemption (request.user guaranteed by middleware ordering)
        user = request.user
        user_exemption = None
        if user.is_authenticated:
            user_exemption = self._get_user_exemption(user.pk)

        # 'all' exemption bypasses entire middleware
        if user_exemption == 'all':
            return self.get_response(request)

        user_agent = request.META.get('HTTP_USER_AGENT', '')
        country_code = get_country_from_ip(ip_address)
        request.country_code = country_code

        # Check IP blacklist — 'ip_block' exemption bypasses this
        if settings.ip_blocking_enabled and self._is_ip_blocked(ip_address):
            if user_exemption != 'ip_block':
                self._log_block(ip_address, 'IP_BLOCK', request, country_code, user_agent)
                return HttpResponseForbidden("Access denied")

        # Check User Agent — no granular exemption, only 'all' bypasses (handled above)
        if settings.user_agent_blocking_enabled and self._is_user_agent_blocked(user_agent):
            self._log_block(ip_address, 'USER_AGENT_BLOCK', request, country_code, user_agent)
            return HttpResponseForbidden("Access denied")

        # Check country — 'geo_block' exemption bypasses this
        if country_code and user_exemption != 'geo_block':
            if settings.country_whitelist_mode:
                if not self._is_country_allowed(country_code):
                    self._log_block(ip_address, 'COUNTRY_WHITELIST_BLOCK', request, country_code, user_agent)
                    return HttpResponseForbidden("Access denied from your region")
            elif settings.country_blocking_enabled:
                if self._is_country_blocked(country_code):
                    self._log_block(ip_address, 'COUNTRY_BLOCK', request, country_code, user_agent)
                    return HttpResponseForbidden("Access denied from your region")

        return self.get_response(request)

    def _get_user_exemption(self, user_id):
        """
        Get the exemption type for a whitelisted user.
        Returns exemption_type string ('all', 'ip_block', 'rate_limit') or None.
        Single DB query, cached for 5 minutes.
        """
        if user_id is None:
            return None

        cache_key = f"sec_user_exempt:{user_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached if cached != '_none_' else None

        from ..models import WhitelistedUser
        from django.utils import timezone

        try:
            whitelist = WhitelistedUser.objects.filter(
                user_id=user_id,
                is_active=True,
            ).first()

            if whitelist is None:
                cache.set(cache_key, '_none_', 300)
                return None

            if whitelist.expires_at and whitelist.expires_at < timezone.now():
                cache.set(cache_key, '_none_', 300)
                return None

            cache.set(cache_key, whitelist.exemption_type, 300)
            return whitelist.exemption_type
        except Exception as e:
            logger.error("Failed to check user exemption for user_id=%s: %s", user_id, e)
            return None

    # ------------------------------------------------------------------
    # IP whitelist
    # ------------------------------------------------------------------

    def _is_ip_whitelisted(self, ip_address: str) -> bool:
        cache_key = f"sec_whitelist:{ip_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        from ..models import WhitelistedIP
        result = WhitelistedIP.is_whitelisted(ip_address)
        cache.set(cache_key, result, 300)
        return result

    # ------------------------------------------------------------------
    # Blocking checks
    # ------------------------------------------------------------------

    def _is_ip_blocked(self, ip_address: str) -> bool:
        cache_key = f"sec_blocked_ip:{ip_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        from ..models import BlockedIP
        from django.utils import timezone

        blocked = BlockedIP.objects.filter(ip_address=ip_address, is_active=True).first()
        if blocked is None:
            cache.set(cache_key, False, 300)
            return False

        if blocked.expires_at and timezone.now() > blocked.expires_at:
            cache.set(cache_key, False, 300)
            return False

        cache.set(cache_key, True, 300)
        return True

    def _is_country_blocked(self, country_code: str) -> bool:
        cache_key = f"sec_blocked_country:{country_code}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        from ..models import BlockedCountry
        result = BlockedCountry.objects.filter(code=country_code, is_active=True).exists()
        cache.set(cache_key, result, 300)
        return result

    def _is_country_allowed(self, country_code: str) -> bool:
        cache_key = f"sec_allowed_country:{country_code}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        from ..models import AllowedCountry
        result = AllowedCountry.is_country_allowed(country_code)
        cache.set(cache_key, result, 300)
        return result

    def _is_user_agent_blocked(self, user_agent: str) -> bool:
        if not user_agent:
            return False

        from ..models import BlockedUserAgent
        is_blocked, pattern = BlockedUserAgent.is_user_agent_blocked(user_agent)

        if is_blocked and pattern:
            self._increment_ua_block_count(pattern.pk)

        return is_blocked

    @staticmethod
    def _increment_ua_block_count(pattern_pk, flush_threshold=100):
        """Batch UA block count in cache, flush to DB every flush_threshold hits."""
        from ..models import BlockedUserAgent

        cache_key = f"sec_ua_count:{pattern_pk}"
        try:
            count = cache.incr(cache_key)
        except ValueError:
            cache.set(cache_key, 1, 3600)
            return

        if count >= flush_threshold:
            BlockedUserAgent.objects.filter(pk=pattern_pk).update(
                block_count=F('block_count') + count
            )
            cache.delete(cache_key)

    def _log_block(self, ip_address, action, request, country_code, user_agent):
        SecurityLog.log_event(
            ip_address=ip_address,
            action=action,
            path=request.path,
            method=request.method,
            country_code=country_code or '',
            user_agent=user_agent,
        )
        logger.warning("%s: %s (%s) - %s", action, ip_address, country_code, request.path)


class RateLimitLoggingMiddleware:
    """
    Logs rate limit events from django-ratelimit.
    Respects 'rate_limit' and 'all' user exemptions from WhitelistedUser.

    MUST be placed AFTER django.contrib.auth.middleware.AuthenticationMiddleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        was_limited = getattr(request, 'limited', False)
        if not was_limited:
            return response

        # Check user exemption — 'rate_limit' or 'all' bypasses rate limit logging
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            from ..models import WhitelistedUser
            if WhitelistedUser.is_whitelisted(user, check_type='rate_limit'):
                return response

        ip_address = get_client_ip(request)
        country_code = getattr(request, 'country_code', '')
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        SecurityLog.log_event(
            ip_address=ip_address,
            action='RATE_LIMIT',
            path=request.path,
            method=request.method,
            country_code=country_code,
            user_agent=user_agent,
        )
        logger.warning("RATE_LIMIT: %s - %s", ip_address, request.path)

        return response
