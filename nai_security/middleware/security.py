import logging
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
    2. Blocked IPs
    3. Blocked Countries / Allowed Countries
    4. Blocked User Agents
    """

    EXEMPT_PATHS = ['/health/', '/health', '/ready/', '/ready', '/favicon.ico']

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get settings
        settings = SecuritySettings.get_settings()

        # Skip exempt paths
        if request.path in self.EXEMPT_PATHS:
            return self.get_response(request)

        ip_address = get_client_ip(request)

        # Skip localhost
        if ip_address in ('127.0.0.1', 'localhost', '::1'):
            return self.get_response(request)

        # Check whitelist first
        if self._is_whitelisted(ip_address):
            return self.get_response(request)

        user_agent = request.META.get('HTTP_USER_AGENT', '')
        country_code = get_country_from_ip(ip_address)
        request.country_code = country_code  # Store for later use

        # Check IP blacklist
        if settings.ip_blocking_enabled and self._is_ip_blocked(ip_address):
            self._log_block(ip_address, 'IP_BLOCK', request, country_code, user_agent)
            return HttpResponseForbidden("Access denied")

        # Check User Agent
        if settings.user_agent_blocking_enabled and self._is_user_agent_blocked(user_agent):
            self._log_block(ip_address, 'USER_AGENT_BLOCK', request, country_code, user_agent)
            return HttpResponseForbidden("Access denied")

        # Check country (whitelist mode or blacklist mode)
        if country_code:
            if settings.country_whitelist_mode:
                if not self._is_country_allowed(country_code):
                    self._log_block(ip_address, 'COUNTRY_WHITELIST_BLOCK', request, country_code, user_agent)
                    return HttpResponseForbidden("Access denied from your region")
            elif settings.country_blocking_enabled:
                if self._is_country_blocked(country_code):
                    self._log_block(ip_address, 'COUNTRY_BLOCK', request, country_code, user_agent)
                    return HttpResponseForbidden("Access denied from your region")

        return self.get_response(request)

    def _is_whitelisted(self, ip_address: str) -> bool:
        cache_key = f"sec_whitelist:{ip_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        from ..models import WhitelistedIP
        result = WhitelistedIP.is_whitelisted(ip_address)
        cache.set(cache_key, result, 300)
        return result

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
            # Increment block count
            BlockedUserAgent.objects.filter(pk=pattern.pk).update(
                block_count=F('block_count') + 1
            )

        return is_blocked

    def _log_block(self, ip_address, action, request, country_code, user_agent):
        SecurityLog.log_event(
            ip_address=ip_address,
            action=action,
            path=request.path,
            method=request.method,
            country_code=country_code or '',
            user_agent=user_agent,
        )
        logger.warning(f"{action}: {ip_address} ({country_code}) - {request.path}")


class RateLimitLoggingMiddleware:
    """Logs rate limit events from django-ratelimit."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        was_limited = getattr(request, 'limited', False)
        if was_limited:
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
            logger.warning(f"RATE_LIMIT: {ip_address} - {request.path}")

        return response
