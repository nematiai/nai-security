"""
Axes integration to use dynamic settings from SecuritySettings.

In axes 8.x, AXES_FAILURE_LIMIT supports callables that are invoked per-request.
AXES_COOLOFF_TIME and AXES_USE_ATTEMPT_EXPIRATION are set as static values
and updated whenever SecuritySettings is saved.
"""
import logging
from datetime import timedelta
from typing import Optional

from django.conf import settings as django_settings
from django.http import HttpRequest
from axes.handlers.database import AxesDatabaseHandler

logger = logging.getLogger(__name__)


def get_dynamic_failure_limit(request: HttpRequest, credentials: Optional[dict] = None) -> int:
    """
    Callable for AXES_FAILURE_LIMIT that reads from SecuritySettings.
    Falls back to AXES_FAILURE_LIMIT_DEFAULT if SecuritySettings unavailable.
    """
    try:
        from nai_security.models import SecuritySettings
        settings = SecuritySettings.get_settings()
        return settings.max_login_attempts
    except Exception:
        return getattr(django_settings, 'AXES_FAILURE_LIMIT_DEFAULT', 5)


class DynamicAxesHandler(AxesDatabaseHandler):
    """
    Custom Axes handler that reads settings from the SecuritySettings model.

    Call configure_dynamic_settings() during app startup to wire up
    AXES_FAILURE_LIMIT as a callable and set AXES_COOLOFF_TIME /
    AXES_USE_ATTEMPT_EXPIRATION from the database.
    """

    @classmethod
    def configure_dynamic_settings(cls):
        """
        Configure axes settings to use dynamic values from SecuritySettings.
        Called from NaiSecurityConfig.ready().
        """
        if not hasattr(django_settings, 'AXES_FAILURE_LIMIT_DEFAULT'):
            original_limit = getattr(django_settings, 'AXES_FAILURE_LIMIT', 5)
            django_settings.AXES_FAILURE_LIMIT_DEFAULT = original_limit

        django_settings.AXES_FAILURE_LIMIT = get_dynamic_failure_limit
        cls._update_cooloff_time()
        cls._update_attempt_expiration()

    @classmethod
    def _update_cooloff_time(cls):
        """Update AXES_COOLOFF_TIME from SecuritySettings."""
        try:
            from nai_security.models import SecuritySettings
            settings = SecuritySettings.get_settings()
            if settings.axes_cooloff_minutes > 0:
                django_settings.AXES_COOLOFF_TIME = timedelta(minutes=settings.axes_cooloff_minutes)
            else:
                django_settings.AXES_COOLOFF_TIME = None
        except Exception:
            pass

    @classmethod
    def _update_attempt_expiration(cls):
        """Update AXES_USE_ATTEMPT_EXPIRATION from SecuritySettings."""
        try:
            from nai_security.models import SecuritySettings
            settings = SecuritySettings.get_settings()
            django_settings.AXES_USE_ATTEMPT_EXPIRATION = settings.axes_attempt_expiry_enabled
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Whitelist bypass
    # -------------------------------------------------------------------------

    def _resolve_username(self, request: Optional[HttpRequest], credentials: Optional[dict]) -> Optional[str]:
        """
        Resolve the login username from credentials OR request body.
        Delegates to axes' own helper so DRF/JSON/form bodies and AXES_USERNAME_CALLABLE
        are all handled consistently with the rest of axes.
        """
        try:
            from axes.helpers import get_client_username
            return get_client_username(request, credentials)
        except Exception:
            return None

    def _lookup_user(self, username: str):
        """
        Tolerant user lookup. Tries USERNAME_FIELD first, then falls back to
        email__iexact when USERNAME_FIELD != 'email' — covers the common case
        where the login form posts an email but USERNAME_FIELD is 'username'.
        """
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.filter(**{User.USERNAME_FIELD: username}).first()
            if user is not None:
                return user
            if User.USERNAME_FIELD != 'email':
                field_names = {f.name for f in User._meta.get_fields()}
                if 'email' in field_names:
                    return User.objects.filter(email__iexact=username).first()
            return None
        except Exception:
            logger.exception("User lookup failed for username=%s", username)
            return None

    def _is_user_active_whitelisted(self, user) -> bool:
        """
        Any active (non-expired) WhitelistedUser row exempts the user from axes
        lockout — exemption_type is intentionally ignored here. The user-facing
        granularity (ip_block / rate_limit / geo_block) applies to the
        SecurityMiddleware path; for axes lockout the rule is binary.
        """
        try:
            from nai_security.models import WhitelistedUser
            from django.utils import timezone
            wl = WhitelistedUser.objects.filter(user=user, is_active=True).first()
            if wl is None:
                return False
            if wl.expires_at and wl.expires_at < timezone.now():
                return False
            return True
        except Exception:
            logger.exception("Whitelist row check failed for user_id=%s", getattr(user, 'pk', None))
            return False

    def _is_request_whitelisted(self, request: Optional[HttpRequest], credentials: Optional[dict]) -> bool:
        """
        Unified bypass: True if the request matches ANY whitelist source —
        WhitelistedIP for the client IP, or an active WhitelistedUser for the
        resolved login user. The IP check runs first so requests with no
        credentials (e.g., GET /login/, CSRF fetches) still bypass when the
        source IP is whitelisted.
        """
        if request is not None:
            try:
                from nai_security.utils import get_client_ip
                from nai_security.models import WhitelistedIP
                ip = get_client_ip(request)
                if ip and WhitelistedIP.is_whitelisted(ip):
                    return True
            except Exception:
                logger.exception("IP whitelist check failed")

        username = self._resolve_username(request, credentials)
        if not username:
            return False
        user = self._lookup_user(username)
        if user is None:
            return False
        return self._is_user_active_whitelisted(user)

    def is_allowed(self, request: HttpRequest, credentials: Optional[dict] = None) -> bool:
        """Whitelisted IPs and users are always allowed — short-circuits axes checks."""
        if self._is_request_whitelisted(request, credentials):
            return True
        return super().is_allowed(request, credentials)

    def is_locked(self, request: HttpRequest, credentials: Optional[dict] = None) -> bool:
        """
        Skip lockout for any whitelisted request.
        axes 8.x renamed `is_already_locked` -> `is_locked` (called from is_allowed
        and from axes.helpers.get_lockout_response).
        """
        if self._is_request_whitelisted(request, credentials):
            logger.debug("Axes lockout check skipped — whitelisted request")
            return False
        return super().is_locked(request, credentials)

    def user_login_failed(self, sender, credentials, request, **kwargs):
        """Skip recording failures for whitelisted requests — keeps AccessAttempt clean."""
        if self._is_request_whitelisted(request, credentials):
            logger.debug("Axes failure recording skipped — whitelisted request")
            return
        super().user_login_failed(sender, credentials, request, **kwargs)