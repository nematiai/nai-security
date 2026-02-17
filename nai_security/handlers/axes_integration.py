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
        # Preserve the original AXES_FAILURE_LIMIT as a fallback (only on first call)
        if not hasattr(django_settings, 'AXES_FAILURE_LIMIT_DEFAULT'):
            original_limit = getattr(django_settings, 'AXES_FAILURE_LIMIT', 5)
            django_settings.AXES_FAILURE_LIMIT_DEFAULT = original_limit

        # Set failure limit to our dynamic callable
        django_settings.AXES_FAILURE_LIMIT = get_dynamic_failure_limit

        # Set cooloff and attempt expiration from SecuritySettings
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
