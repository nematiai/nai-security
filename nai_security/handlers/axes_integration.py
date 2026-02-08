"""
Axes integration to use dynamic max_login_attempts from SecuritySettings.
"""
from django.conf import settings as django_settings
from axes.handlers.database import AxesDatabaseHandler


class DynamicAxesHandler(AxesDatabaseHandler):
    """
    Custom Axes handler that reads max_attempts from SecuritySettings.
    Falls back to AXES_FAILURE_LIMIT if SecuritySettings not available.
    """
    
    def get_failure_limit(self, request, credentials):
        """
        Get the failure limit from SecuritySettings, with fallback to Django settings.
        """
        try:
            from nai_security.models import SecuritySettings
            settings = SecuritySettings.get_settings()
            return settings.max_login_attempts
        except Exception:
            # Fallback to default AXES_FAILURE_LIMIT
            return getattr(django_settings, 'AXES_FAILURE_LIMIT', 5)
    
    def is_allowed(self, request, credentials=None):
        """
        Override to use dynamic failure limit.
        """
        # Get current attempt count
        attempt_count = self.get_failures(request, credentials)
        
        # Get dynamic limit
        failure_limit = self.get_failure_limit(request, credentials)
        
        # Check if locked
        return attempt_count < failure_limit