from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nai_security'
    verbose_name = 'NAI Security'

    def ready(self):
        """Import signals and configure Axes when app is ready."""
        # Import signals to register them
        import nai_security.signals  # noqa
        
        # Configure Django Axes
        from django.conf import settings
        
        # Set default Axes configuration if not already set
        if not hasattr(settings, 'AXES_HANDLER'):
            settings.AXES_HANDLER = 'nai_security.handlers.progressive_lockout.ProgressiveLockoutHandler'
        
        if not hasattr(settings, 'AXES_FAILURE_LIMIT'):
            settings.AXES_FAILURE_LIMIT = 999  # We handle limits in our handler
        
        if not hasattr(settings, 'AXES_LOCK_OUT_AT_FAILURE'):
            settings.AXES_LOCK_OUT_AT_FAILURE = False  # We handle lockouts manually
        
        if not hasattr(settings, 'AXES_COOLOFF_TIME'):
            settings.AXES_COOLOFF_TIME = 1  # Default 1 hour (overridden by our handler)
        
        if not hasattr(settings, 'AXES_ENABLE_ACCESS_FAILURE_LOG'):
            settings.AXES_ENABLE_ACCESS_FAILURE_LOG = True
        
        if not hasattr(settings, 'AXES_RESET_ON_SUCCESS'):
            settings.AXES_RESET_ON_SUCCESS = True
