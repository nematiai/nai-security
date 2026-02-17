from django.apps import AppConfig


class NaiSecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nai_security'
    verbose_name = 'NAI Security'

    def ready(self):
        from . import signals  # noqa: F401

        # Configure axes dynamic settings if axes is installed
        try:
            from .handlers.axes_integration import DynamicAxesHandler
            DynamicAxesHandler.configure_dynamic_settings()
        except ImportError:
            pass
