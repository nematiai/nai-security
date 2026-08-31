from django.apps import AppConfig, apps


class NaiSecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nai_security'
    verbose_name = 'NAI Security'

    def ready(self):
        from . import signals  # noqa: F401

        if apps.is_installed('axes'):
            from .handlers.axes_integration import DynamicAxesHandler
            DynamicAxesHandler.configure_dynamic_settings()
