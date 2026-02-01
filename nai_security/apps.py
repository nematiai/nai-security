from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nai_security'
    verbose_name = 'Security'

    def ready(self):
        # Import signals to register them
        try:
            from . import signals  # noqa
        except ImportError:
            pass
