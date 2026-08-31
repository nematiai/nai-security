from django.apps import apps

if apps.is_installed('axes'):
    from .axes_integration import DynamicAxesHandler

    __all__ = ['DynamicAxesHandler']
