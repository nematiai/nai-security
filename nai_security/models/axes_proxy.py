from django.db import models

try:
    from axes.models import AccessAttempt as AxesAccessAttempt

    class AccessAttempt(AxesAccessAttempt):
        """Proxy model to show Axes AccessAttempt under Security app."""
        
        class Meta:
            proxy = True
            verbose_name = "Access Attempt"
            verbose_name_plural = "Access Attempts"
            app_label = 'security'

except ImportError:
    # axes not installed
    AccessAttempt = None