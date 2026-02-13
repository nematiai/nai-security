from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('nai_security', '0001_initial'),
    ]

    operations = [
        # This is a no-op for databases where 0001 already includes max_login_attempts.
        # Kept for migration graph compatibility with existing deployments.
    ]
