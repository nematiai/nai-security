# Generated manually for nai-security 1.3.0

from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('nai_security', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='securitysettings',
            name='max_login_attempts',
            field=models.PositiveIntegerField(
                default=5,
                help_text='Maximum failed login attempts before account lockout (1-100)',
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(100)
                ]
            ),
        ),
    ]