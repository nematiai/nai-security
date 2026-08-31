from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("nai_security", "0005_alter_whitelisteduser_exemption_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="securitysettings",
            name="path_blocking_enabled",
            field=models.BooleanField(
                default=True,
                help_text="Block requests to /.git, /.env, server-status, and similar leak paths",
            ),
        ),
    ]
