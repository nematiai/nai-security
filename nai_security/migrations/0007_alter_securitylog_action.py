from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nai_security", "0006_securitysettings_path_blocking_enabled"),
    ]

    operations = [
        migrations.AlterField(
            model_name="securitylog",
            name="action",
            field=models.CharField(
                choices=[
                    ("COUNTRY_BLOCK", "Blocked by Country"),
                    ("COUNTRY_WHITELIST_BLOCK", "Blocked - Country Not in Whitelist"),
                    ("IP_BLOCK", "Blocked by IP"),
                    ("EMAIL_BLOCK", "Blocked by Email"),
                    ("DOMAIN_BLOCK", "Blocked by Domain"),
                    ("USER_AGENT_BLOCK", "Blocked by User Agent"),
                    ("PATH_BLOCK", "Blocked by Path"),
                    ("RATE_LIMIT", "Rate Limited"),
                    ("AXES_LOCK", "Login Locked (Axes)"),
                    ("SUSPICIOUS_LOGIN", "Suspicious Login Detected"),
                    ("AUTO_BLOCK_IP", "IP Auto-Blocked"),
                    ("AUTO_BLOCK_COUNTRY", "Country Auto-Blocked"),
                ],
                db_index=True,
                max_length=30,
            ),
        ),
    ]
