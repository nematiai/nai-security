import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def rename_table_if_exists(apps, schema_editor):
    """Rename old table prefix if it exists, otherwise create the table."""
    connection = schema_editor.connection
    tables = connection.introspection.table_names()

    if 'nai_security_whitelisted_user' in tables:
        schema_editor.execute("ALTER TABLE nai_security_whitelisted_user RENAME TO security_whitelisted_user;")
    # If neither table exists, CreateModel below will handle it.
    # If security_whitelisted_user already exists, CreateModel will be skipped by the if_not_exists logic.


def reverse_rename(apps, schema_editor):
    connection = schema_editor.connection
    tables = connection.introspection.table_names()
    if 'security_whitelisted_user' in tables:
        schema_editor.execute("ALTER TABLE security_whitelisted_user RENAME TO nai_security_whitelisted_user;")


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('nai_security', '0002_securitysettings_max_login_attempts'),
    ]

    operations = [
        # Step 1: Rename old table if it exists
        migrations.RunPython(rename_table_if_exists, reverse_rename),

        # Step 2: Create table if it doesn't exist (fresh installs)
        migrations.CreateModel(
            name='WhitelistedUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('exemption_type', models.CharField(
                    choices=[('rate_limit', 'Rate Limiting Only'), ('ip_block', 'IP Blocking Only'), ('all', 'All Security Checks')],
                    default='all',
                    help_text='Type of security check to bypass',
                    max_length=20,
                )),
                ('reason', models.TextField(blank=True, help_text='Reason for whitelisting this user')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this whitelist entry is active')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, help_text='Optional expiration date for temporary exemptions', null=True)),
                ('user', models.OneToOneField(
                    help_text='User to exempt from security checks',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='security_whitelist',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='whitelists_created',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'Whitelisted User',
                'verbose_name_plural': 'Whitelisted Users',
                'db_table': 'security_whitelisted_user',
            },
        ),
    ]
