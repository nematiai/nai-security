from django.db import models
from django.core.cache import cache
from django.core.validators import MinValueValidator, MaxValueValidator


class SecuritySettings(models.Model):
    """
    Global security settings (singleton model).
    Configurable thresholds for automation.
    """
    
    # Auto-blocking thresholds
    auto_block_ip_threshold = models.PositiveIntegerField(
        default=10,
        help_text="Block IP after this many security events in the time window"
    )
    auto_block_ip_window_hours = models.PositiveIntegerField(
        default=1,
        help_text="Time window (hours) for IP auto-block threshold"
    )
    auto_block_ip_duration_hours = models.PositiveIntegerField(
        default=24,
        help_text="How long to auto-block an IP (hours). 0 = permanent"
    )
    
    # Login attempt limits (django-axes)
    max_login_attempts = models.PositiveIntegerField(
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        help_text="Maximum failed login attempts before account lockout (1-100)"
    )
    axes_cooloff_minutes = models.PositiveIntegerField(
        default=0,
        validators=[MaxValueValidator(1440)],
        help_text="Minutes before locked account auto-unlocks (0 = permanent lock until manual reset)"
    )
    axes_attempt_expiry_enabled = models.BooleanField(
        default=False,
        help_text="Each failed attempt expires independently (requires cooloff > 0)"
    )

    auto_block_country_threshold = models.PositiveIntegerField(
        default=100,
        help_text="Consider auto-blocking country after this many attacks"
    )
    auto_block_country_window_hours = models.PositiveIntegerField(
        default=24,
        help_text="Time window (hours) for country auto-block threshold"
    )
    auto_block_country_enabled = models.BooleanField(
        default=False,
        help_text="Auto-block countries (requires manual review)"
    )
    
    # Login anomaly detection
    alert_on_new_country = models.BooleanField(
        default=True,
        help_text="Flag login as suspicious when from new country"
    )
    alert_on_new_ip = models.BooleanField(
        default=False,
        help_text="Flag login as suspicious when from new IP"
    )
    max_countries_per_day = models.PositiveIntegerField(
        default=3,
        help_text="Flag as suspicious if user logs in from more countries in a day"
    )
    
    # Sync settings
    sync_disposable_domains = models.BooleanField(
        default=True,
        help_text="Auto-sync disposable email domain list"
    )
    sync_bad_bots = models.BooleanField(
        default=True,
        help_text="Auto-sync bad bot user agent list"
    )
    last_sync_at = models.DateTimeField(null=True, blank=True)
    
    # Notifications
    notify_on_auto_block = models.BooleanField(
        default=True,
        help_text="Send notification when IP/country is auto-blocked"
    )
    notification_email = models.EmailField(
        blank=True,
        help_text="Email for security notifications"
    )
    telegram_notifications = models.BooleanField(
        default=False,
        help_text="Send Telegram notifications"
    )
    
    # Feature toggles
    country_blocking_enabled = models.BooleanField(default=True)
    country_whitelist_mode = models.BooleanField(
        default=False,
        help_text="If enabled, only allowed countries can access"
    )
    ip_blocking_enabled = models.BooleanField(default=True)
    email_blocking_enabled = models.BooleanField(default=True)
    domain_blocking_enabled = models.BooleanField(default=True)
    user_agent_blocking_enabled = models.BooleanField(default=True)
    login_history_enabled = models.BooleanField(default=True)
    
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_settings"
        verbose_name = "Security Settings"
        verbose_name_plural = "Security Settings"

    def __str__(self):
        return "Security Settings"

    def save(self, *args, **kwargs):
        # Ensure only one instance exists (singleton)
        self.pk = 1
        super().save(*args, **kwargs)
        # Clear cache when settings change
        cache.delete('security_settings')
        # Propagate axes settings changes at runtime
        try:
            from datetime import timedelta
            from django.conf import settings as django_settings
            django_settings.AXES_USE_ATTEMPT_EXPIRATION = self.axes_attempt_expiry_enabled
            if self.axes_cooloff_minutes > 0:
                django_settings.AXES_COOLOFF_TIME = timedelta(minutes=self.axes_cooloff_minutes)
            else:
                django_settings.AXES_COOLOFF_TIME = None
        except Exception:
            pass

    @classmethod
    def get_settings(cls) -> 'SecuritySettings':
        """Get or create the singleton settings instance (cached)."""
        cached = cache.get('security_settings')
        if cached:
            return cached
        
        settings, _ = cls.objects.get_or_create(pk=1)
        cache.set('security_settings', settings, 300)  # Cache 5 minutes
        return settings

    @classmethod
    def load(cls):
        """Alias for get_settings()."""
        return cls.get_settings()
