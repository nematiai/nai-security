from django.db import models
from django.conf import settings


class LoginHistory(models.Model):
    """Track successful login attempts for security monitoring."""
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='login_history',
        db_index=True
    )
    ip_address = models.GenericIPAddressField(db_index=True)
    country_code = models.CharField(max_length=2, blank=True, db_index=True)
    city = models.CharField(max_length=100, blank=True)
    user_agent = models.TextField(blank=True)
    device_type = models.CharField(max_length=50, blank=True, help_text="mobile, desktop, tablet")
    browser = models.CharField(max_length=100, blank=True)
    os = models.CharField(max_length=100, blank=True)
    is_suspicious = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Flagged as suspicious (new country, rapid IP change, etc.)"
    )
    suspicious_reason = models.CharField(max_length=255, blank=True)
    session_key = models.CharField(max_length=255, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "security_login_history"
        verbose_name = "Login History"
        verbose_name_plural = "Login History"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['country_code', '-created_at']),
        ]

    def __str__(self):
        suspicious = " [SUSPICIOUS]" if self.is_suspicious else ""
        return f"{self.user} - {self.ip_address} ({self.country_code}){suspicious}"

    @classmethod
    def get_user_countries(cls, user, limit=10):
        """Get distinct countries user has logged in from."""
        return cls.objects.filter(user=user).values_list(
            'country_code', flat=True
        ).distinct()[:limit]

    @classmethod
    def get_recent_logins(cls, user, limit=10):
        """Get recent login history for user."""
        return cls.objects.filter(user=user).order_by('-created_at')[:limit]

    @classmethod
    def is_new_country(cls, user, country_code) -> bool:
        """Check if this is a new country for the user."""
        if not country_code:
            return False
        return not cls.objects.filter(
            user=user,
            country_code=country_code
        ).exists()

    @classmethod
    def is_new_ip(cls, user, ip_address) -> bool:
        """Check if this is a new IP for the user."""
        return not cls.objects.filter(
            user=user,
            ip_address=ip_address
        ).exists()
