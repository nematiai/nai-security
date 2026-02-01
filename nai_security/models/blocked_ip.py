from django.db import models
from django.utils import timezone


class BlockedIP(models.Model):
    """Manually or automatically blocked IP addresses."""
    
    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        help_text="IP address to block (IPv4 or IPv6)"
    )
    reason = models.TextField(blank=True, help_text="Reason for blocking")
    is_active = models.BooleanField(default=True, db_index=True)
    is_auto_blocked = models.BooleanField(
        default=False,
        help_text="Automatically blocked due to suspicious activity"
    )
    block_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this IP triggered security rules"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Leave empty for permanent block"
    )
    country_code = models.CharField(max_length=2, blank=True, help_text="Detected country")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_blocked_ip"
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address', 'is_active']),
            models.Index(fields=['-created_at']),
        ]

    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    def __str__(self):
        status = ""
        if self.is_expired():
            status = " [EXPIRED]"
        elif self.is_auto_blocked:
            status = " [AUTO]"
        return f"{self.ip_address}{status}"
