from django.db import models


class WhitelistedIP(models.Model):
    """IP addresses that bypass all security checks."""
    
    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        help_text="IP address to whitelist (IPv4 or IPv6)"
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        help_text="e.g., Office IP, VPN, Load Balancer"
    )
    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.CharField(max_length=100, blank=True, help_text="Who added this")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_whitelisted_ip"
        verbose_name = "Whitelisted IP"
        verbose_name_plural = "Whitelisted IPs"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address} - {self.description or 'No description'}"

    @classmethod
    def is_whitelisted(cls, ip_address: str) -> bool:
        """Check if IP is whitelisted."""
        return cls.objects.filter(
            ip_address=ip_address,
            is_active=True
        ).exists()
