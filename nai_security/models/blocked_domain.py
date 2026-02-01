from django.db import models


class BlockedDomain(models.Model):
    """
    Blocked email domains (e.g., disposable email services).
    Blocks all emails from these domains during registration.
    """
    
    DOMAIN_TYPE_CHOICES = [
        ('disposable', 'Disposable Email'),
        ('spam', 'Known Spam Domain'),
        ('competitor', 'Competitor Domain'),
        ('custom', 'Custom Block'),
    ]

    domain = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Domain to block (e.g., tempmail.com)"
    )
    domain_type = models.CharField(
        max_length=20,
        choices=DOMAIN_TYPE_CHOICES,
        default='disposable'
    )
    reason = models.TextField(blank=True, help_text="Reason for blocking")
    is_active = models.BooleanField(default=True, db_index=True)
    is_auto_synced = models.BooleanField(
        default=False,
        help_text="Automatically synced from public list"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_blocked_domain"
        verbose_name = "Blocked Domain"
        verbose_name_plural = "Blocked Domains"
        ordering = ['domain']
        indexes = [
            models.Index(fields=['domain', 'is_active']),
        ]

    def save(self, *args, **kwargs):
        if self.domain:
            self.domain = self.domain.strip().lower()
        super().save(*args, **kwargs)

    def __str__(self):
        auto = " [SYNCED]" if self.is_auto_synced else ""
        return f"{self.domain}{auto}"

    @classmethod
    def is_domain_blocked(cls, email: str) -> bool:
        """Check if email domain is blocked."""
        if '@' not in email:
            return False
        domain = email.split('@')[1].strip().lower()
        return cls.objects.filter(
            domain__iexact=domain,
            is_active=True
        ).exists()
