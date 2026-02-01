from django.core.validators import EmailValidator
from django.db import models


class BlockedEmail(models.Model):
    """
    Blocked email addresses.
    Prevents registration and login from specific emails.
    """

    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        db_index=True,
        help_text="Email address to block from registration and login"
    )
    reason = models.TextField(
        blank=True,
        help_text="Reason for blocking this email address"
    )
    is_active = models.BooleanField(default=True, db_index=True)
    is_auto_blocked = models.BooleanField(
        default=False,
        help_text="Automatically blocked (disposable email, etc.)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_blocked_email"
        verbose_name = "Blocked Email"
        verbose_name_plural = "Blocked Emails"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email"], name="sec_blocked_email_idx"),
        ]

    def __str__(self):
        auto = " [AUTO]" if self.is_auto_blocked else ""
        return f"{self.email}{auto}"

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    @classmethod
    def is_email_blocked(cls, email: str) -> bool:
        """Check if an email is blocked (sync version)."""
        return cls.objects.filter(
            email__iexact=email.strip().lower(),
            is_active=True
        ).exists()

    @classmethod
    async def is_email_blocked_async(cls, email: str) -> bool:
        """Check if an email is blocked (async version)."""
        from asgiref.sync import sync_to_async
        return await sync_to_async(cls.is_email_blocked)(email)
