from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class WhitelistedUser(models.Model):
    """Users exempted from security checks"""
    
    EXEMPTION_CHOICES = [
        ('rate_limit', 'Rate Limiting Only'),
        ('ip_block', 'IP Blocking Only'),
        ('all', 'All Security Checks'),
    ]
    
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='security_whitelist',
        help_text="User to exempt from security checks"
    )
    exemption_type = models.CharField(
        max_length=20, 
        choices=EXEMPTION_CHOICES, 
        default='all',
        help_text="Type of security check to bypass"
    )
    reason = models.TextField(
        blank=True,
        help_text="Reason for whitelisting this user"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this whitelist entry is active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='whitelists_created'
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Optional expiration date for temporary exemptions"
    )
    
    class Meta:
        db_table = 'nai_security_whitelisted_user'
        verbose_name = 'Whitelisted User'
        verbose_name_plural = 'Whitelisted Users'
    
    def __str__(self):
        return f"{self.user.username} ({self.get_exemption_type_display()})"
    
    @classmethod
    def is_whitelisted(cls, user, check_type='all'):
        """Check if user is whitelisted for specific security check"""
        if not user or not user.is_authenticated:
            return False
        
        from django.utils import timezone
        now = timezone.now()
        
        try:
            whitelist = cls.objects.get(
                user=user,
                is_active=True,
                exemption_type__in=[check_type, 'all']
            )
            
            # Check expiration
            if whitelist.expires_at and whitelist.expires_at < now:
                return False
            
            return True
        except cls.DoesNotExist:
            return False