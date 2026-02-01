from django.db import models


class SecurityLog(models.Model):
    """Log of all security events for monitoring and audit."""
    
    ACTION_CHOICES = [
        ('COUNTRY_BLOCK', 'Blocked by Country'),
        ('COUNTRY_WHITELIST_BLOCK', 'Blocked - Country Not in Whitelist'),
        ('IP_BLOCK', 'Blocked by IP'),
        ('EMAIL_BLOCK', 'Blocked by Email'),
        ('DOMAIN_BLOCK', 'Blocked by Domain'),
        ('USER_AGENT_BLOCK', 'Blocked by User Agent'),
        ('RATE_LIMIT', 'Rate Limited'),
        ('AXES_LOCK', 'Login Locked (Axes)'),
        ('SUSPICIOUS_LOGIN', 'Suspicious Login Detected'),
        ('AUTO_BLOCK_IP', 'IP Auto-Blocked'),
        ('AUTO_BLOCK_COUNTRY', 'Country Auto-Blocked'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    ip_address = models.GenericIPAddressField(db_index=True)
    country_code = models.CharField(max_length=2, blank=True, db_index=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    user_email = models.EmailField(blank=True, help_text="If login attempt, the email used")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "security_security_log"
        verbose_name = "Security Log"
        verbose_name_plural = "Security Logs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['action', '-created_at']),
            models.Index(fields=['country_code', '-created_at']),
        ]

    def __str__(self):
        return f"{self.action} - {self.ip_address} - {self.created_at}"

    @classmethod
    def log_event(cls, ip_address: str, action: str, path: str, **kwargs):
        """Helper method to create a security log entry."""
        severity_map = {
            'COUNTRY_BLOCK': 'medium',
            'IP_BLOCK': 'high',
            'EMAIL_BLOCK': 'medium',
            'DOMAIN_BLOCK': 'low',
            'USER_AGENT_BLOCK': 'low',
            'RATE_LIMIT': 'low',
            'AXES_LOCK': 'high',
            'SUSPICIOUS_LOGIN': 'high',
            'AUTO_BLOCK_IP': 'high',
            'AUTO_BLOCK_COUNTRY': 'critical',
        }
        
        return cls.objects.create(
            ip_address=ip_address,
            action=action,
            path=path[:500],
            severity=kwargs.pop('severity', severity_map.get(action, 'medium')),
            country_code=kwargs.pop('country_code', ''),
            method=kwargs.pop('method', ''),
            user_agent=kwargs.pop('user_agent', '')[:1000] if kwargs.get('user_agent') else '',
            details=kwargs.pop('details', ''),
            user_email=kwargs.pop('user_email', ''),
        )
