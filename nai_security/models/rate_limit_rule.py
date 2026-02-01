from django.db import models


class RateLimitRule(models.Model):
    """Custom rate limit rules for specific paths."""
    
    RATE_CHOICES = [
        ('1/m', '1 per minute'),
        ('5/m', '5 per minute'),
        ('10/m', '10 per minute'),
        ('30/m', '30 per minute'),
        ('60/m', '60 per minute'),
        ('100/m', '100 per minute'),
        ('5/h', '5 per hour'),
        ('10/h', '10 per hour'),
        ('50/h', '50 per hour'),
        ('100/h', '100 per hour'),
        ('500/h', '500 per hour'),
        ('1000/h', '1000 per hour'),
        ('1000/d', '1000 per day'),
        ('5000/d', '5000 per day'),
    ]
    
    METHOD_CHOICES = [
        ('ALL', 'All Methods'),
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
    ]
    
    name = models.CharField(max_length=100, help_text="Rule name for identification")
    path_pattern = models.CharField(
        max_length=255,
        db_index=True,
        help_text="URL path pattern (e.g., /api/v1/auth/, /api/v1/chat/)"
    )
    rate = models.CharField(max_length=20, choices=RATE_CHOICES, default='100/m')
    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='ALL')
    is_active = models.BooleanField(default=True, db_index=True)
    block_count = models.PositiveIntegerField(default=0, help_text="Times this rule triggered")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_rate_limit_rule"
        verbose_name = "Rate Limit Rule"
        verbose_name_plural = "Rate Limit Rules"
        ordering = ['path_pattern']
        unique_together = ['path_pattern', 'method']

    def __str__(self):
        return f"{self.name}: {self.path_pattern} ({self.rate})"
