from django.db import models
import re


class BlockedUserAgent(models.Model):
    """
    Blocked user agents (bots, scrapers, etc.).
    Supports exact match or regex pattern.
    """
    
    BLOCK_TYPE_CHOICES = [
        ('exact', 'Exact Match'),
        ('contains', 'Contains'),
        ('regex', 'Regex Pattern'),
    ]
    
    CATEGORY_CHOICES = [
        ('bot', 'Bad Bot'),
        ('scraper', 'Scraper'),
        ('spam', 'Spam Bot'),
        ('attack', 'Attack Tool'),
        ('custom', 'Custom'),
    ]

    pattern = models.CharField(
        max_length=500,
        unique=True,
        db_index=True,
        help_text="User agent pattern to block"
    )
    block_type = models.CharField(
        max_length=20,
        choices=BLOCK_TYPE_CHOICES,
        default='contains'
    )
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='bot'
    )
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    is_auto_synced = models.BooleanField(
        default=False,
        help_text="Automatically synced from public list"
    )
    block_count = models.PositiveIntegerField(default=0, help_text="Times this pattern blocked")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_blocked_user_agent"
        verbose_name = "Blocked User Agent"
        verbose_name_plural = "Blocked User Agents"
        ordering = ['-block_count', 'pattern']

    def __str__(self):
        return f"{self.pattern[:50]} ({self.get_category_display()})"

    def matches(self, user_agent: str) -> bool:
        """Check if user agent matches this pattern."""
        if not user_agent:
            return False
        
        ua_lower = user_agent.lower()
        pattern_lower = self.pattern.lower()
        
        if self.block_type == 'exact':
            return ua_lower == pattern_lower
        elif self.block_type == 'contains':
            return pattern_lower in ua_lower
        elif self.block_type == 'regex':
            try:
                return bool(re.search(self.pattern, user_agent, re.IGNORECASE))
            except re.error:
                return False
        return False

    @classmethod
    def is_user_agent_blocked(cls, user_agent: str) -> tuple[bool, 'BlockedUserAgent | None']:
        """Check if user agent is blocked. Returns (is_blocked, matched_pattern)."""
        if not user_agent:
            return False, None
        
        patterns = cls.objects.filter(is_active=True)
        for pattern in patterns:
            if pattern.matches(user_agent):
                return True, pattern
        return False, None
