"""
Configuration settings for nai_security package.
"""
from django.conf import settings


class SecuritySettings:
    """Central configuration for nai_security package."""
    
    # Progressive Lockout Configuration
    LOCKOUT_TIERS = getattr(settings, 'NAI_SECURITY_LOCKOUT_TIERS', [
        (3, 0),          # 1-3 attempts: no lockout
        (6, 5),          # 4-6 attempts: 5 minutes
        (9, 10),         # 7-9 attempts: 10 minutes
        (12, 15),        # 10-12 attempts: 15 minutes
        (float('inf'), 60),  # 13+ attempts: 1 hour
    ])
    
    # Cache timeout for attempt tracking (24 hours)
    ATTEMPT_CACHE_TIMEOUT = getattr(
        settings, 
        'NAI_SECURITY_ATTEMPT_CACHE_TIMEOUT',
        86400
    )
    
    # Enable/disable progressive lockout
    PROGRESSIVE_LOCKOUT_ENABLED = getattr(
        settings,
        'NAI_SECURITY_PROGRESSIVE_LOCKOUT_ENABLED',
        True
    )
    
    # Middleware settings
    SECURITY_MIDDLEWARE_ENABLED = getattr(
        settings,
        'SECURITY_MIDDLEWARE_ENABLED',
        True
    )
    
    RATELIMIT_MIDDLEWARE_ENABLED = getattr(
        settings,
        'RATELIMIT_MIDDLEWARE_ENABLED',
        True
    )
    
    # GeoIP settings
    GEOIP_PATH = getattr(
        settings,
        'GEOIP_PATH',
        './geoip/GeoLite2-Country.mmdb'
    )


# Export singleton instance
security_settings = SecuritySettings()