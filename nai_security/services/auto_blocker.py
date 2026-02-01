import logging
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count

from ..models import (
    SecurityLog, SecuritySettings, BlockedIP, BlockedCountry
)

logger = logging.getLogger(__name__)


class AutoBlocker:
    """Service for automatically blocking IPs and countries based on attack patterns."""
    
    @classmethod
    def check_and_block_ip(cls, ip_address: str) -> bool:
        """
        Check if IP should be auto-blocked based on security events.
        Returns True if IP was blocked.
        """
        settings = SecuritySettings.get_settings()
        
        if not settings.auto_block_ip_threshold:
            return False
        
        # Already blocked?
        if BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
            return False
        
        # Count events in time window
        window_start = timezone.now() - timedelta(hours=settings.auto_block_ip_window_hours)
        event_count = SecurityLog.objects.filter(
            ip_address=ip_address,
            created_at__gte=window_start
        ).count()
        
        if event_count >= settings.auto_block_ip_threshold:
            # Auto-block this IP
            expires_at = None
            if settings.auto_block_ip_duration_hours > 0:
                expires_at = timezone.now() + timedelta(hours=settings.auto_block_ip_duration_hours)
            
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=f"Auto-blocked: {event_count} security events in {settings.auto_block_ip_window_hours}h",
                is_active=True,
                is_auto_blocked=True,
                block_count=event_count,
                expires_at=expires_at,
            )
            
            SecurityLog.log_event(
                ip_address=ip_address,
                action='AUTO_BLOCK_IP',
                path='system',
                details=f"Auto-blocked after {event_count} events",
                severity='high',
            )
            
            logger.warning(f"AUTO_BLOCK_IP: {ip_address} after {event_count} events")
            return True
        
        return False
    
    @classmethod
    def check_and_flag_country(cls, country_code: str) -> bool:
        """
        Check if country should be flagged for review based on attack volume.
        Returns True if country was flagged/blocked.
        """
        settings = SecuritySettings.get_settings()
        
        if not settings.auto_block_country_threshold or not country_code:
            return False
        
        # Already blocked?
        if BlockedCountry.objects.filter(code=country_code, is_active=True).exists():
            return False
        
        # Count events in time window
        window_start = timezone.now() - timedelta(hours=settings.auto_block_country_window_hours)
        event_count = SecurityLog.objects.filter(
            country_code=country_code,
            created_at__gte=window_start
        ).count()
        
        if event_count >= settings.auto_block_country_threshold:
            if settings.auto_block_country_enabled:
                # Auto-block country
                BlockedCountry.objects.create(
                    code=country_code,
                    reason=f"Auto-blocked: {event_count} attacks in {settings.auto_block_country_window_hours}h",
                    is_active=True,
                    is_auto_blocked=True,
                    attack_count=event_count,
                )
                
                SecurityLog.log_event(
                    ip_address='0.0.0.0',
                    action='AUTO_BLOCK_COUNTRY',
                    path='system',
                    country_code=country_code,
                    details=f"Auto-blocked after {event_count} attacks",
                    severity='critical',
                )
                
                logger.warning(f"AUTO_BLOCK_COUNTRY: {country_code} after {event_count} attacks")
            else:
                # Just update attack count for review
                country, created = BlockedCountry.objects.get_or_create(
                    code=country_code,
                    defaults={'is_active': False, 'attack_count': event_count}
                )
                if not created:
                    country.attack_count = event_count
                    country.save(update_fields=['attack_count', 'updated_at'])
                
                logger.info(f"Country {country_code} flagged for review: {event_count} attacks")
            
            return True
        
        return False
    
    @classmethod
    def process_recent_events(cls) -> dict:
        """
        Process recent security events and auto-block as needed.
        Called by Celery task.
        Returns summary of actions taken.
        """
        settings = SecuritySettings.get_settings()
        window_start = timezone.now() - timedelta(hours=max(
            settings.auto_block_ip_window_hours,
            settings.auto_block_country_window_hours
        ))
        
        # Get IPs with high event counts
        ip_counts = SecurityLog.objects.filter(
            created_at__gte=window_start
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gte=settings.auto_block_ip_threshold)
        
        blocked_ips = 0
        for item in ip_counts:
            if cls.check_and_block_ip(item['ip_address']):
                blocked_ips += 1
        
        # Get countries with high event counts
        country_counts = SecurityLog.objects.filter(
            created_at__gte=window_start
        ).exclude(country_code='').values('country_code').annotate(
            count=Count('id')
        ).filter(count__gte=settings.auto_block_country_threshold)
        
        flagged_countries = 0
        for item in country_counts:
            if cls.check_and_flag_country(item['country_code']):
                flagged_countries += 1
        
        return {
            'blocked_ips': blocked_ips,
            'flagged_countries': flagged_countries,
        }
    
    @classmethod
    def cleanup_expired_blocks(cls) -> int:
        """Remove expired IP blocks. Returns count of removed blocks."""
        expired = BlockedIP.objects.filter(
            expires_at__lt=timezone.now(),
            is_active=True
        )
        count = expired.count()
        expired.update(is_active=False)
        
        if count > 0:
            logger.info(f"Cleaned up {count} expired IP blocks")
        
        return count
