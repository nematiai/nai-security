import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name='security.process_auto_blocks')
def process_auto_blocks():
    """
    Process recent security events and auto-block abusive IPs/countries.
    Run every 5-10 minutes.
    """
    from .services import AutoBlocker
    
    try:
        result = AutoBlocker.process_recent_events()
        logger.info(f"Auto-block processing: {result}")
        return result
    except Exception as e:
        logger.error(f"Auto-block processing failed: {e}")
        return {'error': str(e)}


@shared_task(name='security.cleanup_expired_blocks')
def cleanup_expired_blocks():
    """
    Clean up expired IP blocks.
    Run hourly.
    """
    from .services import AutoBlocker
    
    try:
        count = AutoBlocker.cleanup_expired_blocks()
        return {'cleaned': count}
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return {'error': str(e)}


@shared_task(name='security.sync_security_lists')
def sync_security_lists():
    """
    Sync disposable email domains and bad bot lists.
    Run weekly.
    """
    from .services.sync_services import sync_all
    
    try:
        result = sync_all()
        return result
    except Exception as e:
        logger.error(f"Security sync failed: {e}")
        return {'error': str(e)}


@shared_task(name='security.generate_security_report')
def generate_security_report():
    """
    Generate daily security report.
    Run daily.
    """
    from django.utils import timezone
    from datetime import timedelta
    from django.db.models import Count
    from .models import SecurityLog, BlockedIP, LoginHistory
    
    try:
        yesterday = timezone.now() - timedelta(days=1)
        
        # Get stats
        total_blocks = SecurityLog.objects.filter(created_at__gte=yesterday).count()
        
        blocks_by_action = dict(
            SecurityLog.objects.filter(created_at__gte=yesterday)
            .values_list('action')
            .annotate(count=Count('id'))
        )
        
        top_blocked_ips = list(
            SecurityLog.objects.filter(created_at__gte=yesterday)
            .values('ip_address')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        top_blocked_countries = list(
            SecurityLog.objects.filter(created_at__gte=yesterday)
            .exclude(country_code='')
            .values('country_code')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        new_auto_blocks = BlockedIP.objects.filter(
            is_auto_blocked=True,
            created_at__gte=yesterday
        ).count()
        
        suspicious_logins = LoginHistory.objects.filter(
            is_suspicious=True,
            created_at__gte=yesterday
        ).count()
        
        report = {
            'period': 'last_24h',
            'total_blocks': total_blocks,
            'blocks_by_action': blocks_by_action,
            'top_blocked_ips': top_blocked_ips,
            'top_blocked_countries': top_blocked_countries,
            'new_auto_blocks': new_auto_blocks,
            'suspicious_logins': suspicious_logins,
        }
        
        logger.info(f"Security report: {report}")
        
        # TODO: Send report via email/Telegram if configured
        
        return report
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {'error': str(e)}
