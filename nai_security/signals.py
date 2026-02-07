import logging
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta

from .utils import get_client_ip, get_country_from_ip, parse_user_agent
from .models import LoginHistory, SecurityLog, SecuritySettings

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def log_successful_login(sender, request, user, **kwargs):
    """Log successful login and detect anomalies."""
    try:
        settings = SecuritySettings.get_settings()
        
        if not settings.login_history_enabled:
            return
        
        ip_address = get_client_ip(request)
        country_code = get_country_from_ip(ip_address) or ''
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ua_info = parse_user_agent(user_agent)
        
        # Check for suspicious activity
        is_suspicious = False
        suspicious_reasons = []
        
        # Check if new country
        if settings.alert_on_new_country and country_code:
            if LoginHistory.is_new_country(user, country_code):
                is_suspicious = True
                suspicious_reasons.append(f"New country: {country_code}")
        
        # Check if new IP
        if settings.alert_on_new_ip:
            if LoginHistory.is_new_ip(user, ip_address):
                is_suspicious = True
                suspicious_reasons.append(f"New IP: {ip_address}")
        
        # Check for too many countries in a day
        if settings.max_countries_per_day > 0:
            today = timezone.now().date()
            today_countries = LoginHistory.objects.filter(
                user=user,
                created_at__date=today
            ).values_list('country_code', flat=True).distinct()
            
            if len(set(today_countries)) >= settings.max_countries_per_day:
                is_suspicious = True
                suspicious_reasons.append(f"Multiple countries today: {len(set(today_countries))}")
        
        # Create login history record
        login_record = LoginHistory.objects.create(
            user=user,
            ip_address=ip_address,
            country_code=country_code,
            user_agent=user_agent,
            device_type=ua_info.get('device_type', ''),
            browser=ua_info.get('browser', ''),
            os=ua_info.get('os', ''),
            is_suspicious=is_suspicious,
            suspicious_reason='; '.join(suspicious_reasons) if suspicious_reasons else '',
            session_key=request.session.session_key or '',
        )
        
        # Log suspicious activity
        if is_suspicious:
            SecurityLog.log_event(
                ip_address=ip_address,
                action='SUSPICIOUS_LOGIN',
                path=request.path,
                method='POST',
                country_code=country_code,
                user_agent=user_agent,
                user_email=user.email if hasattr(user, 'email') else '',
                details='; '.join(suspicious_reasons),
            )
            logger.warning(f"Suspicious login: {user} from {ip_address} ({country_code}) - {suspicious_reasons}")
        
    except Exception as e:
        logger.error(f"Error logging login: {e}")


# Django-axes signal integration
try:
    from axes.signals import user_locked_out
    
    @receiver(user_locked_out)
    def handle_user_locked_out(sender, request, username, ip_address, **kwargs):
        """Log when django-axes locks out a user."""
        from .utils import get_client_ip
        
        ip = ip_address or get_client_ip(request) if request else 'unknown'
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
        country_code = getattr(request, 'country_code', '') if request else ''
        
        SecurityLog.log_event(
            ip_address=ip,
            action='AXES_LOCK',
            path=request.path if request else '/login/',
            method='POST',
            country_code=country_code,
            user_agent=user_agent,
            user_email=username or '',
            details=f'User locked out after failed attempts',
        )
        logger.warning(f"AXES_LOCK: {ip} - Username: {username}")

except ImportError:
    logger.debug("django-axes not installed, skipping signal registration")


# Progressive Lockout Signals
try:
    from axes.signals import user_locked_out
    from django.contrib.auth.signals import user_login_failed, user_logged_in
    from .handlers.progressive_lockout import ProgressiveLockoutHandler

    @receiver(user_login_failed)
    def handle_login_failed(sender, credentials, request, **kwargs):
        """Handle failed login attempts with progressive lockout."""
        if request:
            ProgressiveLockoutHandler.user_login_failed(
                sender=sender,
                credentials=credentials,
                request=request,
                **kwargs
            )

    @receiver(user_logged_in)
    def handle_login_success(sender, request, user, **kwargs):
        """Reset lockout on successful login."""
        if request:
            ProgressiveLockoutHandler.reset_attempts(request)

except ImportError:
    logger.debug("django-axes not installed, progressive lockout signals not registered")
