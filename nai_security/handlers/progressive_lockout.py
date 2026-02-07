"""
Progressive lockout handler for Django Axes.
Implements escalating lockout durations based on failed attempt count.
"""
from datetime import timedelta
from typing import Optional, Dict, Any
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from axes.handlers.cache import AxesCacheHandler


class ProgressiveLockoutHandler(AxesCacheHandler):
    """
    Custom Axes handler with progressive lockout penalties.
    
    Lockout progression:
    - Attempts 1-3: No lockout
    - Attempts 4-6: 5 minutes
    - Attempts 7-9: 10 minutes
    - Attempts 10-12: 15 minutes
    - Attempts 13+: 1 hour
    """
    
    # Lockout thresholds and durations (in minutes)
    LOCKOUT_TIERS = [
        (3, 0),      # First 3 attempts: no lockout
        (6, 5),      # 4-6 attempts: 5 minutes
        (9, 10),     # 7-9 attempts: 10 minutes
        (12, 15),    # 10-12 attempts: 15 minutes
        (float('inf'), 60),  # 13+ attempts: 1 hour
    ]
    
    CACHE_KEY_PREFIX = 'progressive_lockout'
    ATTEMPT_CACHE_TIMEOUT = 86400  # 24 hours
    
    @classmethod
    def _get_attempt_cache_key(cls, request: HttpRequest) -> str:
        """Generate cache key for tracking attempts."""
        ip = cls._get_client_ip(request)
        username = request.POST.get('username', 'unknown')
        return f"{cls.CACHE_KEY_PREFIX}:attempts:{ip}:{username}"
    
    @classmethod
    def _get_lockout_cache_key(cls, request: HttpRequest) -> str:
        """Generate cache key for lockout timestamp."""
        ip = cls._get_client_ip(request)
        username = request.POST.get('username', 'unknown')
        return f"{cls.CACHE_KEY_PREFIX}:lockout:{ip}:{username}"
    
    @classmethod
    def _get_client_ip(cls, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    @classmethod
    def get_failure_count(cls, request: HttpRequest) -> int:
        """Get current failure attempt count."""
        cache_key = cls._get_attempt_cache_key(request)
        return cache.get(cache_key, 0)
    
    @classmethod
    def increment_failure_count(cls, request: HttpRequest) -> int:
        """Increment failure count and return new count."""
        cache_key = cls._get_attempt_cache_key(request)
        count = cache.get(cache_key, 0) + 1
        cache.set(cache_key, count, cls.ATTEMPT_CACHE_TIMEOUT)
        return count
    
    @classmethod
    def get_lockout_duration(cls, attempt_count: int) -> int:
        """
        Calculate lockout duration in minutes based on attempt count.
        
        Args:
            attempt_count: Number of failed attempts
            
        Returns:
            Lockout duration in minutes
        """
        for threshold, duration in cls.LOCKOUT_TIERS:
            if attempt_count <= threshold:
                return duration
        return cls.LOCKOUT_TIERS[-1][1]  # Default to maximum
    
    @classmethod
    def set_lockout(cls, request: HttpRequest, duration_minutes: int) -> None:
        """Set lockout timestamp in cache."""
        if duration_minutes == 0:
            return
        
        cache_key = cls._get_lockout_cache_key(request)
        lockout_until = timezone.now() + timedelta(minutes=duration_minutes)
        cache.set(
            cache_key, 
            lockout_until.isoformat(),
            timeout=duration_minutes * 60
        )
    
    @classmethod
    def get_lockout_time_remaining(cls, request: HttpRequest) -> Optional[int]:
        """
        Get remaining lockout time in seconds.
        
        Returns:
            Seconds remaining, or None if not locked out
        """
        cache_key = cls._get_lockout_cache_key(request)
        lockout_until_str = cache.get(cache_key)
        
        if not lockout_until_str:
            return None
        
        lockout_until = timezone.datetime.fromisoformat(lockout_until_str)
        now = timezone.now()
        
        if now >= lockout_until:
            # Lockout expired
            cache.delete(cache_key)
            return None
        
        return int((lockout_until - now).total_seconds())
    
    @classmethod
    def is_locked_out(cls, request: HttpRequest) -> bool:
        """Check if request is currently locked out."""
        return cls.get_lockout_time_remaining(request) is not None
    
    @classmethod
    def reset_attempts(cls, request: HttpRequest) -> None:
        """Reset attempt count and lockout for successful login."""
        attempt_key = cls._get_attempt_cache_key(request)
        lockout_key = cls._get_lockout_cache_key(request)
        cache.delete(attempt_key)
        cache.delete(lockout_key)
    
    @classmethod
    def user_login_failed(cls, sender, credentials, request=None, **kwargs):
        """
        Handle failed login attempt with progressive lockout.
        Called by Axes signal.
        """
        if request is None:
            return
        
        # Check if already locked out
        if cls.is_locked_out(request):
            return
        
        # Increment failure count
        attempt_count = cls.increment_failure_count(request)
        
        # Calculate and set lockout duration
        duration_minutes = cls.get_lockout_duration(attempt_count)
        cls.set_lockout(request, duration_minutes)
        
        # Log the event
        from nai_security.models import SecurityLog
        SecurityLog.log_event(
            ip_address=cls._get_client_ip(request),
            action='AXES_LOCK',
            path=request.path,
            method=request.method,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details=f"Failed attempt #{attempt_count}. Lockout: {duration_minutes}min",
            user_email=credentials.get('username', ''),
        )
    
    @classmethod
    def get_lockout_response_data(cls, request: HttpRequest) -> Dict[str, Any]:
        """
        Get data for lockout response.
        
        Returns:
            Dictionary with lockout information
        """
        seconds_remaining = cls.get_lockout_time_remaining(request)
        attempt_count = cls.get_failure_count(request)
        
        if seconds_remaining is None:
            return {
                'locked_out': False,
                'attempt_count': attempt_count,
            }
        
        minutes_remaining = seconds_remaining // 60
        seconds_part = seconds_remaining % 60
        
        return {
            'locked_out': True,
            'attempt_count': attempt_count,
            'seconds_remaining': seconds_remaining,
            'time_remaining_display': f"{minutes_remaining}m {seconds_part}s",
            'unlock_time': (timezone.now() + timedelta(seconds=seconds_remaining)).isoformat(),
        }