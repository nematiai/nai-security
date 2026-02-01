import logging
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

# GeoIP reader instance (lazy loaded)
_geoip_reader = None


def get_geoip_reader():
    """Get or create GeoIP2 reader instance."""
    global _geoip_reader
    
    if _geoip_reader is not None:
        return _geoip_reader
    
    try:
        import geoip2.database
        geoip_path = getattr(settings, 'GEOIP_PATH', None)
        
        if not geoip_path:
            logger.warning("GEOIP_PATH not configured in settings")
            return None
        
        _geoip_reader = geoip2.database.Reader(geoip_path)
        logger.info(f"GeoIP database loaded from {geoip_path}")
        return _geoip_reader
        
    except FileNotFoundError:
        logger.error(f"GeoIP database not found at {geoip_path}")
        return None
    except Exception as e:
        logger.error(f"Failed to load GeoIP database: {e}")
        return None


def get_country_from_ip(ip_address: str) -> str | None:
    """Get country code from IP address."""
    if not ip_address or ip_address in ('127.0.0.1', 'localhost', '::1'):
        return None
    
    cache_key = f"geoip_country:{ip_address}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached if cached != '__NONE__' else None
    
    reader = get_geoip_reader()
    if reader is None:
        return None
    
    try:
        response = reader.country(ip_address)
        country_code = response.country.iso_code
        cache.set(cache_key, country_code or '__NONE__', 3600)
        return country_code
    except Exception as e:
        logger.debug(f"Could not determine country for IP {ip_address}: {e}")
        cache.set(cache_key, '__NONE__', 3600)
        return None


def get_client_ip(request) -> str:
    """Extract real client IP from request, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('HTTP_X_REAL_IP')
        if not ip:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def parse_user_agent(user_agent: str) -> dict:
    """Parse user agent string to extract device info."""
    result = {
        'device_type': 'unknown',
        'browser': '',
        'os': '',
    }
    
    if not user_agent:
        return result
    
    ua_lower = user_agent.lower()
    
    # Device type
    if any(x in ua_lower for x in ['mobile', 'android', 'iphone', 'ipad']):
        if 'ipad' in ua_lower or 'tablet' in ua_lower:
            result['device_type'] = 'tablet'
        else:
            result['device_type'] = 'mobile'
    else:
        result['device_type'] = 'desktop'
    
    # Browser
    if 'chrome' in ua_lower and 'edg' not in ua_lower:
        result['browser'] = 'Chrome'
    elif 'firefox' in ua_lower:
        result['browser'] = 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        result['browser'] = 'Safari'
    elif 'edg' in ua_lower:
        result['browser'] = 'Edge'
    elif 'opera' in ua_lower or 'opr' in ua_lower:
        result['browser'] = 'Opera'
    
    # OS
    if 'windows' in ua_lower:
        result['os'] = 'Windows'
    elif 'mac os' in ua_lower or 'macos' in ua_lower:
        result['os'] = 'macOS'
    elif 'linux' in ua_lower:
        result['os'] = 'Linux'
    elif 'android' in ua_lower:
        result['os'] = 'Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        result['os'] = 'iOS'
    
    return result


def clear_security_cache():
    """Clear all security-related cache entries."""
    cache.delete('security_settings')
    # Note: For full cache clear, consider cache.clear() but be careful
    logger.info("Security cache cleared")
