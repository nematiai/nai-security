# NAI Security

Django security package for IP blocking, country blocking, email blocking, rate limiting, and login tracking.

## Features

- **IP Blocking** - Block specific IPs manually or automatically
- **Country Blocking** - Block/allow countries using GeoIP
- **Email Blocking** - Block disposable emails and specific addresses
- **Domain Blocking** - Block email domains (disposable, spam, etc.)
- **User Agent Blocking** - Block bots, scrapers, attack tools
- **Rate Limiting** - Custom rate limit rules per endpoint
- **Login History** - Track user logins with anomaly detection
- **Auto-Blocking** - Automatically block IPs/countries based on attack patterns
- **Security Logs** - Comprehensive logging of all security events

## Installation
```bash
pip install git+https://github.com/nematiai/nai-security.git
```

Or add to 
equirements.txt:
```
git+https://github.com/nematiai/nai-security.git@main#egg=nai-security
```

## Quick Start

### 1. Add to INSTALLED_APPS
```python
INSTALLED_APPS = [
    ...
    "nai_security",
]
```

### 2. Add Middleware
```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    ...
    "nai_security.middleware.SecurityMiddleware",  # After SecurityMiddleware
    ...
    "nai_security.middleware.RateLimitLoggingMiddleware",  # Near the end
]
```

### 3. Configure Settings
```python
# GeoIP database path
GEOIP_PATH = "/path/to/GeoLite2-Country.mmdb"

# Optional: Enable/disable middleware
SECURITY_MIDDLEWARE_ENABLED = True
RATELIMIT_MIDDLEWARE_ENABLED = True
```

### 4. Run Migrations
```bash
python manage.py makemigrations nai_security
python manage.py migrate
```

### 5. Download GeoIP Database
```bash
python manage.py download_geoip
```

## Dependencies

**Required:**
- Django >= 4.2
- geoip2 >= 4.0
- redis >= 4.0

**Optional:**
- django-axes >= 6.0 (login attempt tracking)
- django-ratelimit >= 4.0 (rate limiting)
- django-import-export >= 3.0 (admin import/export)
- django-unfold >= 0.10 (admin theme)

Install all optional dependencies:
```bash
pip install nai-security[all]
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| GEOIP_PATH | ./geoip/GeoLite2-Country.mmdb | Path to GeoIP database |
| SECURITY_MIDDLEWARE_ENABLED | True | Enable security middleware |
| RATELIMIT_MIDDLEWARE_ENABLED | True | Enable rate limit logging |

## Management Commands
```bash
# Download GeoIP database
python manage.py download_geoip

# Sync disposable email domains and bad bot lists
python manage.py sync_security_lists
python manage.py sync_security_lists --domains-only
python manage.py sync_security_lists --bots-only
```

## Celery Tasks

Add to your Celery beat schedule:
```python
CELERY_BEAT_SCHEDULE = {
    'security-auto-blocks': {
        'task': 'security.process_auto_blocks',
        'schedule': crontab(minute='*/5'),  # Every 5 minutes
    },
    'security-cleanup-expired': {
        'task': 'security.cleanup_expired_blocks',
        'schedule': crontab(minute=0, hour='*'),  # Every hour
    },
    'security-sync-lists': {
        'task': 'security.sync_security_lists',
        'schedule': crontab(minute=0, hour=0, day_of_week=0),  # Weekly
    },
    'security-daily-report': {
        'task': 'security.generate_security_report',
        'schedule': crontab(minute=0, hour=6),  # Daily at 6 AM
    },
}
```

## Models

| Model | Description |
|-------|-------------|
| BlockedIP | Blocked IP addresses |
| BlockedCountry | Blocked countries |
| AllowedCountry | Allowed countries (whitelist mode) |
| BlockedEmail | Blocked email addresses |
| BlockedDomain | Blocked email domains |
| BlockedUserAgent | Blocked user agents |
| WhitelistedIP | IPs that bypass all checks |
| RateLimitRule | Custom rate limit rules |
| LoginHistory | User login tracking |
| SecurityLog | Security event logs |
| SecuritySettings | Global settings (singleton) |

## License

MIT License

## Author

Ali Nemati - [NEMATI AI](https://nemati.ai)


## Contributing 
Contributions are welcome! Please open issues and pull requests on GitHub.