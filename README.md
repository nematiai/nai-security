# NAI Security

[![PyPI version](https://img.shields.io/pypi/v/nai-security)](https://pypi.org/project/nai-security/)
[![Django Packages](https://img.shields.io/badge/Django_Packages-nai--security-8c3c26)](https://djangopackages.org/packages/p/nai-security/)

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
- **Axes Integration** - Dynamic login attempt limits, cooloff time, and per-attempt expiry via admin panel (requires django-axes >= 8.3)
- **Whitelisted Users** - Exempt specific users from security checks

## Installation

```bash
pip install nai-security
```

With all optional dependencies:

```bash
pip install nai-security[all]
```

Or install from GitHub:

```bash
pip install git+https://github.com/nematiai/nai-security.git
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
    "nai_security.middleware.SecurityMiddleware",
    ...
    "nai_security.middleware.RateLimitLoggingMiddleware",
]
```

### 3. Configure Settings

```python
GEOIP_PATH = "/path/to/GeoLite2-Country.mmdb"
```

### 4. Run Migrations

```bash
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
- `django-axes >= 8.3` — login attempt tracking and lockout; without it axes features are silently disabled
- `django-ratelimit >= 4.0` — rate limiting per endpoint
- `django-import-export >= 3.0` — admin import/export for blocked emails/domains; without it those buttons are hidden
- `django-unfold >= 0.10` — admin UI theme; without it falls back to standard Django admin
- `celery` — background tasks (auto-block processing, sync, reports); without it tasks are no-ops

## Axes Integration

Enable brute-force protection with dynamic settings controlled from the admin panel:

```python
# settings.py
INSTALLED_APPS = [
    ...
    "axes",
    "nai_security",
]

AXES_HANDLER = 'nai_security.handlers.axes_integration.DynamicAxesHandler'

AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]
```

This gives you admin-configurable control over:

| Setting | Description |
|---------|-------------|
| **Max login attempts** | Failed attempts before lockout (default: 5) |
| **Cooloff time** | Minutes before locked accounts auto-unlock (0 = permanent) |
| **Attempt expiry** | Each failed attempt expires independently — requires cooloff > 0 |

All changes take effect immediately — no server restart required.

> **Validation:** Enabling attempt expiry with cooloff set to 0 will raise a validation error in the admin panel.

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

```python
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'security-auto-blocks': {
        'task': 'security.process_auto_blocks',
        'schedule': crontab(minute='*/5'),
    },
    'security-cleanup-expired': {
        'task': 'security.cleanup_expired_blocks',
        'schedule': crontab(minute=0, hour='*'),
    },
    'security-sync-lists': {
        'task': 'security.sync_security_lists',
        'schedule': crontab(minute=0, hour=0, day_of_week=0),
    },
    'security-daily-report': {
        'task': 'security.generate_security_report',
        'schedule': crontab(minute=0, hour=6),
    },
}
```

## Models

| Model | Description |
|-------|-------------|
| `BlockedIP` | Blocked IP addresses |
| `BlockedCountry` | Blocked countries |
| `AllowedCountry` | Allowed countries (whitelist mode) |
| `BlockedEmail` | Blocked email addresses |
| `BlockedDomain` | Blocked email domains |
| `BlockedUserAgent` | Blocked user agents |
| `WhitelistedIP` | IPs that bypass all checks |
| `WhitelistedUser` | Users exempted from security checks |
| `RateLimitRule` | Custom rate limit rules |
| `LoginHistory` | User login tracking |
| `SecurityLog` | Security event logs |
| `SecuritySettings` | Global settings (singleton) |

## Testing

```bash
python -m pytest
```

## License

MIT License

## Author

Ali Nemati - [NEMATI AI](https://nemati.ai)
