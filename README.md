# NAI Security

[![PyPI version](https://img.shields.io/pypi/v/nai-security)](https://pypi.org/project/nai-security/)
[![Django Packages](https://img.shields.io/badge/Django_Packages-nai--security-8c3c26)](https://djangopackages.org/packages/p/nai-security/)

Django security package for IP blocking, country blocking, email blocking, rate limiting, and login tracking.

**User guide (Wiki):** https://github.com/nematiai/nai-security/wiki  
**Wiki source in repo:** [`wiki/`](./wiki/)

## Features

- **IP Blocking** - Block specific IPs manually or automatically
- **Country Blocking** - Block/allow countries using GeoIP
- **Email Blocking** - Helpers + admin lists for signup/login in your app (not request middleware)
- **Domain Blocking** - Helpers + admin lists for disposable/spam domains
- **User Agent Blocking** - Block bots, scrapers, attack tools
- **Rate Limiting** - Logs django-ratelimit hits; `RateLimitRule` is storage only (not an engine)
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

> **Important:** `nai_security.middleware.SecurityMiddleware` **must** be placed **after** `django.contrib.auth.middleware.AuthenticationMiddleware`. The package validates this at startup and raises `ImproperlyConfigured` if misordered.

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # must be before
    "django.contrib.messages.middleware.MessageMiddleware",
    "nai_security.middleware.SecurityMiddleware",               # after auth
    "nai_security.middleware.RateLimitLoggingMiddleware",       # optional
]
```

### 3. Configure Settings

```python
GEOIP_PATH = "/path/to/GeoLite2-Country.mmdb"

# Optional: override default exempt paths (default: /health/, /ready/, /favicon.ico)
NAI_SECURITY_EXEMPT_PATHS = ["/health/", "/health", "/ready/", "/ready", "/favicon.ico"]

# Required if you sit behind a reverse proxy. Default False: ignore X-Forwarded-For / X-Real-IP
# so clients cannot spoof their IP.
NAI_SECURITY_TRUST_PROXY_HEADERS = True
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
- geoip2 >= 5.0, < 6
- redis >= 5.0, < 9
- requests >= 2.28

**Optional:**
- `django-axes >= 8.3.1, < 9` — login attempt tracking and lockout; without it axes features are silently disabled
- `django-ratelimit >= 4.1` — rate limiting per endpoint
- `django-import-export >= 4.0, < 5` — admin import/export for blocked emails/domains; without it those buttons are hidden
- `django-unfold >= 0.90` — admin UI theme; without it falls back to standard Django admin (0.100+ needs Python >= 3.12)
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

### Whitelist bypass

`DynamicAxesHandler` short-circuits all axes checks (`is_allowed`, `is_locked`, `user_login_failed`) when the request matches **any** active whitelist:

- The client IP (`REMOTE_ADDR`, or `X-Forwarded-For` / `X-Real-IP` when `NAI_SECURITY_TRUST_PROXY_HEADERS=True`) appears in `WhitelistedIP` — bypass works even when the request has no credentials (e.g. `GET /login/`).
- The login username/email resolves to a user with an active `WhitelistedUser` row — **regardless of `exemption_type`**. The `exemption_type` field still controls middleware-level bypasses (IP, country, rate-limit); for axes lockout the rule is binary.
- Username lookup tolerates `USERNAME_FIELD='username'` deployments where the login form posts an email — falls back to `email__iexact` automatically.

When a whitelisted request fails authentication, no `AccessAttempt` row is recorded — the table stays clean for whitelisted admins.

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
| `BlockedEmail` | Blocked email addresses (helpers for signup/login in **your** app — not request middleware) |
| `BlockedDomain` | Blocked email domains (helpers for signup/login in **your** app — not request middleware) |
| `BlockedUserAgent` | Blocked user agents |
| `WhitelistedIP` | IPs that bypass all checks |
| `WhitelistedUser` | Users exempted from security checks (see exemption types below) |
| `RateLimitRule` | Storage for custom rate rules — this package does **not** enforce them (use django-ratelimit) |
| `LoginHistory` | User login tracking |
| `SecurityLog` | Security event logs |
| `SecuritySettings` | Global settings (singleton) |

## User Exemptions (WhitelistedUser)

Exempt specific users from security checks via the admin panel or ORM:

| Exemption Type | Bypasses |
|---------------|----------|
| `all` | Entire security middleware — IP, country, user-agent |
| `ip_block` | IP blocking only |
| `geo_block` | Country/geo blocking only |
| `rate_limit` | Rate limit logging only |

Exemptions support optional expiration (`expires_at`) and can be toggled via `is_active`.

> **Axes lockout note:** any active `WhitelistedUser` row exempts the user from django-axes lockout, regardless of `exemption_type`. The `exemption_type` field controls only the `SecurityMiddleware` checks (IP/country/rate-limit). See [Axes Integration → Whitelist bypass](#whitelist-bypass).

## Upgrading to 1.12.0

**Security / behavior fix (no migrations):**

- **If you run behind a reverse proxy, set** `NAI_SECURITY_TRUST_PROXY_HEADERS = True`. Forwarded headers are ignored by default so clients cannot spoof IP to bypass blocks.
- Axes cooloff and attempt-expiry now apply on the next request in every worker (not only the process that saved admin).
- Whitelisting a user with any `exemption_type` now clears an active axes lockout.
- Default bad-bot sync no longer blocks `python-requests` / `curl` / `wget` / `Go-http-client`.
- `GEOIP_PATH` accepts a directory or the `.mmdb` file. Classifiers add Django 6.1 and Python 3.14.

## Upgrading to 1.11.0

**Dependency pin updates (install-time):**

- Declared `requests>=2.28` as a required dependency (used by sync services).
- Raised/capped floors: `geoip2>=5.0,<6`, `redis>=5.0,<9`.
- Optional extras: `django-import-export>=4.0,<5`, `django-unfold>=0.90`, `django-ratelimit>=4.1`.
- `django-axes` remains `>=8.3.1,<9.0`.
- No application API changes in this release.

## Upgrading to 1.10.1

**Bug fixes (no breaking changes):**

- **Whitelisted users were still being locked out by django-axes.** Three independent paths caused this:
  1. `WhitelistedIP` was not consulted by the axes handler — whitelisted IPs could still be locked, especially with `AXES_LOCKOUT_PARAMETERS=['ip_address']`.
  2. The handler's whitelist check was hard-coded to `exemption_type='all'` — users with `'ip_block'`, `'rate_limit'`, or `'geo_block'` were still locked.
  3. User lookup used `USERNAME_FIELD` only and silently failed when the login form posts an email but `USERNAME_FIELD='username'`.
- All three are fixed in `nai_security.handlers.axes_integration.DynamicAxesHandler` via a unified `_is_request_whitelisted()` helper. Failed login attempts from whitelisted requests are no longer recorded in `AccessAttempt`.
- Verified end-to-end with 100x failed-login smoke test (`scripts/smoke_100x_lockout.py`) and 9 regression tests in `tests/test_axes_integration.py`.

## Upgrading to 1.9.1

**Breaking changes:**

- `SecurityMiddleware` now **requires** `AuthenticationMiddleware` to be placed before it in `MIDDLEWARE`. If misordered, the app raises `ImproperlyConfigured` at startup. Previously the middleware silently failed to resolve users.
- `NAI_SECURITY_USER_RESOLVER` setting has been **removed**. User resolution now uses `request.user` directly (guaranteed by middleware ordering).
- `parse_user_agent` now correctly detects Android, iOS, and Opera (previously misidentified as Linux, macOS, and Chrome respectively).

## Testing

```bash
python -m pytest
```

## License

MIT License

## Author

Ali Nemati - [NEMATI AI](https://nemati.ai)
