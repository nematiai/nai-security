# NAI Security Wiki

Django security package for IP / country / email / domain / user-agent blocking, rate-limit logging, login tracking, and django-axes lockout control.

**Docs:** https://nematiai.github.io/nai-security/  
**PyPI:** https://pypi.org/project/nai-security/  
**Current release:** `1.18.0`  
**Repo:** https://github.com/nematiai/nai-security  
**NEMATI AI:** https://nemati.ai

## Quick links

| Page | What you learn |
|------|----------------|
| [[Installation]] | Install, apps, middleware, migrate, GeoIP |
| [[Configuration]] | Settings, cache/redis, exempt paths |
| [[Admin-Guide]] | What to manage in Django admin |
| [[Axes-Integration]] | Brute-force lockout via admin |
| [[Whitelisting]] | IP + user exemptions |
| [[Management-Commands]] | CLI sync / GeoIP commands |
| [[Celery-Tasks]] | Optional background jobs |
| [[Upgrading]] | Version notes |

## 5-minute setup

```bash
pip install "nai-security[all]"
```

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "nai_security",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # required before
    "django.contrib.messages.middleware.MessageMiddleware",
    "nai_security.middleware.SecurityMiddleware",               # after auth
    "nai_security.middleware.RateLimitLoggingMiddleware",       # optional
]

GEOIP_PATH = "/path/to/GeoLite2-Country.mmdb"
```

```bash
python manage.py migrate
python manage.py download_geoip
```

Then open Django admin → **Security Settings** and enable the checks you need.

## What this package does

- Blocks requests by IP, country, user-agent
- Blocks emails/domains (signup / validation helpers + admin lists)
- Logs rate-limit hits (works with django-ratelimit)
- Tracks login history + suspicious login signals
- Auto-blocks noisy IPs/countries from security events
- Blocks scanner probes for dotfiles and leak paths (`/.git`, `/.env`, `/server-status`)
- Optional django-axes handler with admin-controlled limits

## Support matrix (1.18.0)

**Required:** Django >= 5.2, geoip2 >= 5,<6, redis >= 5,<9, requests >= 2.32.4  

**Optional extras:** `axes`, `ratelimit`, `import-export`, `unfold`, `celery` — see [[Installation]].  
**Dev extra:** pytest-cov, hypothesis, time-machine, responses, fakeredis, model-bakery, mypy, pip-audit.
