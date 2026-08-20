# Installation

## Install from PyPI

```bash
pip install nai-security
```

With optional integrations:

```bash
pip install "nai-security[all]"
```

Individual extras:

```bash
pip install "nai-security[axes]"
pip install "nai-security[ratelimit]"
pip install "nai-security[import-export]"
pip install "nai-security[unfold]"
pip install "nai-security[celery]"
```

`[all]` is axes + ratelimit + import-export + unfold. Celery is separate.

For local tests and audit tools:

```bash
pip install -e ".[dev,all]"
```

## 1. Add the app

```python
INSTALLED_APPS = [
    # if using Unfold theme:
    # "unfold",
    # "import_export",
    # "axes",
    "nai_security",
]
```

## 2. Add middleware (order matters)

`SecurityMiddleware` **must** come **after** `AuthenticationMiddleware`. The package raises `ImproperlyConfigured` at startup if order is wrong.

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "nai_security.middleware.SecurityMiddleware",
    "nai_security.middleware.RateLimitLoggingMiddleware",  # optional
]
```

## 3. Configure GeoIP path

```python
GEOIP_PATH = "/var/lib/geoip/GeoLite2-Country.mmdb"
# or a directory containing GeoLite2-Country.mmdb
```

`GEOIP_PATH` may be the `.mmdb` file or a directory; a directory is resolved to `GeoLite2-Country.mmdb` inside it.

Download DB:

```bash
python manage.py download_geoip
```

## 4. Migrate

```bash
python manage.py migrate nai_security
# or
python manage.py migrate
```

## 5. Cache / Redis

The package uses Django’s cache framework (`django.core.cache`). For production, configure Redis (or another shared cache), for example:

```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}
```

`redis` is a declared dependency of `nai-security` because production deployments typically use it as the cache backend.

## Verify

1. Start your project
2. Open admin → Security models appear
3. Hit a blocked IP/country and confirm a `SecurityLog` row is created

Next: [[Configuration]] · [[Admin-Guide]]
