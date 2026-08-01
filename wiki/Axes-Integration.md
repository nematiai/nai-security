# Axes Integration

Use django-axes for brute-force protection, with limits controlled from **SecuritySettings** (no restart).

Requires: `pip install "nai-security[axes]"` (django-axes >= 8.3.1, < 9).

## settings.py

```python
INSTALLED_APPS = [
    # ...
    "axes",
    "nai_security",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

AXES_HANDLER = "nai_security.handlers.axes_integration.DynamicAxesHandler"
AXES_FAILURE_LIMIT = 5  # fallback if DB settings cannot be read
AXES_COOLOFF_TIME = None  # overridden dynamically from SecuritySettings
```

Also include Axes middleware per django-axes docs for your Django version.

## Admin-controlled fields

In **SecuritySettings**:

| Field | Meaning |
|-------|---------|
| Max login attempts | Failures before lockout |
| Cooloff minutes | Auto-unlock delay (`0` = until manual reset) |
| Attempt expiry enabled | Each failure expires independently (requires cooloff > 0) |

Validation: attempt expiry cannot be enabled when cooloff is `0`.

## Whitelist bypass (important)

`DynamicAxesHandler` skips axes lockout when:

1. Client IP is in `WhitelistedIP`, or
2. Login user matches an active `WhitelistedUser` (**any** `exemption_type`)

Notes:

- IP whitelist works even on credential-less requests (e.g. GET login page)
- Username lookup falls back to email when login form posts email but `USERNAME_FIELD` is `username`
- Failed logins for whitelisted requests are **not** written to `AccessAttempt`

`exemption_type` still controls middleware bypasses only. For axes, whitelist presence is binary.

## Manual unlock

Use Axes admin / nai-security admin actions (where available) to clear lockouts for a user/IP.
