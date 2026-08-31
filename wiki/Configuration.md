# Configuration

## Django settings

| Setting | Required | Description |
|---------|----------|-------------|
| `GEOIP_PATH` | Recommended | Path to the GeoLite2/GeoIP2 Country `.mmdb` **file**, or a **directory** containing `GeoLite2-Country.mmdb` |
| `NAI_SECURITY_EXEMPT_PATHS` | Optional | Paths that skip security middleware checks |
| `NAI_SECURITY_TRUST_PROXY_HEADERS` | Optional | If `True`, trust `X-Forwarded-For` / `X-Real-IP`. Default `False` (clients cannot spoof IP) |

### Exempt paths

Default exempt paths:

- `/health/`
- `/ready/`
- `/favicon.ico`

Override:

```python
NAI_SECURITY_EXEMPT_PATHS = [
    "/health/",
    "/health",
    "/ready/",
    "/ready",
    "/favicon.ico",
    "/metrics/",
]
```

## Runtime settings (admin / DB)

Most knobs live in the singleton model **SecuritySettings** (Django admin), not in `settings.py`:

- Enable/disable IP, country, user-agent and path blocking
- Auto-block thresholds / durations
- Login anomaly flags
- Sync toggles for disposable domains / bad bots
- Axes: max attempts, cooloff minutes, attempt expiry

Changes apply without restart (cached values are invalidated on save).

## Path blocking

`path_blocking_enabled` (**on by default**) returns 403 and logs a `PATH_BLOCK` event for any request to
a dotfile path (`/.git`, `/.env`, `/.ssh`, `/.aws`, …) or to `/server-status`, `/server-info`,
`/phpinfo`, `/wp-config.php`, `/web.config`, `/id_rsa`.

Paths are normalized before matching, so `//.git/config` and `/./.git/config` are caught too.
`/.well-known/` stays reachable so ACME / Let's Encrypt renewal is unaffected — but it is not a
shelter: `/.well-known/.git/config` is still blocked.

## Country modes

- **Blocklist mode:** use `BlockedCountry`
- **Allowlist mode:** use `AllowedCountry` (only listed countries pass)

Configure which mode is active in SecuritySettings.

## Optional package settings

### django-axes

See [[Axes-Integration]].

### django-ratelimit

Use django-ratelimit decorators/middleware as usual.  
`RateLimitLoggingMiddleware` only **logs** when `request.limited` is true; it does not enforce limits by itself.

## Localhost behavior

Localhost IPs (`127.0.0.1`, `::1`) bypass blocking checks so local development keeps working.
