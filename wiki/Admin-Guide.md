# Admin Guide

After install + migrate, these models appear in Django admin.

## SecuritySettings (start here)

Singleton row controlling global toggles and thresholds:

- IP / country / UA blocking on/off
- Path blocking on/off (dotfiles and leak paths — `/.git`, `/.env`, `/server-status`)
- Auto-block thresholds and durations
- Suspicious login alerts
- List sync options
- Axes login attempt / cooloff / attempt expiry

Open this first and enable only what you need.

## Block / allow lists

| Model | Purpose |
|-------|---------|
| `BlockedIP` | Deny specific IPs (optional expiry) |
| `WhitelistedIP` | Always allow IP (bypass middleware + axes) |
| `BlockedCountry` | Deny countries |
| `AllowedCountry` | Allow-only country list (allowlist mode) |
| `BlockedEmail` | Block exact emails |
| `BlockedDomain` | Block email domains |
| `BlockedUserAgent` | Block UA exact / contains / regex |

## Monitoring

| Model | Purpose |
|-------|---------|
| `SecurityLog` | Security events (blocks, rate limits, auto-blocks) |
| `LoginHistory` | Per-login history + suspicious flags |

These are typically read-only in admin.

## Rate limits

`RateLimitRule` stores custom rules if you use them in your project. Enforcement still depends on your rate-limit stack (e.g. django-ratelimit).

## Import / export

If `django-import-export` is installed, blocked email/domain admins expose import/export actions.

## Unfold theme

If `django-unfold` is installed and configured as your admin theme, nai-security admin classes integrate with it. Without Unfold, standard Django admin is used.

Next: [[Whitelisting]] · [[Axes-Integration]]
