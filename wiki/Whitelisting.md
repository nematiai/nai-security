# Whitelisting

Two whitelist layers:

1. **WhitelistedIP** — IP bypass
2. **WhitelistedUser** — user bypass

## WhitelistedIP

- Bypasses security middleware checks for that IP
- Bypasses django-axes lockout (via DynamicAxesHandler)
- Supports `is_active` toggle

Use for office IPs, monitoring probes, CI, etc.

## WhitelistedUser

Created in admin against a Django user.

| `exemption_type` | Middleware effect |
|------------------|-------------------|
| `all` | Skip IP + country + user-agent checks |
| `ip_block` | Skip IP blocking only |
| `geo_block` | Skip country blocking only |
| `rate_limit` | Skip rate-limit event logging only |

Also supports:

- `is_active`
- `expires_at` (optional expiration)

### Axes note

Any **active** `WhitelistedUser` row bypasses axes lockout, regardless of `exemption_type`.

## Recommended patterns

- Break-glass admin account → `WhitelistedUser(exemption_type="all")`
- Corporate egress IP → `WhitelistedIP`
- Travelling staff needing geo exceptions → `geo_block` or `all` with expiry

## Programmatic example

```python
from django.contrib.auth import get_user_model
from nai_security.models import WhitelistedUser, WhitelistedIP

user = get_user_model().objects.get(username="admin")
WhitelistedUser.objects.update_or_create(
    user=user,
    defaults={"exemption_type": "all", "is_active": True},
)

WhitelistedIP.objects.update_or_create(
    ip_address="203.0.113.10",
    defaults={"is_active": True, "reason": "Office network"},
)
```
