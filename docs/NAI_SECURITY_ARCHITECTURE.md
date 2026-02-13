# nai-security — Architecture Overview

## Package Identity
- **App name:** `nai_security`
- **AppConfig:** `NaiSecurityConfig` (verbose: "NAI Security")
- **Total source:** 919 lines across 29 Python files

---

## Directory Structure

```
nai_security/
├── __init__.py                     # default_app_config
├── apps.py                         # NaiSecurityConfig
├── admin.py                        # placeholder
├── admin/
│   └── __init__.py                 # empty
├── middleware.py                    # SecurityMiddleware, RateLimitLoggingMiddleware (135 lines)
├── utils.py                        # get_client_ip, get_country_from_ip, parse_user_agent (98 lines)
├── signals.py                      # placeholder
│
├── models/
│   ├── __init__.py                 # exports all 12 models
│   ├── blocked_ip.py               # BlockedIP (37 lines)
│   ├── blocked_country.py          # BlockedCountry (34 lines)
│   ├── blocked_email.py            # BlockedEmail (35 lines)
│   ├── blocked_domain.py           # BlockedDomain (43 lines)
│   ├── blocked_user_agent.py       # BlockedUserAgent (63 lines)
│   ├── whitelisted_ip.py           # WhitelistedIP (23 lines)
│   ├── whitelisted_user.py         # WhitelistedUser (44 lines)
│   ├── allowed_country.py          # AllowedCountry (38 lines)
│   ├── security_settings.py        # SecuritySettings — singleton (59 lines)
│   ├── security_log.py             # SecurityLog (66 lines)
│   ├── login_history.py            # LoginHistory (55 lines)
│   ├── rate_limit_rule.py          # RateLimitRule (19 lines)
│   └── axes_proxy.py               # AxesProxy — unmanaged proxy (8 lines)
│
├── services/
│   ├── __init__.py                 # exports AutoBlocker
│   ├── auto_blocker.py             # AutoBlocker (101 lines)
│   └── sync_services.py            # placeholder (2 lines)
│
├── handlers/
│   ├── __init__.py                 # exports DynamicAxesHandler
│   └── axes_integration.py         # DynamicAxesHandler (25 lines)
│
├── management/
│   └── commands/                   # empty — no management commands yet
│
└── migrations/
    └── __init__.py                 # no migrations generated yet
```

---

## Layer Breakdown

### 1. Models (12 active + 1 proxy)

| Model | db_table | Key Purpose |
|---|---|---|
| `BlockedIP` | `security_blocked_ip` | IP blacklist with auto-block, expiry, block_count |
| `BlockedCountry` | `security_blocked_country` | Country blacklist with auto-name from ISO code |
| `BlockedEmail` | `security_blocked_email` | Email blacklist, normalizes to lowercase |
| `BlockedDomain` | `security_blocked_domain` | Domain blacklist (disposable/spam/competitor/custom) |
| `BlockedUserAgent` | `security_blocked_user_agent` | UA blocking via exact/contains/regex matching |
| `WhitelistedIP` | `security_whitelisted_ip` | IP whitelist bypass |
| `WhitelistedUser` | `nai_security_whitelisted_user` | Per-user exemptions (rate_limit/ip_block/all) with expiry |
| `AllowedCountry` | `security_allowed_country` | Country whitelist mode (if any active → only listed countries allowed) |
| `SecuritySettings` | `security_settings` | Singleton (pk=1) config: thresholds, toggles, feature flags |
| `SecurityLog` | `security_security_log` | Audit log for all security events (11 action types) |
| `LoginHistory` | `security_login_history` | Per-user login tracking (country/IP/device/browser) |
| `RateLimitRule` | `security_rate_limit_rule` | Path-based rate limit config (stub) |
| `AxesProxy` | *(unmanaged)* | Proxy for django-axes integration |

**⚠️ Inconsistency:** `WhitelistedUser` uses `nai_security_` prefix while all others use `security_` prefix.

### 2. Middleware (135 lines)

**`SecurityMiddleware`** — Main request filter pipeline:
```
Request → Exempt path? → Localhost? → Whitelisted IP? → Blocked IP? → Blocked UA? → Blocked Country? → Pass
```
- Reads `SecuritySettings` (cached)
- Respects feature toggle flags (`ip_blocking_enabled`, `user_agent_blocking_enabled`, `country_blocking_enabled`)
- Supports both blacklist and whitelist country modes
- Logs blocks to `SecurityLog`

**`RateLimitLoggingMiddleware`** — Post-response logger:
- Checks `request.limited` flag (set by django-ratelimit or similar)
- Logs rate limit events to `SecurityLog`

### 3. Utils (98 lines)

| Function | Purpose |
|---|---|
| `get_client_ip(request)` | Extract IP: X-Forwarded-For → X-Real-IP → REMOTE_ADDR |
| `get_country_from_ip(ip)` | GeoIP lookup with caching, localhost bypass |
| `parse_user_agent(ua_string)` | Extract device_type/browser/os from UA string |

### 4. Services (101 lines)

**`AutoBlocker`** — Static methods for automated threat response:
- `check_and_block_ip(ip)` — Auto-block IP if events exceed threshold within window
- `check_and_flag_country(code)` — Auto-block or flag country based on attack volume
- `process_recent_events()` — Batch scan: find IPs/countries to block
- `cleanup_expired_blocks()` — Deactivate expired `BlockedIP` entries

### 5. Handlers (25 lines)

**`DynamicAxesHandler`** — django-axes integration:
- `get_failure_limit(request, credentials)` — Returns `max_login_attempts` from `SecuritySettings`
- Graceful fallback if axes not installed

---

## Data Flow

```
Incoming Request
       │
       ▼
 SecurityMiddleware
       │
       ├─ get_client_ip() ──► IP extracted
       ├─ SecuritySettings.get_settings() ──► cached singleton
       ├─ WhitelistedIP.is_whitelisted() ──► bypass check
       ├─ BlockedIP check ──► 403 + SecurityLog
       ├─ BlockedUserAgent.is_user_agent_blocked() ──► 403 + SecurityLog
       ├─ get_country_from_ip() ──► GeoIP lookup
       ├─ BlockedCountry check ──► 403 + SecurityLog
       ├─ AllowedCountry whitelist check ──► 403 + SecurityLog
       │
       ▼
   Response
       │
       ▼
 RateLimitLoggingMiddleware
       │
       ├─ request.limited? ──► SecurityLog
       ▼
   Client
```

---

## Gaps / Stubs

| Item | Status |
|---|---|
| `admin.py` / `admin/__init__.py` | Empty placeholders |
| `signals.py` | Placeholder comment only |
| `sync_services.py` | 2 lines, placeholder |
| `management/commands/` | Empty — no CLI commands |
| `migrations/` | Only `__init__.py` — no migrations generated |
| `RateLimitRule` model | 19-line stub, not wired into middleware |
| `AxesProxy` model | Unmanaged proxy, minimal |

---

## Known Bugs (from prior review)

1. **`middleware.py`** — Uses `models.F('block_count')` but imports `from django.db import models` instead of `from django.db.models import F`. Should be `F('block_count')` with proper import.
2. **`tasks.py`** (if exists outside package) — Same `F` import scope issue.
3. **`WhitelistedUser.db_table`** — Inconsistent prefix (`nai_security_` vs `security_`).
