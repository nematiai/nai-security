# Upgrading

```bash
pip install -U "nai-security==1.13.0"
python manage.py migrate
```

## 1.13.0

- No application API or dependency changes
- Docs site hides the MkDocs generator mark

## 1.12.2

- PyPI / docs / wiki link **NEMATI AI** to https://nemati.ai
- Docs JSON-LD includes Organization + WebSite for search engines

## 1.12.1

- PyPI **Documentation** URL now points at https://nematiai.github.io/nai-security/
- Wiki whitelist example uses `description` (the real `WhitelistedIP` field)

## 1.12.0

Security and honesty fixes (no model/migration break):

- **Breaking if you are behind a reverse proxy:** `X-Forwarded-For` / `X-Real-IP` are ignored unless you set `NAI_SECURITY_TRUST_PROXY_HEADERS = True`. Default is `False` so clients cannot spoof IP.
- Axes cooloff/attempt-expiry now re-read from `SecuritySettings` on each lockout check (multi-worker safe).
- Any active `WhitelistedUser` clears axes lockout on save (not only `exemption_type='all'`).
- `AccessLog` / `AccessFailureLog` stay in admin (only `AccessAttempt` is customized).
- Default bot sync no longer includes `python-requests`, `curl/`, `wget/`, `Go-http-client`.
- `GEOIP_PATH` may be a directory or the `.mmdb` file.
- Classifiers: Django 6.1, Python 3.14.
- Docs: email/domain blocking are helpers; `RateLimitRule` is storage only.

## 1.11.0

Dependency pin updates (no app API break):

- Required: `requests>=2.28`, `geoip2>=5,<6`, `redis>=5,<9`
- Optional: import-export 4.x, unfold >= 0.90, ratelimit >= 4.1
- Axes remains `>=8.3.1,<9`

## 1.10.1

Axes whitelist bypass fixes:

- Whitelisted IPs respected by axes handler
- Any active `WhitelistedUser` bypasses axes (not only `exemption_type='all'`)
- Email login forms work when `USERNAME_FIELD='username'`
- Whitelisted failed logins no longer pollute `AccessAttempt`

## 1.9.1 (breaking)

- `SecurityMiddleware` must be after `AuthenticationMiddleware`
- `NAI_SECURITY_USER_RESOLVER` removed
- User-agent OS/browser detection fixes (Android/iOS/Opera)

## After every upgrade

1. `pip install -U nai-security[...]`
2. `python manage.py migrate`
3. Restart web workers
4. Smoke-test login + one blocked IP/country path
