# Upgrading

```bash
pip install -U "nai-security==1.11.0"
python manage.py migrate
```

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
