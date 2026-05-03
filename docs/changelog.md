# Changelog

## 2026-05-02

| Time | Action | Files | Details | Skill |
|------|--------|-------|---------|-------|
| 22:10 | modified | nai_security/handlers/axes_integration.py | Replaced `is_already_locked` with `is_locked` (axes 8.x rename), added `is_allowed` override, used `axes.helpers.get_client_username` so DRF/JSON logins bypass lockout when whitelisted | manual |
| 22:11 | modified | nai_security/admin.py | Re-registered `AccessAttempt` with custom `AccessAttemptAdmin` and `unlock_selected` bulk action calling `axes.utils.reset` | manual |
| 22:11 | modified | nai_security/models/whitelisted_user.py | `WhitelistedUser.save()` now calls `axes.utils.reset(username=...)` when `is_active=True` and `exemption_type='all'` to actively clear active lockout | manual |
| 22:11 | modified | tests/test_axes_integration.py | Added `WhitelistBypassTest` (4 cases) and `WhitelistAutoResetTest` (3 cases) | manual |
| 22:30 | modified | pyproject.toml | Bumped `django-axes` requirement to `>=8.3.1,<9.0` | manual |
| 22:30 | created | docs/issues.md | Tracked 3 fixed + 2 outstanding issues | manual |
| 22:30 | created | docs/changelog.md | Initial changelog | manual |
| 23:10 | modified | nai_security/signals.py | Fixed multi-country detection: `timezone.now().date()` → `timezone.localdate()` to match `__date` lookup TZ behavior | manual |
