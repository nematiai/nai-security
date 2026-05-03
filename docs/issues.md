# Issues

## 2026-05-02

- [x] Whitelisted users still hit 423 lockout via DRF/JSON logins — `nai_security/handlers/axes_integration.py:104` — priority: high — fixed via `_resolve_username` using `axes.helpers.get_client_username`
- [x] `AccessAttempt` admin unregistered with no replacement — no UI to unlock locked accounts — `nai_security/admin.py:23` — priority: high — fixed via `AccessAttemptAdmin` + `unlock_selected` action calling `axes.utils.reset`
- [x] Adding user to `WhitelistedUser` does not clear active axes lockout — `nai_security/models/whitelisted_user.py:50` — priority: high — fixed via `_reset_axes_lockout` on save when `exemption_type='all'`
- [ ] `nai_security/admin.py` is 368 lines — exceeds 200-line hard limit in `workflow.md` — priority: med — pre-existing, needs split into `admin/` package
- [x] Multi-country detection broken across midnight-UTC due to TZ-aware `__date` lookup — `nai_security/signals.py:45` — priority: high — fixed by switching `timezone.now().date()` to `timezone.localdate()`
