# Changelog

## 2026-08-20

| Time | Action | Files | Details | Skill |
|------|--------|-------|---------|-------|
| 01:54 | modified | pyproject.toml, nai_security/__init__.py | 1.13.0: Django >=5.2, requests >=2.32.4, celery extra, expanded dev extra (pytest-cov, hypothesis, time-machine, responses, fakeredis, model-bakery, mypy, pip-audit), ruff S + coverage/mypy tool config | manual |
| 01:54 | modified | tests/test_dependencies.py | Contract tests for Django 5.2 floor, requests 2.32.4, celery extra, new dev tools, dropped 4.2/5.0 classifiers | manual |
| 01:54 | modified | README.md, wiki/Home.md, wiki/Installation.md, wiki/Upgrading.md, wiki/Celery-Tasks.md, tools/prepare_docs.py, mkdocs.yml, overrides/main.html | Docs for 1.13.0 support matrix, extras, testing/audit commands; MkDocs extra.version + JSON-LD softwareVersion | manual |
| 01:59 | modified | mkdocs.yml, overrides/main.html, tools/prepare_docs.py, docs/assets/, .github/workflows/docs.yml | NEMATI AI logo + favicon on MkDocs (from nemati.ai); logo links to https://nemati.ai | manual |
| 21:28 | modified | mkdocs.yml | Hide Material for MkDocs generator mark (`extra.generator: false`) | manual |

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
