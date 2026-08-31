# Changelog

## 2026-08-31

| Time | Action | Files | Details | Skill |
|------|--------|-------|---------|-------|
| 03:10 | modified | nai_security/admin.py | 1.14.1: `IMPORT_EXPORT_BASES` tuple — without `django-import-export` the fallback declared `ModelAdmin` twice, raising `TypeError: duplicate base class` on a bare install | manual |
| 03:10 | modified | nai_security/admin.py, apps.py, signals.py, handlers/__init__.py | Gate axes on `apps.is_installed('axes')` — axes installed but absent from `INSTALLED_APPS` raises `RuntimeError`, which `except ImportError` never caught | manual |
| 03:10 | modified | tests/test_admin.py | `BareInstallTest` — imports the admin in a subprocess with `import_export`/`unfold` blocked; the suite installs `[all,dev]` so this branch was never exercised | manual |
| 03:10 | modified | README.md, wiki/Installation.md | An extra installed without its app in `INSTALLED_APPS` is safe; the reverse is fatal | manual |

## 2026-08-30

| Time | Action | Files | Details | Skill |
|------|--------|-------|---------|-------|
| 16:26 | created | nai_security/paths.py, nai_security/migrations/0006_securitysettings_path_blocking_enabled.py | Nikto dangerous-path catalog: `is_dangerous_path()` + `SecuritySettings.path_blocking_enabled` (default on) | /audit recheck |
| 16:26 | modified | nai_security/middleware/security.py, nai_security/models/security_log.py, nai_security/models/security_settings.py, nai_security/admin.py | `PATH_BLOCK` 403 + log after the UA check; admin toggle; action colour + `medium` severity | /audit recheck |
| 17:10 | modified | nai_security/paths.py | Normalize (`posixpath.normpath` + collapse `//`) before matching — closes the `//.git/config` and `/./.git/config` bypass; replaced the enumerated dotfile list with a dot-segment rule, `/.well-known/` allow-listed | /audit reapply |
| 17:10 | modified | pyproject.toml, nai_security/__init__.py, mkdocs.yml, README.md, wiki/Home.md, wiki/Upgrading.md, tools/prepare_docs.py, tests/test_dependencies.py | 1.14.0 release: Path Blocking feature + upgrade notes | /audit reapply |
| 17:10 | modified | .gitignore | Ignore `design/` (was only `design/audit/` + `design/plan/`) | /audit reapply |
| 17:15 | created | nai_security/migrations/0007_alter_securitylog_action.py | `AlterField` on `SecurityLog.action` — adding the `PATH_BLOCK` choice alters migration state, so `0006` alone left `makemigrations --check` dirty | /audit reapply |
| 18:40 | created | tests/test_tasks.py, tests/test_sync_services.py, tests/conftest.py | Celery task + sync-service coverage (78.15% -> 85.05%); `mock`/`real` markers registered and auto-applied | /test-suite |
| 18:40 | modified | pyproject.toml, tox.ini | Dev extra adds `pytest-randomly` (S1 isolation), `pytest-xdist` (S6 parallel-safety check), `mutmut` (mutation gate) — all three are manual hygiene gates, no lane runs them yet; coverage gate moved to the tox command so targeted `pytest <file>` runs are not failed by a partial-coverage threshold | /test-suite |
| 19:20 | modified | nai_security/paths.py | `/.well-known/` allow-list no longer shelters a nested dotfile (`/.well-known/.git/config` now blocked) | /audit reapply |
| 19:20 | modified | tests/test_utils.py | Regression guards for the repeated-slash collapse on non-dot prefixes (`//server-status`) and for the `.well-known` subtree | /audit reapply |

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
