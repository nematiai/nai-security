# Upgrading

```bash
pip install -U "nai-security==1.17.0"
python manage.py migrate
```

## 1.17.0

**Path blocking now also matches file extensions.** Requests ending in an editor/backup leftover
(`.bak` `.old` `.orig` `.save` `.swp` `.swo` `.tmp`), data or key material (`.sql` `.log` `.pem`
`.key` `.sqlite` `.sqlite3` `.db`), or a script Django never executes (`.php` `.php5` `.phtml`
`.asp` `.aspx` `.jsp` `.cgi`) return 403 and log `PATH_BLOCK`.

Archives are blocked **only at the site root**, so `/backup.zip` is refused while
`/media/user/report.zip` is not.

**This is a behaviour change on upgrade.** If a real route ends in one of those extensions, add it to
`NAI_SECURITY_EXEMPT_PATHS` — exempt paths are checked before every blocking rule. Set
`path_blocking_enabled = False` in admin to turn the whole feature off.

Derived from the 0xInfection/TIDoS check classes: backdoor locations (47), backup locations (48),
password-file locations (49), logfile locations (53).

## 1.16.0

New **`ResponseHeaderMiddleware`** — removes headers that fingerprint the stack.

- Add it to `MIDDLEWARE` **first**, so it sees the response after every other middleware has
  finished with it. It is opt-in; installing 1.16.0 changes nothing until you add it.
- Strips by default: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`,
  `X-Runtime`, `X-Generator`, `X-Drupal-Cache`, `X-Varnish`.
- Override with `NAI_SECURITY_STRIP_HEADERS` (a list; it **replaces** the default, and `[]` disables).
- New check `nai_security.W004` warns under `check --deploy` when the middleware is absent.

**Limit worth knowing:** this only reaches headers Django owns. A `Server` header added by gunicorn
or nginx is set *after* Django returns, and must be removed at that layer
(`server_tokens off;` in nginx).

## 1.15.0

New **deploy checks**. No migration, no API change, nothing changes at request time.

Three checks register under Django's `deploy` tag and appear in `manage.py check --deploy`:

| ID | Flags |
| --- | --- |
| `nai_security.W001` | A URL pattern resolves to a path `SecurityMiddleware` blocks — the view is unreachable |
| `nai_security.W002` | The admin is mounted at a default, guessable prefix |
| `nai_security.W003` | Django serves `static/`/`media/` through the URLconf with `DEBUG=False` |

Django's own checks inspect **settings** only; these inspect the **URLconf**. They are warnings, so
`check --deploy` still exits 0 — use `--fail-level WARNING` to gate a build on them.

## 1.14.1

Fixes two startup crashes on installs without the full extra set. No API change, no migration.

- **`TypeError: duplicate base class ModelAdmin`** — with `django-import-export` absent, the admin
  fell back to `ImportExportModelAdmin = ModelAdmin`, so two admin classes were declared with the
  same base twice. Plain `pip install nai-security` plus `django.contrib.admin` could not start.
- **`RuntimeError: Model class axes.models.AccessFailureLog doesn't declare an explicit app_label`**
  — with `django-axes` installed as a package but **not** in `INSTALLED_APPS`, importing it raises
  `RuntimeError`, which the `except ImportError` guards did not catch. Four call sites now gate on
  `django.apps.apps.is_installed('axes')` instead.

Installing an extra without adding its app to `INSTALLED_APPS` is now safe — the feature is inactive
rather than fatal.

## 1.14.0

New **Path Blocking** check in `SecurityMiddleware` (two migrations):

- Run `python manage.py migrate` — `0006` adds `SecuritySettings.path_blocking_enabled` (**default on**);
  `0007` adds `PATH_BLOCK` to the `SecurityLog.action` choices.
- Requests to any dotfile path (`/.git`, `/.env`, `/.ssh`, `/.aws`, …) and to `/server-status`,
  `/server-info`, `/phpinfo`, `/wp-config.php`, `/web.config`, `/id_rsa` now return **403** and log a
  `PATH_BLOCK` security event.
- `/.well-known/` stays reachable, so ACME / Let's Encrypt renewal is unaffected — but it is not a
  shelter: a dotfile nested under it (`/.well-known/.git/config`) is still blocked.
- Paths are normalized before matching, so `//.git/config` and `/./.git/config` are blocked too.
- Turn it off in admin → Security Settings → **Path blocking enabled**.

## 1.13.0

Install-time / support matrix (no app API or migrations):

- **Django >= 5.2** required. Django 4.2 and 5.0 are past end of support.
- **requests >= 2.32.4** required.
- New extra: `pip install nai-security[celery]` (`celery>=5.3,<6`). `[all]` is unchanged.
- Dev extra: pytest-cov, hypothesis, time-machine, responses, fakeredis, model-bakery, mypy, pip-audit.

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
