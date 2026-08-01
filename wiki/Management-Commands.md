# Management Commands

## download_geoip

Downloads / refreshes the GeoIP country database used by country blocking.

```bash
python manage.py download_geoip
```

Ensure `GEOIP_PATH` points at the resulting `.mmdb` file (or the path your command writes to).

## sync_security_lists

Syncs public disposable-email domains and/or bad-bot user agents into your DB.

```bash
# everything enabled in SecuritySettings
python manage.py sync_security_lists

# domains only
python manage.py sync_security_lists --domains-only

# bots only
python manage.py sync_security_lists --bots-only
```

Requires network access (`requests`). Controlled by SecuritySettings flags:

- `sync_disposable_domains`
- `sync_bad_bots`
