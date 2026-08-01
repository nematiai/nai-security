# Celery Tasks

Celery is optional. Without Celery, task callables are no-ops / unused.

Suggested beat schedule:

```python
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "security-auto-blocks": {
        "task": "security.process_auto_blocks",
        "schedule": crontab(minute="*/5"),
    },
    "security-cleanup-expired": {
        "task": "security.cleanup_expired_blocks",
        "schedule": crontab(minute=0, hour="*"),
    },
    "security-sync-lists": {
        "task": "security.sync_security_lists",
        "schedule": crontab(minute=0, hour=0, day_of_week=0),
    },
    "security-daily-report": {
        "task": "security.generate_security_report",
        "schedule": crontab(minute=0, hour=6),
    },
}
```

## What they do

| Task | Purpose |
|------|---------|
| `security.process_auto_blocks` | Evaluate recent events and auto-block IPs/countries |
| `security.cleanup_expired_blocks` | Deactivate expired temporary blocks |
| `security.sync_security_lists` | Refresh disposable domains / bad bots |
| `security.generate_security_report` | Produce periodic security summary |

Tune thresholds in **SecuritySettings** before enabling aggressive auto-block.
