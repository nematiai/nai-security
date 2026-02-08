# Axes Integration

The `max_login_attempts` field in SecuritySettings dynamically controls Axes login lockout.

## Setup in Your Django Project

Add to your `settings.py`:

```python
# Use dynamic Axes handler
AXES_HANDLER = 'nai_security.handlers.DynamicAxesHandler'

# Optional: Set a fallback default (used if SecuritySettings fails)
AXES_FAILURE_LIMIT = 5
```

## How It Works

1. Admin changes `max_login_attempts` in SecuritySettings
2. Next login attempt reads the current value from database
3. Axes uses that value to determine lockout threshold
4. No server restart needed - changes apply immediately

## Testing

```python
from nai_security.models import SecuritySettings

# Change limit
settings = SecuritySettings.get_settings()
settings.max_login_attempts = 3
settings.save()

# Try logging in with wrong password 3 times - should lock
```