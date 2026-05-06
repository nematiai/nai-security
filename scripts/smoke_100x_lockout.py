"""
Live 100x lockout demo for nai-security whitelist fix.

Runs three scenarios against axes' real authenticate() pipeline:
  A) No whitelist           -> expect lockout after AXES_FAILURE_LIMIT (5) failures
  B) WhitelistedUser(ip_block) -> expect NEVER locked even at 100 failures
  C) WhitelistedIP            -> expect NEVER locked even at 100 failures

Each scenario reports: # of recorded AccessAttempt rows, observable lockout point,
and whether the correct password still works after the loop.

Run from repo root:
    python scripts/smoke_100x_lockout.py
"""
import os
import sys
import django

# Ensure repo root (containing tests/ package) is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')
django.setup()

import logging
# Quiet the axes log spam so the demo output stays readable.
logging.getLogger('axes').setLevel(logging.ERROR)
logging.getLogger('axes.signals').setLevel(logging.ERROR)
logging.getLogger('nai_security').setLevel(logging.ERROR)

from django.core.management import call_command
call_command('migrate', verbosity=0, run_syncdb=True)

from django.contrib.auth import authenticate, get_user_model
from django.test import RequestFactory
from axes.models import AccessAttempt
from nai_security.models import WhitelistedUser, WhitelistedIP

User = get_user_model()
factory = RequestFactory()

CORRECT_PW = 'correct_password_123'
WRONG_PW = 'wrong_password_xyz'
EMAIL = 'x@gmail.com'
USERNAME = 'admin1'
TEST_IP = '203.0.113.10'


def _make_request():
    r = factory.post('/login/')
    r.META['REMOTE_ADDR'] = TEST_IP
    r.axes_ip_address = TEST_IP
    r.axes_user_agent = 'smoke-100x'
    return r


def _attempt(password):
    return authenticate(_make_request(), username=USERNAME, password=password)


def _full_cleanup():
    User.objects.filter(email=EMAIL).delete()
    AccessAttempt.objects.all().delete()
    WhitelistedUser.objects.all().delete()
    WhitelistedIP.objects.all().delete()


def _make_user():
    return User.objects.create_user(
        username=USERNAME, email=EMAIL, password=CORRECT_PW,
    )


def run_loop(label, n=100):
    """Hit authenticate() n times with wrong password. Detect first lockout point
    by also probing with the correct password every 10 attempts."""
    first_lock_at = None
    for i in range(1, n + 1):
        result = _attempt(WRONG_PW)
        if result is None and first_lock_at is None and i % 5 == 0:
            # Probe with the correct password — if THIS also returns None, we are locked.
            probe = _attempt(CORRECT_PW)
            if probe is None:
                first_lock_at = i
                # don't break — keep going to confirm subsequent attempts also fail
    final_correct = _attempt(CORRECT_PW)
    rows = AccessAttempt.objects.count()
    failures_total = sum(a.failures_since_start for a in AccessAttempt.objects.all())
    print(f"  AccessAttempt rows recorded:        {rows}")
    print(f"  Sum(failures_since_start):          {failures_total}")
    print(f"  First detected lockout at attempt:  "
          f"{first_lock_at if first_lock_at else 'NEVER (loop completed clean)'}")
    print(f"  Correct password works AFTER loop:  "
          f"{'YES (not locked)' if final_correct is not None else 'NO (locked out)'}")
    return first_lock_at, rows, final_correct is not None


def banner(text):
    print()
    print('=' * 70)
    print(text)
    print('=' * 70)


def main():
    # ---------------------------------------------------------------
    # Scenario A — negative control: no whitelist, must lock
    # ---------------------------------------------------------------
    banner("Scenario A — NO whitelist  (expect lockout at attempt #5)")
    _full_cleanup()
    _make_user()
    a_lock, a_rows, a_can_login = run_loop("A")
    a_pass = (a_lock is not None) and (not a_can_login)
    print(f"  RESULT: {'PASS — lockout occurred as expected' if a_pass else 'FAIL — axes did not lock; suite is broken'}")

    # ---------------------------------------------------------------
    # Scenario B — WhitelistedUser('ip_block')
    # ---------------------------------------------------------------
    banner("Scenario B — WhitelistedUser(exemption_type='ip_block')  (expect: NEVER locked)")
    _full_cleanup()
    user = _make_user()
    WhitelistedUser.objects.create(user=user, exemption_type='ip_block', is_active=True)
    b_lock, b_rows, b_can_login = run_loop("B")
    b_pass = (b_lock is None) and b_can_login and b_rows == 0
    print(f"  RESULT: {'PASS — fix bypasses lockout for whitelisted user' if b_pass else 'FAIL — user got locked despite whitelist'}")

    # ---------------------------------------------------------------
    # Scenario C — WhitelistedIP only (no user-level whitelist)
    # ---------------------------------------------------------------
    banner("Scenario C — WhitelistedIP only  (expect: NEVER locked)")
    _full_cleanup()
    _make_user()
    WhitelistedIP.objects.create(ip_address=TEST_IP, is_active=True)
    c_lock, c_rows, c_can_login = run_loop("C")
    c_pass = (c_lock is None) and c_can_login and c_rows == 0
    print(f"  RESULT: {'PASS — fix bypasses lockout for whitelisted IP' if c_pass else 'FAIL — IP got locked despite whitelist'}")

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    banner("SUMMARY")
    print(f"  A (negative control):  {'PASS' if a_pass else 'FAIL'}")
    print(f"  B (user whitelist):    {'PASS' if b_pass else 'FAIL'}")
    print(f"  C (IP whitelist):      {'PASS' if c_pass else 'FAIL'}")
    print()
    overall = a_pass and b_pass and c_pass
    print(f"  OVERALL: {'ALL PASS — fix verified end-to-end' if overall else 'FAILURE — review output above'}")
    _full_cleanup()
    return 0 if overall else 1


if __name__ == '__main__':
    sys.exit(main())
