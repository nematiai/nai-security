from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from nai_security.models import (
    BlockedDomain,
    BlockedUserAgent,
    SecuritySettings,
)
from nai_security.services.sync_services import (
    BadBotSync,
    DisposableDomainSync,
    sync_all,
)

REQUESTS_GET = 'requests.get'


class _Response:
    def __init__(self, text='', ok=True):
        self.text = text
        self._ok = ok

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError('502')


class SyncBaseTest(TestCase):
    """get_settings() caches the singleton for 5 minutes; a rollback does not evict it."""

    def setUp(self):
        cache.clear()
        self.settings_row = SecuritySettings.get_settings()
        self.settings_row.sync_disposable_domains = True
        self.settings_row.sync_bad_bots = True
        self.settings_row.save()
        cache.clear()

    def tearDown(self):
        cache.clear()


class DisposableDomainSyncTest(SyncBaseTest):

    def test_disabled_toggle_short_circuits(self):
        self.settings_row.sync_disposable_domains = False
        self.settings_row.save()
        self.assertEqual(DisposableDomainSync.sync(), {'status': 'disabled', 'added': 0})

    def test_adds_new_domains_and_skips_comments(self):
        body = '# header\nmailinator.com\nGUERRILLAMAIL.COM\n\n'
        with patch(REQUESTS_GET, return_value=_Response(body)):
            result = DisposableDomainSync.sync()

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['added'], 2)
        stored = set(BlockedDomain.objects.values_list('domain', flat=True))
        self.assertEqual(stored, {'mailinator.com', 'guerrillamail.com'})

    def test_second_run_adds_nothing(self):
        with patch(REQUESTS_GET, return_value=_Response('mailinator.com\n')):
            DisposableDomainSync.sync()
            result = DisposableDomainSync.sync()
        self.assertEqual(result['added'], 0)
        self.assertEqual(result['existing'], 1)

    def test_upstream_failure_is_swallowed_as_no_data(self):
        with patch(REQUESTS_GET, side_effect=RuntimeError('unreachable')):
            self.assertEqual(DisposableDomainSync.sync(), {'status': 'no_data', 'added': 0})
        self.assertEqual(BlockedDomain.objects.count(), 0)

    def test_http_error_is_swallowed_as_no_data(self):
        with patch(REQUESTS_GET, return_value=_Response('junk', ok=False)):
            self.assertEqual(DisposableDomainSync.sync(), {'status': 'no_data', 'added': 0})

    def test_records_the_sync_time(self):
        with patch(REQUESTS_GET, return_value=_Response('mailinator.com\n')):
            DisposableDomainSync.sync()
        self.assertIsNotNone(SecuritySettings.objects.get(pk=1).last_sync_at)


class BadBotSyncTest(SyncBaseTest):

    def test_disabled_toggle_short_circuits(self):
        self.settings_row.sync_bad_bots = False
        self.settings_row.save()
        self.assertEqual(BadBotSync.sync(), {'status': 'disabled', 'added': 0})

    def test_seeds_every_default_pattern(self):
        result = BadBotSync.sync()
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['added'], len(BadBotSync.DEFAULT_BAD_BOTS))
        self.assertTrue(BlockedUserAgent.objects.filter(pattern='nikto').exists())

    def test_second_run_is_idempotent(self):
        BadBotSync.sync()
        result = BadBotSync.sync()
        self.assertEqual(result['added'], 0)
        self.assertEqual(BlockedUserAgent.objects.count(), len(BadBotSync.DEFAULT_BAD_BOTS))


class SyncAllTest(SyncBaseTest):

    def test_returns_both_legs(self):
        with patch(REQUESTS_GET, return_value=_Response('mailinator.com\n')):
            result = sync_all()
        self.assertEqual(set(result), {'disposable_domains', 'bad_bots'})
        self.assertEqual(result['disposable_domains']['status'], 'success')
        self.assertEqual(result['bad_bots']['status'], 'success')
