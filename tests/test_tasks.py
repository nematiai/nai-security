from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from nai_security.models import BlockedIP, LoginHistory, SecurityLog
from nai_security.tasks import (
    cleanup_expired_blocks,
    generate_security_report,
    process_auto_blocks,
    shared_task,
    sync_security_lists,
)

AUTO_BLOCKER = 'nai_security.services.AutoBlocker'


class ShimTest(TestCase):
    """Celery is an optional extra; without it tasks.py installs a pass-through decorator."""

    def test_bare_decorator_returns_the_function(self):
        def job():
            return 'ran'
        self.assertIs(shared_task(job), job)

    def test_keyword_form_returns_a_decorator(self):
        def job():
            return 'ran'
        self.assertIs(shared_task(name='security.x')(job), job)


class ProcessAutoBlocksTest(TestCase):

    def test_returns_the_service_result(self):
        with patch(f'{AUTO_BLOCKER}.process_recent_events', return_value={'blocked': 2}) as svc:
            self.assertEqual(process_auto_blocks(), {'blocked': 2})
        svc.assert_called_once_with()

    def test_swallows_failure_and_reports_it(self):
        with patch(f'{AUTO_BLOCKER}.process_recent_events', side_effect=RuntimeError('boom')):
            self.assertEqual(process_auto_blocks(), {'error': 'boom'})


class CleanupExpiredBlocksTest(TestCase):

    def test_wraps_the_count(self):
        with patch(f'{AUTO_BLOCKER}.cleanup_expired_blocks', return_value=7):
            self.assertEqual(cleanup_expired_blocks(), {'cleaned': 7})

    def test_swallows_failure_and_reports_it(self):
        with patch(f'{AUTO_BLOCKER}.cleanup_expired_blocks', side_effect=RuntimeError('boom')):
            self.assertEqual(cleanup_expired_blocks(), {'error': 'boom'})


class SyncSecurityListsTest(TestCase):

    def test_returns_the_sync_result(self):
        with patch('nai_security.services.sync_services.sync_all', return_value={'bad_bots': {}}):
            self.assertEqual(sync_security_lists(), {'bad_bots': {}})

    def test_swallows_failure_and_reports_it(self):
        with patch('nai_security.services.sync_services.sync_all', side_effect=RuntimeError('boom')):
            self.assertEqual(sync_security_lists(), {'error': 'boom'})


class GenerateSecurityReportTest(TestCase):

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_empty_window_reports_zeroes(self):
        report = generate_security_report()
        self.assertEqual(report['period'], 'last_24h')
        self.assertEqual(report['total_blocks'], 0)
        self.assertEqual(report['blocks_by_action'], {})
        self.assertEqual(report['top_blocked_ips'], [])
        self.assertEqual(report['top_blocked_countries'], [])
        self.assertEqual(report['new_auto_blocks'], 0)
        self.assertEqual(report['suspicious_logins'], 0)

    def test_counts_and_ranks_recent_events(self):
        for _ in range(3):
            SecurityLog.log_event(ip_address='1.1.1.1', action='PATH_BLOCK', path='/.git',
                                  country_code='US')
        SecurityLog.log_event(ip_address='2.2.2.2', action='IP_BLOCK', path='/', country_code='DE')
        BlockedIP.objects.create(ip_address='1.1.1.1', is_active=True, is_auto_blocked=True)
        user = get_user_model().objects.create_user(username='scanned', password='x')  # noqa: S106
        LoginHistory.objects.create(user=user, ip_address='3.3.3.3', is_suspicious=True)

        report = generate_security_report()

        self.assertEqual(report['total_blocks'], 4)
        self.assertEqual(report['blocks_by_action'], {'PATH_BLOCK': 3, 'IP_BLOCK': 1})
        self.assertEqual(report['top_blocked_ips'][0], {'ip_address': '1.1.1.1', 'count': 3})
        self.assertEqual(report['top_blocked_countries'][0], {'country_code': 'US', 'count': 3})
        self.assertEqual(report['new_auto_blocks'], 1)
        self.assertEqual(report['suspicious_logins'], 1)

    def test_excludes_blank_country_from_the_country_ranking(self):
        SecurityLog.log_event(ip_address='4.4.4.4', action='IP_BLOCK', path='/')
        self.assertEqual(generate_security_report()['top_blocked_countries'], [])

    def test_swallows_failure_and_reports_it(self):
        with patch('nai_security.models.SecurityLog.objects') as objects:
            objects.filter.side_effect = RuntimeError('boom')
            self.assertEqual(generate_security_report(), {'error': 'boom'})
