from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from nai_security.models import BlockedIP, BlockedCountry, SecurityLog, SecuritySettings
from nai_security.services.auto_blocker import AutoBlocker


class AutoBlockerBaseTest(TestCase):

    def setUp(self):
        cache.clear()
        SecuritySettings.objects.update_or_create(
            pk=1,
            defaults={
                'auto_block_ip_threshold': 10,
                'auto_block_ip_window_hours': 1,
                'auto_block_ip_duration_hours': 24,
                'auto_block_country_threshold': 100,
                'auto_block_country_window_hours': 24,
                'auto_block_country_enabled': False,
            }
        )

    def _create_events(self, ip, count, country_code='', hours_ago=0):
        """Helper to create security log events."""
        created_at = timezone.now() - timedelta(hours=hours_ago)
        for _ in range(count):
            SecurityLog.objects.create(
                ip_address=ip,
                action='IP_BLOCK',
                path='/test/',
                country_code=country_code,
            )


# ------------------------------------------------------------------
# IP auto-blocking
# ------------------------------------------------------------------

class CheckAndBlockIPTest(AutoBlockerBaseTest):

    def test_blocks_ip_above_threshold(self):
        self._create_events('6.6.6.6', 10)
        result = AutoBlocker.check_and_block_ip('6.6.6.6')
        self.assertTrue(result)
        self.assertTrue(BlockedIP.objects.filter(ip_address='6.6.6.6', is_auto_blocked=True).exists())

    def test_does_not_block_below_threshold(self):
        self._create_events('6.6.6.6', 5)
        result = AutoBlocker.check_and_block_ip('6.6.6.6')
        self.assertFalse(result)
        self.assertFalse(BlockedIP.objects.filter(ip_address='6.6.6.6').exists())

    def test_does_not_double_block(self):
        self._create_events('6.6.6.6', 10)
        BlockedIP.objects.create(ip_address='6.6.6.6', is_active=True)
        result = AutoBlocker.check_and_block_ip('6.6.6.6')
        self.assertFalse(result)
        self.assertEqual(BlockedIP.objects.filter(ip_address='6.6.6.6').count(), 1)

    def test_sets_expiry_when_duration_nonzero(self):
        self._create_events('6.6.6.6', 10)
        AutoBlocker.check_and_block_ip('6.6.6.6')
        blocked = BlockedIP.objects.get(ip_address='6.6.6.6')
        self.assertIsNotNone(blocked.expires_at)
        # Should be ~24h from now
        diff = blocked.expires_at - timezone.now()
        self.assertTrue(timedelta(hours=23) < diff < timedelta(hours=25))

    def test_permanent_block_when_duration_zero(self):
        settings = SecuritySettings.get_settings()
        settings.auto_block_ip_duration_hours = 0
        settings.save()
        cache.clear()

        self._create_events('6.6.6.6', 10)
        AutoBlocker.check_and_block_ip('6.6.6.6')
        blocked = BlockedIP.objects.get(ip_address='6.6.6.6')
        self.assertIsNone(blocked.expires_at)

    def test_logs_auto_block_event(self):
        self._create_events('6.6.6.6', 10)
        AutoBlocker.check_and_block_ip('6.6.6.6')
        self.assertTrue(SecurityLog.objects.filter(action='AUTO_BLOCK_IP').exists())

    def test_disabled_threshold_does_not_block(self):
        settings = SecuritySettings.get_settings()
        settings.auto_block_ip_threshold = 0
        settings.save()
        cache.clear()

        self._create_events('6.6.6.6', 50)
        result = AutoBlocker.check_and_block_ip('6.6.6.6')
        self.assertFalse(result)


# ------------------------------------------------------------------
# Country auto-blocking / flagging
# ------------------------------------------------------------------

class CheckAndFlagCountryTest(AutoBlockerBaseTest):

    def test_flags_country_when_auto_block_disabled(self):
        self._create_events('1.1.1.1', 100, country_code='CN')
        result = AutoBlocker.check_and_flag_country('CN')
        self.assertTrue(result)
        # Should be flagged but NOT active (auto_block_country_enabled=False)
        country = BlockedCountry.objects.get(code='CN')
        self.assertFalse(country.is_active)

    def test_blocks_country_when_auto_block_enabled(self):
        settings = SecuritySettings.get_settings()
        settings.auto_block_country_enabled = True
        settings.save()
        cache.clear()

        self._create_events('1.1.1.1', 100, country_code='CN')
        result = AutoBlocker.check_and_flag_country('CN')
        self.assertTrue(result)
        country = BlockedCountry.objects.get(code='CN')
        self.assertTrue(country.is_active)
        self.assertTrue(country.is_auto_blocked)

    def test_does_not_flag_below_threshold(self):
        self._create_events('1.1.1.1', 50, country_code='CN')
        result = AutoBlocker.check_and_flag_country('CN')
        self.assertFalse(result)

    def test_does_not_double_block_country(self):
        BlockedCountry.objects.create(code='CN', is_active=True)
        self._create_events('1.1.1.1', 100, country_code='CN')
        result = AutoBlocker.check_and_flag_country('CN')
        self.assertFalse(result)

    def test_empty_country_code_skipped(self):
        result = AutoBlocker.check_and_flag_country('')
        self.assertFalse(result)

    def test_logs_auto_block_country_event(self):
        settings = SecuritySettings.get_settings()
        settings.auto_block_country_enabled = True
        settings.save()
        cache.clear()

        self._create_events('1.1.1.1', 100, country_code='RU')
        AutoBlocker.check_and_flag_country('RU')
        self.assertTrue(SecurityLog.objects.filter(action='AUTO_BLOCK_COUNTRY').exists())


# ------------------------------------------------------------------
# process_recent_events
# ------------------------------------------------------------------

class ProcessRecentEventsTest(AutoBlockerBaseTest):

    def test_processes_and_blocks(self):
        self._create_events('6.6.6.6', 15)
        self._create_events('7.7.7.7', 3)
        result = AutoBlocker.process_recent_events()
        self.assertEqual(result['blocked_ips'], 1)
        self.assertTrue(BlockedIP.objects.filter(ip_address='6.6.6.6').exists())
        self.assertFalse(BlockedIP.objects.filter(ip_address='7.7.7.7').exists())

    def test_returns_zero_when_no_threats(self):
        result = AutoBlocker.process_recent_events()
        self.assertEqual(result['blocked_ips'], 0)
        self.assertEqual(result['flagged_countries'], 0)


# ------------------------------------------------------------------
# cleanup_expired_blocks
# ------------------------------------------------------------------

class CleanupExpiredBlocksTest(AutoBlockerBaseTest):

    def test_deactivates_expired_blocks(self):
        BlockedIP.objects.create(
            ip_address='1.1.1.1',
            is_active=True,
            expires_at=timezone.now() - timedelta(hours=1),
        )
        BlockedIP.objects.create(
            ip_address='2.2.2.2',
            is_active=True,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        count = AutoBlocker.cleanup_expired_blocks()
        self.assertEqual(count, 1)
        self.assertFalse(BlockedIP.objects.get(ip_address='1.1.1.1').is_active)
        self.assertTrue(BlockedIP.objects.get(ip_address='2.2.2.2').is_active)

    def test_permanent_blocks_not_cleaned(self):
        BlockedIP.objects.create(
            ip_address='3.3.3.3',
            is_active=True,
            expires_at=None,
        )
        count = AutoBlocker.cleanup_expired_blocks()
        self.assertEqual(count, 0)
        self.assertTrue(BlockedIP.objects.get(ip_address='3.3.3.3').is_active)

    def test_returns_zero_when_nothing_expired(self):
        count = AutoBlocker.cleanup_expired_blocks()
        self.assertEqual(count, 0)
