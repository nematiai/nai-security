import logging
import requests
from django.utils import timezone

from ..models import BlockedDomain, BlockedUserAgent, SecuritySettings

logger = logging.getLogger(__name__)


class DisposableDomainSync:
    """Sync disposable email domains from public lists."""
    
    # Public sources for disposable email domains
    SOURCES = [
        'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
    ]
    
    @classmethod
    def sync(cls) -> dict:
        """
        Sync disposable domains from public sources.
        Returns summary of actions.
        """
        settings = SecuritySettings.get_settings()
        
        if not settings.sync_disposable_domains:
            return {'status': 'disabled', 'added': 0}
        
        all_domains = set()
        
        for source_url in cls.SOURCES:
            try:
                response = requests.get(source_url, timeout=30)
                response.raise_for_status()
                
                domains = [
                    line.strip().lower()
                    for line in response.text.split('\n')
                    if line.strip() and not line.startswith('#')
                ]
                all_domains.update(domains)
                logger.info(f"Fetched {len(domains)} domains from {source_url}")
                
            except Exception as e:
                logger.error(f"Failed to fetch from {source_url}: {e}")
        
        if not all_domains:
            return {'status': 'no_data', 'added': 0}
        
        # Get existing domains
        existing = set(BlockedDomain.objects.filter(
            is_auto_synced=True
        ).values_list('domain', flat=True))
        
        # Find new domains
        new_domains = all_domains - existing
        
        # Bulk create new domains
        added = 0
        if new_domains:
            objs = [
                BlockedDomain(
                    domain=domain,
                    domain_type='disposable',
                    reason='Auto-synced from public list',
                    is_active=True,
                    is_auto_synced=True,
                )
                for domain in new_domains
            ]
            BlockedDomain.objects.bulk_create(objs, ignore_conflicts=True)
            added = len(new_domains)
            logger.info(f"Added {added} new disposable domains")
        
        # Update last sync time
        SecuritySettings.objects.filter(pk=1).update(last_sync_at=timezone.now())
        
        return {
            'status': 'success',
            'total_sources': len(cls.SOURCES),
            'total_domains': len(all_domains),
            'added': added,
            'existing': len(existing),
        }


class BadBotSync:
    """Sync bad bot user agents from public lists."""
    
    # Common bad bots to block
    DEFAULT_BAD_BOTS = [
        ('AhrefsBot', 'contains', 'scraper', 'SEO scraper'),
        ('SemrushBot', 'contains', 'scraper', 'SEO scraper'),
        ('MJ12bot', 'contains', 'scraper', 'SEO scraper'),
        ('DotBot', 'contains', 'scraper', 'SEO scraper'),
        ('BLEXBot', 'contains', 'scraper', 'SEO scraper'),
        ('serpstatbot', 'contains', 'scraper', 'SEO scraper'),
        ('SeekportBot', 'contains', 'scraper', 'SEO scraper'),
        ('zgrab', 'contains', 'attack', 'Security scanner'),
        ('masscan', 'contains', 'attack', 'Security scanner'),
        ('Nuclei', 'contains', 'attack', 'Security scanner'),
        ('sqlmap', 'contains', 'attack', 'SQL injection tool'),
        ('nikto', 'contains', 'attack', 'Vulnerability scanner'),
        ('nmap', 'contains', 'attack', 'Network scanner'),
        ('python-requests', 'contains', 'bot', 'Generic bot'),
        ('Go-http-client', 'contains', 'bot', 'Generic bot'),
        ('curl/', 'contains', 'bot', 'Command line tool'),
        ('wget/', 'contains', 'bot', 'Command line tool'),
        ('libwww-perl', 'contains', 'bot', 'Generic bot'),
        ('Scrapy', 'contains', 'scraper', 'Web scraper'),
        ('CCBot', 'contains', 'scraper', 'Common Crawl bot'),
        ('Bytespider', 'contains', 'scraper', 'ByteDance spider'),
        ('GPTBot', 'contains', 'scraper', 'OpenAI crawler'),
        ('ClaudeBot', 'contains', 'scraper', 'Anthropic crawler'),
        ('anthropic-ai', 'contains', 'scraper', 'Anthropic crawler'),
        ('ChatGPT-User', 'contains', 'scraper', 'OpenAI crawler'),
    ]
    
    @classmethod
    def sync(cls) -> dict:
        """
        Sync bad bot user agents.
        Returns summary of actions.
        """
        settings = SecuritySettings.get_settings()
        
        if not settings.sync_bad_bots:
            return {'status': 'disabled', 'added': 0}
        
        # Get existing patterns
        existing = set(BlockedUserAgent.objects.filter(
            is_auto_synced=True
        ).values_list('pattern', flat=True))
        
        added = 0
        for pattern, block_type, category, description in cls.DEFAULT_BAD_BOTS:
            if pattern not in existing:
                BlockedUserAgent.objects.create(
                    pattern=pattern,
                    block_type=block_type,
                    category=category,
                    description=description,
                    is_active=True,
                    is_auto_synced=True,
                )
                added += 1
        
        if added > 0:
            logger.info(f"Added {added} new bad bot patterns")
        
        # Update last sync time
        SecuritySettings.objects.filter(pk=1).update(last_sync_at=timezone.now())
        
        return {
            'status': 'success',
            'total_patterns': len(cls.DEFAULT_BAD_BOTS),
            'added': added,
            'existing': len(existing),
        }


def sync_all() -> dict:
    """Run all sync operations."""
    results = {
        'disposable_domains': DisposableDomainSync.sync(),
        'bad_bots': BadBotSync.sync(),
    }
    logger.info(f"Security sync completed: {results}")
    return results
