from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Sync disposable email domains and bad bot lists'

    def add_arguments(self, parser):
        parser.add_argument(
            '--domains-only',
            action='store_true',
            help='Only sync disposable email domains',
        )
        parser.add_argument(
            '--bots-only',
            action='store_true',
            help='Only sync bad bot user agents',
        )

    def handle(self, *args, **options):
        from nai_security.services.sync_services import (
            DisposableDomainSync, BadBotSync, sync_all
        )

        if options['domains_only']:
            self.stdout.write("Syncing disposable email domains...")
            result = DisposableDomainSync.sync()
            self.stdout.write(self.style.SUCCESS(f"Result: {result}"))
        
        elif options['bots_only']:
            self.stdout.write("Syncing bad bot user agents...")
            result = BadBotSync.sync()
            self.stdout.write(self.style.SUCCESS(f"Result: {result}"))
        
        else:
            self.stdout.write("Syncing all security lists...")
            result = sync_all()
            self.stdout.write(self.style.SUCCESS(f"Result: {result}"))
