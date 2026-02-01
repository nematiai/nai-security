import os
import urllib.request
from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Download MaxMind GeoLite2 Country database'
    
    DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"

    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            help='Output path for the database file',
        )

    def handle(self, *args, **options):
        output_path = options.get('output')
        
        if not output_path:
            output_path = getattr(settings, 'GEOIP_PATH', None)
        
        if not output_path:
            output_path = os.path.join(settings.BASE_DIR, 'geoip', 'GeoLite2-Country.mmdb')
        
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            self.stdout.write(f"Created directory: {output_dir}")
        
        self.stdout.write(f"Downloading GeoLite2-Country database...")
        self.stdout.write(f"URL: {self.DOWNLOAD_URL}")
        self.stdout.write(f"Output: {output_path}")
        
        try:
            urllib.request.urlretrieve(self.DOWNLOAD_URL, output_path)
            self.stdout.write(self.style.SUCCESS(f"Downloaded to {output_path}"))
            self.stdout.write(self.style.SUCCESS(f"Size: {os.path.getsize(output_path)} bytes"))
            
            try:
                import geoip2.database
                reader = geoip2.database.Reader(output_path)
                response = reader.country('8.8.8.8')
                self.stdout.write(self.style.SUCCESS(f"Verified: 8.8.8.8 -> {response.country.iso_code}"))
                reader.close()
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"Verification failed: {e}"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Download failed: {e}"))
