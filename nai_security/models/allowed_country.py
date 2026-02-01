from django.db import models


class AllowedCountry(models.Model):
    """
    Countries allowed to access the application (whitelist mode).
    When any allowed country exists, ONLY those countries can access.
    """
    
    COUNTRY_CHOICES = [
        ('AF', 'Afghanistan'), ('AL', 'Albania'), ('DZ', 'Algeria'), ('AO', 'Angola'),
        ('AR', 'Argentina'), ('AM', 'Armenia'), ('AU', 'Australia'), ('AT', 'Austria'),
        ('AZ', 'Azerbaijan'), ('BH', 'Bahrain'), ('BD', 'Bangladesh'), ('BY', 'Belarus'),
        ('BE', 'Belgium'), ('BR', 'Brazil'), ('BG', 'Bulgaria'), ('KH', 'Cambodia'),
        ('CA', 'Canada'), ('CN', 'China'), ('CO', 'Colombia'), ('HR', 'Croatia'),
        ('CU', 'Cuba'), ('CY', 'Cyprus'), ('CZ', 'Czech Republic'), ('DK', 'Denmark'),
        ('EG', 'Egypt'), ('EE', 'Estonia'), ('ET', 'Ethiopia'), ('FI', 'Finland'),
        ('FR', 'France'), ('GE', 'Georgia'), ('DE', 'Germany'), ('GH', 'Ghana'),
        ('GR', 'Greece'), ('HK', 'Hong Kong'), ('HU', 'Hungary'), ('IN', 'India'),
        ('ID', 'Indonesia'), ('IR', 'Iran'), ('IQ', 'Iraq'), ('IE', 'Ireland'),
        ('IL', 'Israel'), ('IT', 'Italy'), ('JP', 'Japan'), ('JO', 'Jordan'),
        ('KZ', 'Kazakhstan'), ('KE', 'Kenya'), ('KP', 'North Korea'), ('KR', 'South Korea'),
        ('KW', 'Kuwait'), ('LV', 'Latvia'), ('LB', 'Lebanon'), ('LY', 'Libya'),
        ('LT', 'Lithuania'), ('MY', 'Malaysia'), ('MX', 'Mexico'), ('MA', 'Morocco'),
        ('MM', 'Myanmar'), ('NL', 'Netherlands'), ('NZ', 'New Zealand'), ('NG', 'Nigeria'),
        ('NO', 'Norway'), ('OM', 'Oman'), ('PK', 'Pakistan'), ('PS', 'Palestine'),
        ('PH', 'Philippines'), ('PL', 'Poland'), ('PT', 'Portugal'), ('QA', 'Qatar'),
        ('RO', 'Romania'), ('RU', 'Russia'), ('SA', 'Saudi Arabia'), ('RS', 'Serbia'),
        ('SG', 'Singapore'), ('SK', 'Slovakia'), ('SI', 'Slovenia'), ('ZA', 'South Africa'),
        ('ES', 'Spain'), ('SD', 'Sudan'), ('SE', 'Sweden'), ('CH', 'Switzerland'),
        ('SY', 'Syria'), ('TW', 'Taiwan'), ('TH', 'Thailand'), ('TN', 'Tunisia'),
        ('TR', 'Turkey'), ('UA', 'Ukraine'), ('AE', 'United Arab Emirates'),
        ('GB', 'United Kingdom'), ('US', 'United States'), ('VE', 'Venezuela'),
        ('VN', 'Vietnam'), ('YE', 'Yemen'), ('ZW', 'Zimbabwe'),
    ]
    
    code = models.CharField(
        max_length=2,
        choices=COUNTRY_CHOICES,
        unique=True,
        db_index=True,
        help_text="ISO 3166-1 alpha-2 country code"
    )
    name = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_allowed_country"
        verbose_name = "Allowed Country"
        verbose_name_plural = "Allowed Countries"
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.name:
            self.name = dict(self.COUNTRY_CHOICES).get(self.code, self.code)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.code})"

    @classmethod
    def is_whitelist_mode(cls) -> bool:
        """Check if whitelist mode is active (any allowed countries exist)."""
        return cls.objects.filter(is_active=True).exists()

    @classmethod
    def is_country_allowed(cls, country_code: str) -> bool:
        """Check if country is allowed (only matters in whitelist mode)."""
        if not cls.is_whitelist_mode():
            return True  # No whitelist = all allowed
        return cls.objects.filter(
            code=country_code,
            is_active=True
        ).exists()
