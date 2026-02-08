from django.contrib import admin
from django.utils.html import format_html
from unfold.admin import ModelAdmin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from .models import (
    BlockedCountry, BlockedIP, BlockedEmail, BlockedDomain,
    BlockedUserAgent, WhitelistedIP, AllowedCountry,
    RateLimitRule, LoginHistory, SecurityLog, SecuritySettings
)

# =============================================================================
# UNREGISTER AXES DEFAULT ADMIN
# =============================================================================
try:
    from axes.models import AccessAttempt, AccessLog, AccessFailureLog
    
    admin.site.unregister(AccessAttempt)
    try:
        admin.site.unregister(AccessLog)
    except admin.sites.NotRegistered:
        pass
    try:
        admin.site.unregister(AccessFailureLog)
    except admin.sites.NotRegistered:
        pass
    
    AXES_INSTALLED = True
except (ImportError, admin.sites.NotRegistered):
    AXES_INSTALLED = False


# =============================================================================
# RESOURCES FOR IMPORT/EXPORT
# =============================================================================
class BlockedEmailResource(resources.ModelResource):
    class Meta:
        model = BlockedEmail
        fields = ('id', 'email', 'reason', 'is_active', 'is_auto_blocked', 'created_at')
        import_id_fields = ('email',)


class BlockedDomainResource(resources.ModelResource):
    class Meta:
        model = BlockedDomain
        fields = ('id', 'domain', 'domain_type', 'reason', 'is_active', 'created_at')
        import_id_fields = ('domain',)


# =============================================================================
# ADMIN CLASSES
# =============================================================================
@admin.register(BlockedCountry)
class BlockedCountryAdmin(ModelAdmin):
    list_display = ['code', 'name', 'is_active', 'is_auto_blocked', 'attack_count', 'created_at']
    list_filter = ['is_active', 'is_auto_blocked', 'created_at']
    search_fields = ['code', 'name', 'reason']
    list_editable = ['is_active']
    ordering = ['name']


@admin.register(BlockedIP)
class BlockedIPAdmin(ModelAdmin):
    list_display = ['ip_address', 'is_active', 'status_badge', 'is_auto_blocked', 'country_code', 'expires_at']
    list_filter = ['is_active', 'is_auto_blocked', 'country_code', 'created_at']
    search_fields = ['ip_address', 'reason']
    list_editable = ['is_active']
    ordering = ['-created_at']

    def status_badge(self, obj):
        if obj.is_expired():
            return format_html('<span style="color: orange;">⏰ Expired</span>')
        if obj.is_auto_blocked:
            return format_html('<span style="color: purple;">🤖 Auto</span>')
        if obj.is_active:
            return format_html('<span style="color: red;">🚫 Blocked</span>')
        return format_html('<span style="color: gray;">⭕ Inactive</span>')
    status_badge.short_description = 'Status'


@admin.register(BlockedEmail)
class BlockedEmailAdmin(ImportExportModelAdmin, ModelAdmin):
    resource_class = BlockedEmailResource
    list_display = ['email_display', 'is_active', 'is_auto_blocked', 'reason_short', 'created_at']
    list_filter = ['is_active', 'is_auto_blocked', 'created_at']
    search_fields = ['email', 'reason']
    list_editable = ['is_active']
    ordering = ['-created_at']

    def email_display(self, obj):
        icon = '🤖' if obj.is_auto_blocked else '🚫'
        return format_html('<span style="color: #dc3545;">{} {}</span>', icon, obj.email)
    email_display.short_description = 'Email'

    def reason_short(self, obj):
        if obj.reason and len(obj.reason) > 40:
            return obj.reason[:40] + '...'
        return obj.reason or '-'
    reason_short.short_description = 'Reason'


@admin.register(BlockedDomain)
class BlockedDomainAdmin(ImportExportModelAdmin, ModelAdmin):
    resource_class = BlockedDomainResource
    list_display = ['domain', 'domain_type', 'is_active', 'is_auto_synced', 'created_at']
    list_filter = ['is_active', 'is_auto_synced', 'domain_type', 'created_at']
    search_fields = ['domain', 'reason']
    list_editable = ['is_active']
    ordering = ['domain']


@admin.register(BlockedUserAgent)
class BlockedUserAgentAdmin(ModelAdmin):
    list_display = ['pattern_short', 'block_type', 'category', 'is_active', 'block_count', 'is_auto_synced']
    list_filter = ['is_active', 'is_auto_synced', 'category', 'block_type']
    search_fields = ['pattern', 'description']
    list_editable = ['is_active']
    ordering = ['-block_count']

    def pattern_short(self, obj):
        if len(obj.pattern) > 40:
            return obj.pattern[:40] + '...'
        return obj.pattern
    pattern_short.short_description = 'Pattern'


@admin.register(WhitelistedIP)
class WhitelistedIPAdmin(ModelAdmin):
    list_display = ['ip_address', 'description', 'is_active', 'created_by', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['ip_address', 'description']
    list_editable = ['is_active']
    ordering = ['-created_at']


@admin.register(AllowedCountry)
class AllowedCountryAdmin(ModelAdmin):
    list_display = ['code', 'name', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['code', 'name']
    list_editable = ['is_active']
    ordering = ['name']


@admin.register(RateLimitRule)
class RateLimitRuleAdmin(ModelAdmin):
    list_display = ['name', 'path_pattern', 'method', 'rate', 'is_active', 'block_count']
    list_filter = ['is_active', 'method', 'rate']
    search_fields = ['name', 'path_pattern']
    list_editable = ['is_active', 'rate']
    ordering = ['path_pattern']


@admin.register(LoginHistory)
class LoginHistoryAdmin(ModelAdmin):
    list_display = ['created_at', 'user', 'ip_address', 'country_code', 'device_type', 'suspicious_badge']
    list_filter = ['is_suspicious', 'country_code', 'device_type', 'created_at']
    search_fields = ['user__email', 'ip_address', 'country_code']
    readonly_fields = ['user', 'ip_address', 'country_code', 'city', 'user_agent', 'device_type', 
                      'browser', 'os', 'is_suspicious', 'suspicious_reason', 'session_key', 'created_at']
    ordering = ['-created_at']

    def suspicious_badge(self, obj):
        if obj.is_suspicious:
            return format_html('<span style="color: red;" title="{}">⚠️ Yes</span>', obj.suspicious_reason)
        return format_html('<span style="color: green;">✅ No</span>')
    suspicious_badge.short_description = 'Suspicious'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SecurityLog)
class SecurityLogAdmin(ModelAdmin):
    list_display = ['created_at', 'action_badge', 'severity_badge', 'ip_address', 'country_code', 'path_short']
    list_filter = ['action', 'severity', 'country_code', 'created_at']
    search_fields = ['ip_address', 'path', 'details', 'user_email']
    readonly_fields = ['ip_address', 'country_code', 'action', 'severity', 'path', 'method',
                      'user_agent', 'details', 'user_email', 'created_at']
    ordering = ['-created_at']

    def action_badge(self, obj):
        colors = {
            'COUNTRY_BLOCK': '#fd7e14',
            'COUNTRY_WHITELIST_BLOCK': '#fd7e14',
            'IP_BLOCK': '#dc3545',
            'EMAIL_BLOCK': '#6f42c1',
            'DOMAIN_BLOCK': '#6c757d',
            'USER_AGENT_BLOCK': '#6c757d',
            'RATE_LIMIT': '#0d6efd',
            'AXES_LOCK': '#dc3545',
            'SUSPICIOUS_LOGIN': '#ffc107',
            'AUTO_BLOCK_IP': '#dc3545',
            'AUTO_BLOCK_COUNTRY': '#dc3545',
        }
        color = colors.get(obj.action, '#6c757d')
        return format_html('<span style="color: {};">{}</span>', color, obj.get_action_display())
    action_badge.short_description = 'Action'

    def severity_badge(self, obj):
        colors = {'low': '#28a745', 'medium': '#ffc107', 'high': '#fd7e14', 'critical': '#dc3545'}
        color = colors.get(obj.severity, '#6c757d')
        return format_html('<span style="color: {};">●</span> {}', color, obj.severity.upper())
    severity_badge.short_description = 'Severity'

    def path_short(self, obj):
        return obj.path[:40] + '...' if len(obj.path) > 40 else obj.path
    path_short.short_description = 'Path'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SecuritySettings)
class SecuritySettingsAdmin(ModelAdmin):
    list_display = ['__str__', 'country_blocking_enabled', 'ip_blocking_enabled', 
                   'email_blocking_enabled', 'login_history_enabled', 'updated_at']
    
    fieldsets = (
        ('Feature Toggles', {
            'fields': (
                'country_blocking_enabled', 'country_whitelist_mode',
                'ip_blocking_enabled', 'email_blocking_enabled',
                'domain_blocking_enabled', 'user_agent_blocking_enabled',
                'login_history_enabled',
            )
        }),
        ('Auto-Block IP Settings', {
            'fields': (
                'max_login_attempts',
                'auto_block_ip_threshold', 'auto_block_ip_window_hours',
                'auto_block_ip_duration_hours',
            )
        }),
        ('Auto-Block Country Settings', {
            'fields': (
                'auto_block_country_enabled', 'auto_block_country_threshold',
                'auto_block_country_window_hours',
            )
        }),
        ('Login Anomaly Detection', {
            'fields': (
                'alert_on_new_country', 'alert_on_new_ip', 'max_countries_per_day',
            )
        }),
        ('Sync Settings', {
            'fields': ('sync_disposable_domains', 'sync_bad_bots', 'last_sync_at'),
        }),
        ('Notifications', {
            'fields': ('notify_on_auto_block', 'notification_email', 'telegram_notifications'),
        }),
    )

    def has_add_permission(self, request):
        return not SecuritySettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


# =============================================================================
# AXES ADMIN (PROXY MODEL UNDER SECURITY)
# =============================================================================
try:
    from axes.models import AccessAttempt as AxesAccessAttempt
    from .models import AccessAttempt  # Our proxy model
    
    # Unregister original Axes admin
    try:
        admin.site.unregister(AxesAccessAttempt)
    except admin.sites.NotRegistered:
        pass
    
    @admin.register(AccessAttempt)
    class AccessAttemptAdmin(ModelAdmin):
        list_display = ['attempt_time', 'ip_address', 'username', 'failures_since_start', 'path_info']
        list_filter = ['attempt_time', 'path_info']
        search_fields = ['ip_address', 'username', 'user_agent']
        readonly_fields = ['user_agent', 'ip_address', 'username', 'http_accept', 
                          'path_info', 'attempt_time', 'get_data', 'post_data', 'failures_since_start']
        ordering = ['-attempt_time']

        def has_add_permission(self, request):
            return False

        def has_change_permission(self, request, obj=None):
            return False

        def has_delete_permission(self, request, obj=None):
            return True  # Allow clearing attempts

except ImportError:
    pass
