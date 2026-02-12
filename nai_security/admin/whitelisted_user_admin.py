from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from ..models import WhitelistedUser

@admin.register(WhitelistedUser)
class WhitelistedUserAdmin(admin.ModelAdmin):
    list_display = ['user', 'exemption_type', 'status_badge', 'expires_at', 'created_at']
    list_filter = ['exemption_type', 'is_active', 'created_at']
    search_fields = ['user__username', 'user__email', 'reason']
    readonly_fields = ['created_at', 'created_by']
    autocomplete_fields = ['user']
    
    fieldsets = (
        ('User', {
            'fields': ('user', 'exemption_type')
        }),
        ('Settings', {
            'fields': ('is_active', 'expires_at', 'reason')
        }),
        ('Audit', {
            'fields': ('created_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
    
    def status_badge(self, obj):
        if not obj.is_active:
            return format_html('<span style="color: red;">❌ Inactive</span>')
        if obj.expires_at and obj.expires_at < timezone.now():
            return format_html('<span style="color: orange;">⏰ Expired</span>')
        return format_html('<span style="color: green;">✅ Active</span>')
    
    status_badge.short_description = 'Status'