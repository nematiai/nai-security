"""
Middleware to handle lockout responses with user-friendly messages.
"""
from django.http import JsonResponse, HttpResponse
from django.template.loader import render_to_string
from django.utils.deprecation import MiddlewareMixin


class LockoutMessageMiddleware(MiddlewareMixin):
    """
    Intercepts 429 (Too Many Requests) responses and adds lockout information.
    """
    
    def process_response(self, request, response):
        """Add lockout details to 429 responses."""
        if response.status_code != 429:
            return response
        
        # Import here to avoid circular imports
        from nai_security.handlers.progressive_lockout import ProgressiveLockoutHandler
        
        lockout_data = ProgressiveLockoutHandler.get_lockout_response_data(request)
        
        if not lockout_data.get('locked_out'):
            return response
        
        # Check if this is an API request
        if request.path.startswith('/api/') or request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
            return JsonResponse({
                'error': 'Too many login attempts',
                'locked_out': True,
                'attempt_count': lockout_data['attempt_count'],
                'seconds_remaining': lockout_data['seconds_remaining'],
                'time_remaining': lockout_data['time_remaining_display'],
                'unlock_time': lockout_data['unlock_time'],
                'message': f"Account temporarily locked. Please try again in {lockout_data['time_remaining_display']}."
            }, status=429)
        
        # For admin/web requests, add context for template
        request.lockout_data = lockout_data
        return response