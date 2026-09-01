"""Strip headers that fingerprint the stack for a scanner."""

from django.conf import settings

DEFAULT_FINGERPRINT_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
)


class ResponseHeaderMiddleware:
    """
    Removes stack-identifying response headers.

    Only reaches headers Django owns. A `Server` header added by gunicorn or
    nginx is set after Django returns and must be stripped at that layer.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.headers = tuple(
            getattr(settings, "NAI_SECURITY_STRIP_HEADERS", DEFAULT_FINGERPRINT_HEADERS)
        )

    def __call__(self, request):
        response = self.get_response(request)
        for header in self.headers:
            del response[header]
        return response
