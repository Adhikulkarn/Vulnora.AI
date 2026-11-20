"""
Production settings for Vulnora AI backend.
"""

from .base import *  # noqa: F403

DEBUG = False

# Ensure SECRET_KEY is set via environment variable
if SECRET_KEY == "django-insecure-vulnora-default-dev-key-change-in-production":
    raise ValueError("DJANGO_SECRET_KEY environment variable must be set in production.")

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("DJANGO_ALLOWED_HOSTS", "").split(",")
    if host.strip()
]

if not ALLOWED_HOSTS:
    raise ValueError("DJANGO_ALLOWED_HOSTS environment variable must be set in production.")

# Security headers & hardening
SECURE_SSL_REDIRECT = os.getenv("DJANGO_SECURE_SSL_REDIRECT", "True").lower() in ("true", "1", "yes")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_SECURE_HSTS_SECONDS", "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookies
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Disable browsable API in production by default
REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [  # noqa: F405
    "rest_framework.renderers.JSONRenderer",
]

