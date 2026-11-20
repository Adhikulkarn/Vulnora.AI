"""
Development settings for Vulnora AI backend.
"""

from .base import *  # noqa: F403

DEBUG = True

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,0.0.0.0,testserver").split(",")
    if host.strip()
]
if "testserver" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("testserver")

# Allow all origins in local development for smooth CLI and local client testing
CORS_ALLOW_ALL_ORIGINS = True

INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
]

