"""
Root URL configuration for Vulnora AI backend.
"""

from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Django Admin
    path("admin/", admin.site.urls),

    # OpenAPI 3 / Swagger Documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),

    # API v1 Endpoints
    path("api/v1/", include("apps.core.urls")),
    path("api/v1/projects/", include("apps.projects.urls")),
    path("api/v1/scans/", include("apps.scans.urls")),
    path("api/v1/remediation/", include("apps.remediation.urls")),
    path("api/v1/ai/", include("apps.ai_engine.urls")),
]

