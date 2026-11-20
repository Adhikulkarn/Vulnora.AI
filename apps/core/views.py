from django.conf import settings
from django.db import connection
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema

from .serializers import HealthCheckSerializer, SystemStatusSerializer


class ApiRootView(APIView):
    """
    Vulnora AI API Root.
    Provides entry points for all primary API resources.
    """

    @extend_schema(summary="API Root Navigation", responses={200: dict})
    def get(self, request, *args, **kwargs):
        return Response(
            {
                "service": "Vulnora AI Backend",
                "version": "1.0.0",
                "description": "Branch-Aware CLI Security Guard & Remediation Platform API",
                "documentation": {
                    "swagger": request.build_absolute_uri("/api/docs/"),
                    "redoc": request.build_absolute_uri("/api/redoc/"),
                    "openapi_schema": request.build_absolute_uri("/api/schema/"),
                },
                "endpoints": {
                    "health": request.build_absolute_uri("/api/v1/health/"),
                    "status": request.build_absolute_uri("/api/v1/status/"),
                    "projects": request.build_absolute_uri("/api/v1/projects/"),
                    "scans": request.build_absolute_uri("/api/v1/scans/"),
                    "remediation": request.build_absolute_uri("/api/v1/remediation/"),
                    "ai_engine": request.build_absolute_uri("/api/v1/ai/"),
                },
            }
        )


class HealthCheckView(APIView):
    """
    Lightweight health-check endpoint for CLI probes, container orchestrators,
    and monitoring agents.
    """

    @extend_schema(summary="Health Check Probe", responses={200: HealthCheckSerializer})
    def get(self, request, *args, **kwargs):
        payload = {
            "status": "healthy",
            "service": "vulnora-backend",
            "version": "1.0.0",
            "timestamp": timezone.now(),
        }
        return Response(payload, status=status.HTTP_200_OK)


class SystemStatusView(APIView):
    """
    Detailed system status endpoint verifying database connectivity and configuration.
    """

    @extend_schema(summary="System Status & Readiness", responses={200: SystemStatusSerializer})
    def get(self, request, *args, **kwargs):
        db_status = "healthy"
        db_error = None
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except Exception as exc:
            db_status = "unhealthy"
            db_error = str(exc)

        is_healthy = db_status == "healthy"
        http_status = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

        payload = {
            "status": "operational" if is_healthy else "degraded",
            "service": "vulnora-backend",
            "version": "1.0.0",
            "database": {
                "engine": connection.settings_dict.get("ENGINE", "unknown"),
                "status": db_status,
                "error": db_error,
            },
            "environment": {
                "debug": settings.DEBUG,
                "time_zone": settings.TIME_ZONE,
            },
            "vulnora_config": {
                "protected_branches": getattr(settings, "VULNORA_PROTECTED_BRANCHES", []),
                "auto_remediate_default": getattr(settings, "VULNORA_AUTO_REMEDIATE", False),
                "remote_ai_endpoint": getattr(settings, "VULNORA_REMOTE_AI_ENDPOINT", ""),
                "remote_ai_model": getattr(settings, "VULNORA_REMOTE_AI_MODEL", ""),
            },
        }
        return Response(payload, status=http_status)

