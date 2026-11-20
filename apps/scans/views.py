import logging
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiParameter

from .models import Finding, ScanSession, Severity
from .serializers import (
    FindingSerializer,
    ScanInitiateSerializer,
    ScanSessionDetailSerializer,
    ScanSessionListSerializer,
    ScanSummarySerializer,
    ScansModuleInfoSerializer,
)
from .services.orchestrator import ScannerOrchestrator

logger = logging.getLogger(__name__)


class ScansModuleIndexView(APIView):
    """
    Overview of Security Scanner Orchestration status and tool discovery.
    """

    @extend_schema(summary="Scans Module Overview", responses={200: ScansModuleInfoSerializer})
    def get(self, request, *args, **kwargs):
        orchestrator = ScannerOrchestrator()
        tool_status = orchestrator.get_scanner_availability()

        return Response(
            {
                "module": "scans",
                "description": "Orchestrates and normalizes findings from Gitleaks, Semgrep, Bandit, OSV-Scanner, Trivy, and OWASP ZAP.",
                "status": "operational",
                "integrated_scanners": [
                    f"{name} ({'Available: ' + str(meta['version']) if meta['installed'] else 'Not Installed'})"
                    for name, meta in tool_status.items()
                ],
                "scanner_details": tool_status,
            }
        )


class ScanListCreateView(APIView):
    """
    POST /api/v1/scans/ — Initiate a new security scan.
    GET /api/v1/scans/ — List historical security scans.
    """

    @extend_schema(
        summary="List Scan History",
        responses={200: ScanSessionListSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        sessions = ScanSession.objects.all().order_by("-created_at")
        serializer = ScanSessionListSerializer(sessions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Initiate Security Scan",
        request=ScanInitiateSerializer,
        responses={201: ScanSessionDetailSerializer, 400: dict, 404: dict},
    )
    def post(self, request, *args, **kwargs):
        serializer = ScanInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        project_path = serializer.validated_data.get("project_path")
        target_url = serializer.validated_data.get("target_url")
        scanners = serializer.validated_data.get("scanners")
        timeout_seconds = serializer.validated_data.get("timeout_seconds", 60)

        orchestrator = ScannerOrchestrator()

        try:
            session = orchestrator.execute_and_record(
                raw_project_path=project_path,
                target_url=target_url,
                scanners_to_run=scanners,
                timeout_seconds=timeout_seconds,
            )
            response_serializer = ScanSessionDetailSerializer(session)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except FileNotFoundError as fnf_err:
            return Response(
                {"error": "Project path not found", "detail": str(fnf_err)},
                status=status.HTTP_404_NOT_FOUND,
            )
        except (ValueError, NotADirectoryError, PermissionError) as val_err:
            return Response(
                {"error": "Invalid project directory or target URL", "detail": str(val_err)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            logger.exception(f"Scan initiation failed unexpectedly: {exc}")
            return Response(
                {"error": "Scan execution failed", "detail": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            return Response(
                {"error": "Invalid project directory", "detail": str(val_err)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            logger.exception(f"Scan initiation failed unexpectedly: {exc}")
            return Response(
                {"error": "Scan execution failed", "detail": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ScanDetailView(APIView):
    """
    GET /api/v1/scans/{id}/ — Retrieve complete scan details with findings and scanner logs.
    """

    @extend_schema(
        summary="Retrieve Scan Details",
        responses={200: ScanSessionDetailSerializer, 404: dict},
    )
    def get(self, request, pk, *args, **kwargs):
        session = get_object_or_404(ScanSession.objects.prefetch_related("findings"), pk=pk)
        serializer = ScanSessionDetailSerializer(session)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ScanSummaryView(APIView):
    """
    GET /api/v1/scans/{id}/summary/ — Get a severity-based summary of a scan session.
    """

    @extend_schema(
        summary="Get Scan Severity Summary",
        responses={200: ScanSummarySerializer, 404: dict},
    )
    def get(self, request, pk, *args, **kwargs):
        session = get_object_or_404(ScanSession, pk=pk)

        payload = {
            "scan_id": session.id,
            "status": session.status,
            "project_path": session.project_path,
            "target_url": session.target_url,
            "scanners": session.scanner_statuses,
            "severity_summary": {
                "CRITICAL": session.critical_count,
                "HIGH": session.high_count,
                "MEDIUM": session.medium_count,
                "LOW": session.low_count,
                "INFO": session.info_count,
                "total": session.total_findings,
            },
            "duration_seconds": session.duration_seconds,
            "started_at": session.started_at,
            "completed_at": session.completed_at,
        }
        return Response(payload, status=status.HTTP_200_OK)


class VulnerabilityListView(APIView):
    """
    GET /api/v1/vulnerabilities/ — List normalized findings across scans with query filters.
    """

    @extend_schema(
        summary="List Normalized Vulnerabilities",
        parameters=[
            OpenApiParameter("scan_id", str, description="Filter by scan session ID (UUID)"),
            OpenApiParameter("severity", str, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
            OpenApiParameter("scanner_name", str, description="Filter by scanner (gitleaks, semgrep, bandit, osv-scanner)"),
            OpenApiParameter("rule_id", str, description="Filter by rule ID"),
        ],
        responses={200: FindingSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        queryset = Finding.objects.all().order_by("-created_at")

        scan_id = request.query_params.get("scan_id")
        if scan_id:
            queryset = queryset.filter(scan_session_id=scan_id)

        severity = request.query_params.get("severity")
        if severity:
            queryset = queryset.filter(severity=severity.upper())

        scanner_name = request.query_params.get("scanner_name")
        if scanner_name:
            queryset = queryset.filter(scanner_name=scanner_name.lower())

        rule_id = request.query_params.get("rule_id")
        if rule_id:
            queryset = queryset.filter(rule_id=rule_id)

        serializer = FindingSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
