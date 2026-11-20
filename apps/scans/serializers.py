from rest_framework import serializers
from .models import Finding, ScanSession, ScanStatus, Severity


class ScansModuleInfoSerializer(serializers.Serializer):
    module = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    integrated_scanners = serializers.ListField(child=serializers.CharField())
    scanner_details = serializers.DictField()


class FindingSerializer(serializers.ModelSerializer):
    """
    Serializer for normalized vulnerability and secret findings.
    """
    scan_id = serializers.UUIDField(source="scan_session_id", read_only=True)

    class Meta:
        model = Finding
        fields = [
            "id",
            "scan_id",
            "title",
            "description",
            "scanner_name",
            "rule_id",
            "severity",
            "file_path",
            "line_number",
            "end_line_number",
            "remediation",
            "reference_urls",
            "fingerprint",
            "raw_details",
            "created_at",
        ]
        read_only_fields = fields


class ScanInitiateSerializer(serializers.Serializer):
    """
    Input schema for initiating a security scan.
    Supports filesystem scanning (SAST/secrets/dependencies/IaC) and web app scanning (DAST).
    """
    project_path = serializers.CharField(
        required=False,
        default="",
        allow_blank=True,
        help_text="Absolute local filesystem directory path to be scanned.",
    )
    target_url = serializers.CharField(
        required=False,
        default="",
        allow_blank=True,
        help_text="Target URL of the running web application for DAST scanning (e.g. http://127.0.0.1:8000).",
    )
    scanners = serializers.ListField(
        child=serializers.ChoiceField(
            choices=["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"]
        ),
        required=False,
        default=None,
        help_text="Optional list of specific scanners to run. Defaults to all 6 available scanners.",
    )
    timeout_seconds = serializers.IntegerField(
        required=False,
        default=60,
        min_value=5,
        max_value=600,
        help_text="Per-scanner execution timeout in seconds (default: 60).",
    )

    def validate(self, attrs):
        if not attrs.get("project_path") and not attrs.get("target_url"):
            raise serializers.ValidationError(
                "Either 'project_path' (for SAST/secrets/dependencies/IaC) or 'target_url' (for DAST) must be provided."
            )
        return attrs


class ScanSessionListSerializer(serializers.ModelSerializer):
    """
    Summary view for listing scan history.
    """
    class Meta:
        model = ScanSession
        fields = [
            "id",
            "project_path",
            "target_url",
            "status",
            "requested_scanners",
            "total_findings",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "info_count",
            "duration_seconds",
            "started_at",
            "completed_at",
            "created_at",
        ]


class ScanSessionDetailSerializer(serializers.ModelSerializer):
    """
    Detailed scan session including findings and individual scanner execution logs.
    """
    findings = FindingSerializer(many=True, read_only=True)

    class Meta:
        model = ScanSession
        fields = [
            "id",
            "project_path",
            "target_url",
            "status",
            "requested_scanners",
            "scanner_statuses",
            "total_findings",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "info_count",
            "duration_seconds",
            "started_at",
            "completed_at",
            "error_message",
            "findings",
            "created_at",
            "updated_at",
        ]


class ScanSummarySerializer(serializers.Serializer):
    """
    Severity-based summary of a specific scan session.
    """
    scan_id = serializers.UUIDField()
    status = serializers.CharField()
    project_path = serializers.CharField(allow_blank=True)
    target_url = serializers.CharField(allow_blank=True)
    scanners = serializers.DictField()
    severity_summary = serializers.DictField()
    duration_seconds = serializers.FloatField()
    started_at = serializers.DateTimeField(allow_null=True)
    completed_at = serializers.DateTimeField(allow_null=True)
