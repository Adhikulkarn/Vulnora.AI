import uuid
from django.db import models
from apps.core.models import TimeStampedModel


class ScanStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    RUNNING = "RUNNING", "Running"
    COMPLETED = "COMPLETED", "Completed"
    PARTIALLY_FAILED = "PARTIALLY_FAILED", "Partially Failed"
    FAILED = "FAILED", "Failed"
    TIMED_OUT = "TIMED_OUT", "Timed Out"


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"
    INFO = "INFO", "Info"


class ScanSession(TimeStampedModel):
    """
    Represents a full security scanning execution across selected or all scanners.
    """
    project_path = models.CharField(max_length=1024)
    status = models.CharField(
        max_length=32,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
    )
    requested_scanners = models.JSONField(default=list, blank=True)
    scanner_statuses = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(default=0.0)

    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    error_message = models.TextField(blank=True, default="")

    class Meta(TimeStampedModel.Meta):
        verbose_name = "Scan Session"
        verbose_name_plural = "Scan Sessions"

    def __str__(self):
        return f"ScanSession {self.id} [{self.status}] - {self.total_findings} findings"

    def recalculate_counts(self):
        """Recalculate severity totals based on associated findings."""
        findings = self.findings.all()
        self.total_findings = findings.count()
        self.critical_count = findings.filter(severity=Severity.CRITICAL).count()
        self.high_count = findings.filter(severity=Severity.HIGH).count()
        self.medium_count = findings.filter(severity=Severity.MEDIUM).count()
        self.low_count = findings.filter(severity=Severity.LOW).count()
        self.info_count = findings.filter(severity=Severity.INFO).count()
        self.save(
            update_fields=[
                "total_findings",
                "critical_count",
                "high_count",
                "medium_count",
                "low_count",
                "info_count",
            ]
        )


class Finding(TimeStampedModel):
    """
    Normalized security vulnerability or secret finding identified by a scanner.
    """
    scan_session = models.ForeignKey(
        ScanSession,
        related_name="findings",
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=512)
    description = models.TextField()
    scanner_name = models.CharField(max_length=64, db_index=True)
    rule_id = models.CharField(max_length=256, db_index=True)
    severity = models.CharField(
        max_length=32,
        choices=Severity.choices,
        default=Severity.MEDIUM,
        db_index=True,
    )
    file_path = models.CharField(max_length=1024)
    line_number = models.IntegerField(null=True, blank=True)
    end_line_number = models.IntegerField(null=True, blank=True)
    remediation = models.TextField(blank=True, default="")
    reference_urls = models.JSONField(default=list, blank=True)
    fingerprint = models.CharField(max_length=64, db_index=True, blank=True)
    raw_details = models.JSONField(default=dict, blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = "Finding"
        verbose_name_plural = "Findings"
        indexes = [
            models.Index(fields=["scanner_name", "rule_id"]),
            models.Index(fields=["severity", "created_at"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title} ({self.file_path}:{self.line_number})"
