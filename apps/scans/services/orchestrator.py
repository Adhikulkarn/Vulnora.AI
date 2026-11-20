import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from django.utils import timezone

from apps.scans.models import Finding, ScanSession, ScanStatus, Severity
from vulnora.scanners import (
    BanditScannerService,
    BaseScannerService,
    GitleaksScannerService,
    NormalizedFinding,
    OSVScannerService,
    OWASPZAPScannerService,
    ScannerExecutionResult,
    ScannerOrchestrator as BaseScannerOrchestrator,
    SemgrepScannerService,
    TrivyScannerService,
)

logger = logging.getLogger(__name__)


class ScannerOrchestrator(BaseScannerOrchestrator):
    """
    Django-integrated Scanner Orchestrator.
    Inherits the core multi-scanner engine from vulnora.scanners and adds
    ORM persistence into Django's ScanSession and Finding database tables.
    """

    def execute_and_record(
        self,
        raw_project_path: Optional[str] = None,
        target_url: Optional[str] = None,
        scanners_to_run: Optional[List[str]] = None,
        timeout_seconds: int = 60,
    ) -> ScanSession:
        """
        Validates input path and target URL, coordinates scanner executions, and persists results.
        """
        if not raw_project_path and not target_url:
            raise ValueError("Either 'project_path' (for SAST/secrets/dependencies/IaC) or 'target_url' (for DAST) must be provided.")

        validated_path = self.validate_project_path(raw_project_path) if raw_project_path else None
        validated_url = self.validate_target_url(target_url) if target_url else None
        started_at = timezone.now()

        # Initialize ScanSession record
        session = ScanSession.objects.create(
            project_path=str(validated_path) if validated_path else "",
            target_url=validated_url or "",
            status=ScanStatus.RUNNING,
            requested_scanners=scanners_to_run or (
                list(self.scanners.keys()) if (validated_path and validated_url) else
                (["zap"] if validated_url and not validated_path else list(self.DEFAULT_FILESYSTEM_SCANNERS))
            ),
            started_at=started_at,
        )

        try:
            overall_status, scanner_statuses, unified_findings, duration = self.run_scan(
                project_path=validated_path,
                target_url=validated_url,
                scanners_to_run=scanners_to_run,
                timeout_seconds=timeout_seconds,
            )

            # Map status string to Django model enum
            if overall_status == "COMPLETED":
                db_status = ScanStatus.COMPLETED
            elif overall_status == "PARTIAL":
                db_status = ScanStatus.PARTIALLY_FAILED
            elif overall_status == "TIMED_OUT":
                db_status = ScanStatus.TIMED_OUT
            else:
                db_status = ScanStatus.FAILED

            # Bulk persist normalized findings
            finding_models = [
                Finding(
                    scan_session=session,
                    title=f.title,
                    description=f.description,
                    scanner_name=f.scanner_name,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    end_line_number=f.end_line_number,
                    remediation=f.remediation,
                    reference_urls=f.reference_urls,
                    fingerprint=f.fingerprint,
                    raw_details=f.raw_details,
                )
                for f in unified_findings
            ]

            if finding_models:
                Finding.objects.bulk_create(finding_models)

            session.status = db_status
            session.scanner_statuses = scanner_statuses
            session.completed_at = timezone.now()
            session.duration_seconds = round(duration, 3)
            session.recalculate_counts()
            session.save()

            return session

        except Exception as exc:
            logger.exception(f"Scan orchestration failed for session {session.id}: {exc}")
            session.status = ScanStatus.FAILED
            session.error_message = str(exc)
            session.completed_at = timezone.now()
            session.save(update_fields=["status", "error_message", "completed_at"])
            raise
