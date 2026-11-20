import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from django.utils import timezone

from apps.scans.models import Finding, ScanSession, ScanStatus, Severity
from .bandit import BanditScannerService
from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult
from .gitleaks import GitleaksScannerService
from .osv_scanner import OSVScannerService
from .semgrep import SemgrepScannerService

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    """
    Central orchestration engine for Vulnora AI security scanning.
    Discovers, schedules, and executes modular scanners (Gitleaks, Semgrep, Bandit, OSV-Scanner),
    aggregates and deduplicates findings, handles failures/timeouts, and records scan sessions.
    """

    def __init__(self):
        # Register the 4 core open-source scanners
        self.scanners: Dict[str, BaseScannerService] = {
            "gitleaks": GitleaksScannerService(),
            "semgrep": SemgrepScannerService(),
            "bandit": BanditScannerService(),
            "osv-scanner": OSVScannerService(),
        }

    def get_scanner_availability(self) -> Dict[str, Dict[str, Any]]:
        """Returns the availability and version of each registered scanner."""
        status_report = {}
        for name, service in self.scanners.items():
            installed = service.is_available()
            version = service.get_version() if installed else None
            status_report[name] = {
                "installed": installed,
                "executable": service.find_executable(),
                "version": version,
            }
        return status_report

    def validate_project_path(self, raw_path: str) -> Path:
        """
        Validates project path safety:
        - Resolves to canonical absolute path.
        - Verifies existence and directory type.
        - Prevents directory traversal attacks and scanning dangerous system roots.
        """
        if not raw_path or not isinstance(raw_path, str):
            raise ValueError("A valid project path string must be provided.")

        clean_path = raw_path.strip().strip("'\"")
        resolved = Path(clean_path).resolve()

        if not resolved.exists():
            raise FileNotFoundError(f"Project directory does not exist: '{resolved}'")

        if not resolved.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: '{resolved}'")

        # Disallow system root directories
        system_roots = {Path(p).resolve() for p in ("/", "/etc", "/var", "/usr", "/bin", "C:\\", "C:\\Windows")}
        if resolved in system_roots or str(resolved).lower() in ("c:\\", "c:\\windows", "/"):
            raise PermissionError("Scanning system root directories is strictly prohibited.")

        return resolved

    def run_scan(
        self,
        project_path: Path,
        scanners_to_run: Optional[List[str]] = None,
        timeout_seconds: int = 60,
        parallel: bool = True,
    ) -> Tuple[ScanStatus, Dict[str, Any], List[NormalizedFinding], float]:
        """
        Executes scanners against the validated project directory.
        Returns:
            (overall_status, scanner_statuses, unified_findings, total_duration)
        """
        start_time = time.time()

        # Determine target scanners
        if not scanners_to_run:
            target_scanners = list(self.scanners.keys())
        else:
            target_scanners = [s for s in scanners_to_run if s in self.scanners]

        if not target_scanners:
            raise ValueError(f"No valid scanners selected from available: {list(self.scanners.keys())}")

        scanner_results: Dict[str, ScannerExecutionResult] = {}

        if parallel and len(target_scanners) > 1:
            # Parallel execution across worker threads
            with ThreadPoolExecutor(max_workers=min(len(target_scanners), 4)) as executor:
                futures = {
                    executor.submit(self.scanners[name].scan, project_path, timeout_seconds): name
                    for name in target_scanners
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        scanner_results[name] = future.result()
                    except Exception as exc:
                        logger.error(f"Scanner '{name}' raised unhandled exception: {exc}")
                        scanner_results[name] = ScannerExecutionResult(
                            scanner_name=name,
                            status="FAILED",
                            error_message=str(exc),
                        )
        else:
            # Sequential execution
            for name in target_scanners:
                try:
                    scanner_results[name] = self.scanners[name].scan(project_path, timeout_seconds)
                except Exception as exc:
                    logger.error(f"Scanner '{name}' raised unhandled exception: {exc}")
                    scanner_results[name] = ScannerExecutionResult(
                        scanner_name=name,
                        status="FAILED",
                        error_message=str(exc),
                    )

        total_duration = time.time() - start_time

        # Track individual scanner statuses
        scanner_statuses = {name: res.to_dict() for name, res in scanner_results.items()}

        # Aggregate and deduplicate findings
        unified_findings, seen_fingerprints = [], set()

        for res in scanner_results.values():
            if res.status == "COMPLETED":
                for finding in res.findings:
                    # Deduplicate based on unique fingerprint
                    if finding.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(finding.fingerprint)
                        unified_findings.append(finding)

        # Determine overall scan session status
        statuses = [res.status for res in scanner_results.values()]
        if all(s == "COMPLETED" for s in statuses):
            overall_status = ScanStatus.COMPLETED
        elif any(s == "COMPLETED" for s in statuses):
            overall_status = ScanStatus.PARTIALLY_FAILED
        elif any(s == "TIMED_OUT" for s in statuses):
            overall_status = ScanStatus.TIMED_OUT
        else:
            overall_status = ScanStatus.FAILED

        return overall_status, scanner_statuses, unified_findings, total_duration

    def execute_and_record(
        self,
        raw_project_path: str,
        scanners_to_run: Optional[List[str]] = None,
        timeout_seconds: int = 60,
    ) -> ScanSession:
        """
        Validates input path, executes scan orchestrator, and persists results to the database.
        """
        validated_path = self.validate_project_path(raw_project_path)
        started_at = timezone.now()

        # Initialize ScanSession record
        session = ScanSession.objects.create(
            project_path=str(validated_path),
            status=ScanStatus.RUNNING,
            requested_scanners=scanners_to_run or list(self.scanners.keys()),
            started_at=started_at,
        )

        try:
            overall_status, scanner_statuses, unified_findings, duration = self.run_scan(
                project_path=validated_path,
                scanners_to_run=scanners_to_run,
                timeout_seconds=timeout_seconds,
            )

            # Persist normalized findings in bulk
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

            # Update session status and counts
            session.status = overall_status
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
