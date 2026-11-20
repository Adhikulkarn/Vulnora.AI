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
from .trivy import TrivyScannerService
from .zap import OWASPZAPScannerService

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    """
    Central orchestration engine for Vulnora AI security scanning.
    Manages and coordinates 6 modular security tools:
      1. Gitleaks (Secrets detection)
      2. Semgrep (Multi-language SAST)
      3. Bandit (Python source code SAST)
      4. OSV-Scanner (Known dependency vulnerabilities)
      5. Trivy (Containers, dependencies & IaC misconfigurations)
      6. OWASP ZAP (Dynamic Application Security Testing / DAST)
    """

    DEFAULT_FILESYSTEM_SCANNERS = ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy"]

    def __init__(self):
        self.scanners: Dict[str, BaseScannerService] = {
            "gitleaks": GitleaksScannerService(),
            "semgrep": SemgrepScannerService(),
            "bandit": BanditScannerService(),
            "osv-scanner": OSVScannerService(),
            "trivy": TrivyScannerService(),
            "zap": OWASPZAPScannerService(),
        }

    def get_scanner_availability(self) -> Dict[str, Dict[str, Any]]:
        """Returns the availability, version, and installation guide for each registered scanner."""
        status_report = {}
        for name, service in self.scanners.items():
            installed = service.is_available()
            version = service.get_version() if installed else None
            instructions = getattr(service, "INSTALLATION_INSTRUCTIONS", f"Install '{name}' using your system package manager.")

            status_report[name] = {
                "installed": installed,
                "executable": service.find_executable(),
                "version": version,
                "installation_instructions": instructions if not installed else None,
            }
        return status_report

    def validate_project_path(self, raw_path: Optional[str]) -> Optional[Path]:
        """
        Validates project path safety:
        - Resolves to canonical absolute path.
        - Verifies existence and directory type.
        - Prevents directory traversal attacks and scanning dangerous system roots.
        """
        if not raw_path:
            return None

        clean_path = raw_path.strip().strip("'\"")
        resolved = Path(clean_path).resolve()

        if not resolved.exists():
            raise FileNotFoundError(f"Project directory does not exist: '{resolved}'")

        if not resolved.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: '{resolved}'")

        system_roots = {Path(p).resolve() for p in ("/", "/etc", "/var", "/usr", "/bin", "C:\\", "C:\\Windows")}
        if resolved in system_roots or str(resolved).lower() in ("c:\\", "c:\\windows", "/"):
            raise PermissionError("Scanning system root directories is strictly prohibited.")

        return resolved

    def run_scan(
        self,
        project_path: Optional[Path] = None,
        target_url: Optional[str] = None,
        scanners_to_run: Optional[List[str]] = None,
        timeout_seconds: int = 60,
        parallel: bool = True,
    ) -> Tuple[ScanStatus, Dict[str, Any], List[NormalizedFinding], float]:
        """
        Executes scanners against the validated project directory and/or target web application URL.
        Returns:
            (overall_status, scanner_statuses, unified_findings, total_duration)
        """
        start_time = time.time()

        # Determine target scanners
        if not scanners_to_run:
            if target_url and not project_path:
                target_scanners = ["zap"]
            elif target_url and project_path:
                target_scanners = list(self.scanners.keys())
            else:
                target_scanners = list(self.DEFAULT_FILESYSTEM_SCANNERS)
        else:
            target_scanners = [s for s in scanners_to_run if s in self.scanners]

        if not target_scanners:
            raise ValueError(f"No valid scanners selected from available: {list(self.scanners.keys())}")

        scanner_results: Dict[str, ScannerExecutionResult] = {}

        def _execute_scanner(scanner_name: str) -> ScannerExecutionResult:
            service = self.scanners[scanner_name]
            if scanner_name == "zap":
                return service.scan(
                    project_path=project_path,
                    timeout_seconds=timeout_seconds,
                    target_url=target_url,
                )
            else:
                if not project_path:
                    return ScannerExecutionResult(
                        scanner_name=scanner_name,
                        status="FAILED",
                        error_message="Filesystem scanning requires a valid project_path.",
                    )
                return service.scan(project_path, timeout_seconds)

        if parallel and len(target_scanners) > 1:
            with ThreadPoolExecutor(max_workers=min(len(target_scanners), 6)) as executor:
                futures = {
                    executor.submit(_execute_scanner, name): name
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
            for name in target_scanners:
                try:
                    scanner_results[name] = _execute_scanner(name)
                except Exception as exc:
                    logger.error(f"Scanner '{name}' raised unhandled exception: {exc}")
                    scanner_results[name] = ScannerExecutionResult(
                        scanner_name=name,
                        status="FAILED",
                        error_message=str(exc),
                    )

        total_duration = time.time() - start_time
        scanner_statuses = {name: res.to_dict() for name, res in scanner_results.items()}

        # Aggregate and deduplicate findings
        unified_findings, seen_fingerprints = [], set()

        for res in scanner_results.values():
            if res.status == "COMPLETED":
                for finding in res.findings:
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
        started_at = timezone.now()

        # Initialize ScanSession record
        session = ScanSession.objects.create(
            project_path=str(validated_path) if validated_path else "",
            target_url=target_url.strip() if target_url else "",
            status=ScanStatus.RUNNING,
            requested_scanners=scanners_to_run or (
                list(self.scanners.keys()) if (validated_path and target_url) else
                (["zap"] if target_url and not validated_path else list(self.DEFAULT_FILESYSTEM_SCANNERS))
            ),
            started_at=started_at,
        )

        try:
            overall_status, scanner_statuses, unified_findings, duration = self.run_scan(
                project_path=validated_path,
                target_url=target_url,
                scanners_to_run=scanners_to_run,
                timeout_seconds=timeout_seconds,
            )

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
