"""
Central Scanner Orchestrator for Vulnora AI.
Coordinates concurrent execution of SAST, SCA, Secrets, IaC, and DAST security scanners.
Pure Python architecture compatible with both local CLI and Django backend.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .bandit import BanditScannerService
from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult, ScanStatus, Severity
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

    CORE_SCANNERS = ["gitleaks", "semgrep", "bandit", "osv-scanner"]
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
        """Returns the availability, executable path, version, and install guide for each scanner."""
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

        clean_path = str(raw_path).strip().strip("'\"")
        resolved = Path(clean_path).resolve()

        if not resolved.exists():
            raise FileNotFoundError(f"Project directory does not exist: '{resolved}'")

        if not resolved.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: '{resolved}'")

        system_roots = {Path(p).resolve() for p in ("/", "/etc", "/var", "/usr", "/bin", "C:\\", "C:\\Windows")}
        if resolved in system_roots or str(resolved).lower() in ("c:\\", "c:\\windows", "/"):
            raise PermissionError("Scanning system root directories is strictly prohibited.")

        return resolved

    def validate_target_url(self, raw_url: Optional[str]) -> Optional[str]:
        """
        Validates target URL safety for DAST scans:
        - Ensures HTTP or HTTPS scheme.
        - Ensures valid hostname is present.
        """
        if not raw_url:
            return None

        clean_url = str(raw_url).strip()
        parsed = urlparse(clean_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid target URL scheme: '{parsed.scheme}'. Only http:// and https:// are supported.")

        if not parsed.netloc:
            raise ValueError(f"Invalid target URL: '{clean_url}'. Target must contain a valid hostname and port.")

        return clean_url

    def run_scan(
        self,
        project_path: Optional[Path] = None,
        target_url: Optional[str] = None,
        scanners_to_run: Optional[List[str]] = None,
        timeout_seconds: int = 60,
        parallel: bool = True,
    ) -> Tuple[str, Dict[str, Any], List[NormalizedFinding], float]:
        """
        Executes scanners against the project directory and/or target web application URL.
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
            # Map aliases e.g. 'osv' -> 'osv-scanner'
            resolved_names = []
            for s in scanners_to_run:
                norm = s.strip().lower()
                if norm == "osv":
                    norm = "osv-scanner"
                if norm in self.scanners:
                    resolved_names.append(norm)
            target_scanners = resolved_names

        if not target_scanners:
            raise ValueError(f"No valid scanners selected. Available scanners: {list(self.scanners.keys())}")

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
                        status=ScanStatus.FAILED,
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
                            status=ScanStatus.FAILED,
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
                        status=ScanStatus.FAILED,
                        error_message=str(exc),
                    )

        total_duration = time.time() - start_time
        scanner_statuses = {name: res.to_dict() for name, res in scanner_results.items()}

        # Aggregate and deduplicate findings using SHA-256 fingerprints
        unified_findings: List[NormalizedFinding] = []
        seen_fingerprints: Set[str] = set()

        for res in scanner_results.values():
            if res.status == ScanStatus.COMPLETED:
                for finding in res.findings:
                    if finding.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(finding.fingerprint)
                        unified_findings.append(finding)

        # Sort findings by severity (CRITICAL down to INFO)
        unified_findings.sort(key=lambda f: Severity.ORDER.get(f.severity, 0), reverse=True)

        # Determine overall scan session status
        statuses = [res.status for res in scanner_results.values()]
        if all(s == ScanStatus.COMPLETED for s in statuses):
            overall_status = ScanStatus.COMPLETED
        elif any(s == ScanStatus.COMPLETED for s in statuses):
            overall_status = ScanStatus.PARTIAL
        else:
            overall_status = ScanStatus.FAILED

        return overall_status, scanner_statuses, unified_findings, total_duration

    def calculate_severity_counts(self, findings: List[NormalizedFinding]) -> Dict[str, int]:
        """Calculates count breakdown by severity."""
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
            "total": len(findings),
        }
        for f in findings:
            sev = Severity.normalize(f.severity)
            if sev in counts:
                counts[sev] += 1
            else:
                counts[Severity.INFO] += 1
        return counts

