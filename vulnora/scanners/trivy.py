import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, List, Optional

from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class TrivyScannerService(BaseScannerService):
    """
    Modular scanner service for Aqua Security Trivy.
    Performs comprehensive security auditing across:
    - Filesystem & software dependencies (pip, npm, composer, go, etc.)
    - Configuration & Infrastructure-as-Code files (Dockerfile, Kubernetes, Terraform, CloudFormation)
    - Container images (when requested)
    """

    name = "trivy"
    executable_name = "trivy"

    INSTALLATION_INSTRUCTIONS = (
        "Trivy is not installed or not in PATH.\n"
        "To install Trivy:\n"
        "  - Windows (winget): 'winget install AquaSecurity.Trivy'\n"
        "  - macOS (Homebrew): 'brew install aquasecurity/trivy/trivy'\n"
        "  - Linux (Debian/Ubuntu): 'sudo apt-get install trivy' (via Aqua repo)\n"
        "  - Direct Binary: https://github.com/aquasecurity/trivy/releases"
    )

    def scan(
        self,
        project_path: Path,
        timeout_seconds: int = 90,
        scanners_enabled: str = "vuln,misconfig",
    ) -> ScannerExecutionResult:
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message=self.INSTALLATION_INSTRUCTIONS,
            )

        try:
            # Trivy filesystem scan with JSON output and disabled updates for speed & safety
            cmd = [
                exe,
                "fs",
                "--format", "json",
                "--scanners", scanners_enabled,
                "--quiet",
                "--skip-version-check",
                "--exit-code", "0",
                str(project_path),
            ]

            proc = self._run_subprocess(cmd, timeout_seconds=timeout_seconds, cwd=project_path)
            duration = time.time() - start_time

            raw_json = {}
            stdout_str = proc.stdout.strip()
            json_start = stdout_str.find("{")
            json_end = stdout_str.rfind("}")

            if json_start != -1 and json_end != -1 and json_end > json_start:
                try:
                    raw_json = json.loads(stdout_str[json_start : json_end + 1])
                except json.JSONDecodeError as err:
                    logger.warning(f"Failed to parse Trivy JSON output: {err}")

            if proc.returncode == 0:
                results = raw_json.get("Results", [])
                normalized = self.normalize(results, project_path)
                return ScannerExecutionResult(
                    scanner_name=self.name,
                    status="COMPLETED",
                    duration_seconds=duration,
                    findings=normalized,
                    raw_output=results,
                )
            else:
                error_msg = proc.stderr.strip() or f"Trivy exited with code {proc.returncode}"
                return ScannerExecutionResult(
                    scanner_name=self.name,
                    status="FAILED",
                    duration_seconds=duration,
                    error_message=error_msg,
                )

        except subprocess.TimeoutExpired:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="TIMED_OUT",
                duration_seconds=time.time() - start_time,
                error_message=f"Trivy execution timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception(f"Unexpected error executing Trivy: {exc}")
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="FAILED",
                duration_seconds=time.time() - start_time,
                error_message=str(exc),
            )

    def scan_image(
        self,
        image_name: str,
        timeout_seconds: int = 120,
    ) -> ScannerExecutionResult:
        """
        Scans a container image for vulnerabilities and misconfigurations.
        """
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message=self.INSTALLATION_INSTRUCTIONS,
            )

        try:
            cmd = [
                exe,
                "image",
                "--format", "json",
                "--quiet",
                "--skip-version-check",
                image_name,
            ]
            proc = self._run_subprocess(cmd, timeout_seconds=timeout_seconds)
            duration = time.time() - start_time

            raw_json = {}
            stdout_str = proc.stdout.strip()
            json_start = stdout_str.find("{")
            json_end = stdout_str.rfind("}")
            if json_start != -1 and json_end != -1 and json_end > json_start:
                try:
                    raw_json = json.loads(stdout_str[json_start : json_end + 1])
                except json.JSONDecodeError:
                    pass

            results = raw_json.get("Results", [])
            normalized = self.normalize(results, Path("."))
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="COMPLETED" if proc.returncode == 0 else "FAILED",
                duration_seconds=duration,
                findings=normalized,
                raw_output=results,
            )
        except Exception as exc:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="FAILED",
                duration_seconds=time.time() - start_time,
                error_message=str(exc),
            )

    def normalize(self, raw_data: Any, project_path: Path) -> List[NormalizedFinding]:
        if not isinstance(raw_data, list):
            return []

        normalized: List[NormalizedFinding] = []

        for target_result in raw_data:
            if not isinstance(target_result, dict):
                continue

            target_file = target_result.get("Target", "unknown-target")
            rel_target = self.to_relative_path(target_file, project_path)

            # 1. Process Vulnerabilities (Dependencies & Software Packages)
            vulnerabilities = target_result.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                vuln_id = vuln.get("VulnerabilityID", "TRIVY-VULN")
                pkg_name = vuln.get("PkgName", "unknown-package")
                installed_ver = vuln.get("InstalledVersion", "unknown")
                fixed_ver = vuln.get("FixedVersion")

                title = vuln.get("Title") or f"Vulnerable Package: {pkg_name}@{installed_ver} ({vuln_id})"
                desc = vuln.get("Description") or title

                raw_sev = (vuln.get("Severity") or "MEDIUM").upper()
                severity = self._map_severity(raw_sev)

                remediation = (
                    f"Upgrade {pkg_name} (installed: {installed_ver}) to version {fixed_ver} or higher."
                    if fixed_ver
                    else f"Review security advisory for {pkg_name} ({vuln_id}) and apply upstream vendor patches."
                )

                references = []
                primary_url = vuln.get("PrimaryURL")
                if primary_url:
                    references.append(primary_url)
                for ref in vuln.get("References", []):
                    if ref and ref not in references:
                        references.append(ref)

                normalized.append(
                    NormalizedFinding(
                        title=title,
                        description=desc[:1000],
                        scanner_name=self.name,
                        rule_id=vuln_id,
                        severity=severity,
                        file_path=rel_target,
                        line_number=None,
                        end_line_number=None,
                        remediation=remediation,
                        reference_urls=references[:5],
                        raw_details={
                            "package": pkg_name,
                            "installed_version": installed_ver,
                            "fixed_version": fixed_ver,
                            "cvss": vuln.get("CVSS"),
                        },
                    )
                )

            # 2. Process Misconfigurations (IaC, Dockerfile, Terraform, Kubernetes)
            misconfigurations = target_result.get("Misconfigurations", [])
            for misconfig in misconfigurations:
                rule_id = misconfig.get("ID", "TRIVY-MISCONFIG")
                title = misconfig.get("Title") or f"Misconfiguration detected in {rel_target} ({rule_id})"
                desc = misconfig.get("Description") or misconfig.get("Message") or title

                raw_sev = (misconfig.get("Severity") or "MEDIUM").upper()
                severity = self._map_severity(raw_sev)

                remediation = misconfig.get("Resolution") or "Review and correct the configuration according to best security practices."

                cause = misconfig.get("CauseMetadata", {})
                start_line = cause.get("StartLine")
                end_line = cause.get("EndLine")

                references = []
                primary_url = misconfig.get("PrimaryURL")
                if primary_url:
                    references.append(primary_url)
                for ref in misconfig.get("References", []):
                    if ref and ref not in references:
                        references.append(ref)

                normalized.append(
                    NormalizedFinding(
                        title=f"Configuration Flaw: {title}",
                        description=desc[:1000],
                        scanner_name=self.name,
                        rule_id=rule_id,
                        severity=severity,
                        file_path=rel_target,
                        line_number=start_line,
                        end_line_number=end_line,
                        remediation=remediation,
                        reference_urls=references[:5],
                        raw_details={
                            "type": misconfig.get("Type"),
                            "status": misconfig.get("Status"),
                            "message": misconfig.get("Message"),
                        },
                    )
                )

        return normalized

    def _map_severity(self, raw_sev: str) -> str:
        sev_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "INFO",
            "INFORMATIONAL": "INFO",
        }
        return sev_map.get(raw_sev, "MEDIUM")

