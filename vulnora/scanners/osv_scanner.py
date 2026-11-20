import json
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, List, Optional

from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class OSVScannerService(BaseScannerService):
    """
    Modular scanner service for OSV-Scanner (Open Source Vulnerability Scanner).
    Audits project dependencies against the Google Open Source Vulnerabilities database
    (supporting Python requirements.txt, package-lock.json, poetry.lock, Pipfile, go.mod, etc.).
    """

    name = "osv-scanner"
    executable_name = "osv-scanner"

    # Common dependency manifests and lockfiles to target directly
    KNOWN_MANIFESTS = [
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile.lock",
        "poetry.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Gemfile.lock",
        "go.mod",
        "pom.xml",
    ]

    def scan(self, project_path: Path, timeout_seconds: int = 60) -> ScannerExecutionResult:
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message="OSV-Scanner executable not found on system.",
            )

        try:
            # Locate any specific dependency manifests/lockfiles in the project
            manifest_args = []
            for item in project_path.rglob("*"):
                # Exclude virtual environments and hidden dirs
                parts = item.parts
                if any(p.startswith(".") or p in ("venv", ".venv", "node_modules", "__pycache__") for p in parts):
                    continue
                if item.is_file() and (item.name in self.KNOWN_MANIFESTS or item.name.startswith("requirements")):
                    manifest_args.extend(["-L", str(item)])

            # Base command
            cmd = [
                exe,
                "scan",
                "source",
                "--format", "json",
                "--no-call-analysis",
                "--allow-no-lockfiles",
            ]

            if manifest_args:
                cmd.extend(manifest_args)
            else:
                # If no manifest found, run recursive directory scan
                cmd.extend(["-r", str(project_path)])

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
                    logger.warning(f"Failed to parse OSV-Scanner JSON output: {err}")

            # Exit code 0 (clean) or 1 (vulnerabilities found) are successful scan states
            if proc.returncode in (0, 1):
                results = raw_json.get("results", [])
                normalized = self.normalize(results, project_path)
                return ScannerExecutionResult(
                    scanner_name=self.name,
                    status="COMPLETED",
                    duration_seconds=duration,
                    findings=normalized,
                    raw_output=results,
                )
            else:
                error_msg = proc.stderr.strip() or f"OSV-Scanner exited with code {proc.returncode}"
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
                error_message=f"OSV-Scanner execution timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception(f"Unexpected error executing OSV-Scanner: {exc}")
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

        for source_entry in raw_data:
            if not isinstance(source_entry, dict):
                continue

            source_info = source_entry.get("source", {})
            raw_source_path = source_info.get("path", "")
            file_path = self.to_relative_path(raw_source_path, project_path)

            packages = source_entry.get("packages", [])
            for pkg_entry in packages:
                pkg_info = pkg_entry.get("package", {})
                pkg_name = pkg_info.get("name", "unknown-package")
                pkg_ver = pkg_info.get("version", "unknown-version")
                vulnerabilities = pkg_entry.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    vuln_id = vuln.get("id", "OSV-VULN")
                    summary = vuln.get("summary") or f"Vulnerability {vuln_id} affecting {pkg_name}"
                    details = vuln.get("details") or summary

                    severity = self._determine_severity(vuln)
                    fixed_version = self._find_fixed_version(vuln)

                    remediation = (
                        f"Upgrade {pkg_name} (currently {pkg_ver}) to version {fixed_version} or higher."
                        if fixed_version
                        else f"Upgrade {pkg_name} (currently {pkg_ver}) to a patched release addressing {vuln_id}."
                    )

                    # Gather reference URLs
                    references = []
                    for ref in vuln.get("references", []):
                        if isinstance(ref, dict) and ref.get("url"):
                            references.append(ref["url"])

                    normalized.append(
                        NormalizedFinding(
                            title=f"Vulnerable Dependency: {pkg_name}@{pkg_ver} ({vuln_id})",
                            description=details[:1000],  # Truncate overly long advisory text
                            scanner_name=self.name,
                            rule_id=vuln_id,
                            severity=severity,
                            file_path=file_path or "dependencies",
                            line_number=None,
                            end_line_number=None,
                            remediation=remediation,
                            reference_urls=references[:5],
                            raw_details={
                                "package": pkg_name,
                                "version": pkg_ver,
                                "aliases": vuln.get("aliases", []),
                                "fixed_version": fixed_version,
                            },
                        )
                    )

        return normalized

    def _determine_severity(self, vuln_dict: dict) -> str:
        """Extracts and normalizes vulnerability severity from CVSS or database_specific."""
        # 1. Check CVSS scores
        for sev in vuln_dict.get("severity", []):
            score_str = sev.get("score", "")
            # Example CVSS vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            # Or numeric score
            if isinstance(score_str, (int, float)):
                val = float(score_str)
                if val >= 9.0:
                    return "CRITICAL"
                if val >= 7.0:
                    return "HIGH"
                if val >= 4.0:
                    return "MEDIUM"
                return "LOW"

        # 2. Check database_specific severity
        db_specific = vuln_dict.get("database_specific", {})
        db_sev = (db_specific.get("severity") or "").upper()
        if "CRITICAL" in db_sev:
            return "CRITICAL"
        if "HIGH" in db_sev:
            return "HIGH"
        if "MODERATE" in db_sev or "MEDIUM" in db_sev:
            return "MEDIUM"
        if "LOW" in db_sev:
            return "LOW"

        # 3. Default to HIGH for known CVEs
        return "HIGH"

    def _find_fixed_version(self, vuln_dict: dict) -> Optional[str]:
        """Inspects affected ranges to locate the fixed version string."""
        for affected in vuln_dict.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return str(event["fixed"])
        return None

