import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, List

from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class GitleaksScannerService(BaseScannerService):
    """
    Modular scanner service for Gitleaks.
    Detects hardcoded secrets, API keys, private keys, passwords, and tokens.
    Guarantees secret values are masked and never exposed in logs or API responses.
    """

    name = "gitleaks"
    executable_name = "gitleaks"

    def scan(self, project_path: Path, timeout_seconds: int = 60) -> ScannerExecutionResult:
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message="Gitleaks executable not found on system.",
            )

        # Temporary file for JSON report output
        temp_report = tempfile.NamedTemporaryFile(
            mode="w+",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        )
        temp_report_path = temp_report.name
        temp_report.close()

        try:
            # Gitleaks command: dir scan with 100% redaction and JSON output
            # Note: Gitleaks exits with 1 when leaks are found, 0 when clean.
            cmd = [
                exe,
                "dir",
                "--no-banner",
                "--redact",
                "--report-format", "json",
                "--report-path", temp_report_path,
                "-v",
                str(project_path),
            ]

            proc = self._run_subprocess(cmd, timeout_seconds=timeout_seconds, cwd=project_path)
            duration = time.time() - start_time

            # Check if report was generated
            raw_findings = []
            if os.path.exists(temp_report_path) and os.path.getsize(temp_report_path) > 0:
                with open(temp_report_path, "r", encoding="utf-8") as f:
                    try:
                        raw_findings = json.load(f)
                    except json.JSONDecodeError:
                        raw_findings = []
            elif proc.stdout:
                # Fallback: extract JSON array from stdout if present
                stdout_str = proc.stdout.strip()
                start_idx = stdout_str.find("[")
                end_idx = stdout_str.rfind("]")
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        raw_findings = json.loads(stdout_str[start_idx : end_idx + 1])
                    except json.JSONDecodeError:
                        raw_findings = []

            # Exit code 0 (clean) or 1 (leaks found) are valid completion states
            if proc.returncode in (0, 1):
                normalized = self.normalize(raw_findings, project_path)
                return ScannerExecutionResult(
                    scanner_name=self.name,
                    status="COMPLETED",
                    duration_seconds=duration,
                    findings=normalized,
                    raw_output=raw_findings,
                )
            else:
                error_msg = proc.stderr.strip() or f"Gitleaks exited with code {proc.returncode}"
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
                error_message=f"Gitleaks execution timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception(f"Unexpected error executing Gitleaks: {exc}")
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="FAILED",
                duration_seconds=time.time() - start_time,
                error_message=str(exc),
            )
        finally:
            if os.path.exists(temp_report_path):
                try:
                    os.remove(temp_report_path)
                except OSError:
                    pass

    def normalize(self, raw_data: Any, project_path: Path) -> List[NormalizedFinding]:
        if not isinstance(raw_data, list):
            return []

        normalized: List[NormalizedFinding] = []

        # High-risk secret types mapped to CRITICAL
        critical_rule_keywords = ["private-key", "aws", "gcp", "azure", "github", "slack", "password"]

        for item in raw_data:
            if not isinstance(item, dict):
                continue

            rule_id = item.get("RuleID", "generic-secret")
            desc = item.get("Description") or f"Exposed sensitive secret matching rule '{rule_id}'"
            file_path = self.to_relative_path(item.get("File", ""), project_path)
            line = item.get("StartLine")
            end_line = item.get("EndLine")

            # Determine severity
            rule_lower = rule_id.lower()
            if any(k in rule_lower for k in critical_rule_keywords):
                severity = "CRITICAL"
            else:
                severity = "HIGH"

            remediation = (
                "Revoke and rotate the exposed secret immediately. Remove the sensitive value "
                "from source code and configuration files, and store credentials securely using "
                "environment variables (.env) or a secret manager (e.g., Vault, AWS Secrets Manager)."
            )

            # Sanitize raw details: NEVER leak raw secret strings
            safe_raw = {
                "rule_id": rule_id,
                "file": file_path,
                "start_line": line,
                "end_line": end_line,
                "entropy": item.get("Entropy"),
                "secret_masked": "***REDACTED***",
            }

            normalized.append(
                NormalizedFinding(
                    title=f"Hardcoded Secret ({rule_id})",
                    description=desc,
                    scanner_name=self.name,
                    rule_id=rule_id,
                    severity=severity,
                    file_path=file_path,
                    line_number=line,
                    end_line_number=end_line,
                    remediation=remediation,
                    reference_urls=[
                        "https://github.com/gitleaks/gitleaks",
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                    ],
                    raw_details=safe_raw,
                )
            )

        return normalized

