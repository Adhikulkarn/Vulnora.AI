import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, List

from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class SemgrepScannerService(BaseScannerService):
    """
    Modular scanner service for Semgrep.
    Detects security vulnerabilities, dangerous APIs, and insecure coding patterns
    across Python, JavaScript, TypeScript, Go, Java, and other supported languages.
    """

    name = "semgrep"
    executable_name = "semgrep"

    def scan(self, project_path: Path, timeout_seconds: int = 90) -> ScannerExecutionResult:
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message="Semgrep executable not found on system.",
            )

        try:
            # Semgrep command with p/default security rules, JSON output, disabled metrics
            cmd = [
                exe,
                "scan",
                "--config", "p/default",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                str(project_path),
            ]

            proc = self._run_subprocess(cmd, timeout_seconds=timeout_seconds, cwd=project_path)
            duration = time.time() - start_time

            # Semgrep exit status:
            # 0: Completed, no findings
            # 1: Completed, findings detected
            # 2+: Fatal error
            if proc.returncode in (0, 1):
                raw_json = {}
                stdout_str = proc.stdout.strip()

                # Semgrep may prepend banner lines before JSON output
                json_start = stdout_str.find("{")
                json_end = stdout_str.rfind("}")
                if json_start != -1 and json_end != -1 and json_end > json_start:
                    try:
                        raw_json = json.loads(stdout_str[json_start : json_end + 1])
                    except json.JSONDecodeError as err:
                        logger.warning(f"Failed to parse Semgrep JSON output: {err}")

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
                error_msg = proc.stderr.strip() or f"Semgrep failed with exit code {proc.returncode}"
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
                error_message=f"Semgrep execution timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception(f"Unexpected error executing Semgrep: {exc}")
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

        for item in raw_data:
            if not isinstance(item, dict):
                continue

            check_id = item.get("check_id", "semgrep-finding")
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})

            # Map Semgrep severity
            raw_severity = (extra.get("severity") or "WARNING").upper()
            if raw_severity in ("ERROR", "CRITICAL"):
                severity = "HIGH"
            elif raw_severity in ("WARNING", "WARN"):
                severity = "MEDIUM"
            elif raw_severity in ("INFO", "INFORMATIONAL"):
                severity = "LOW"
            else:
                severity = "MEDIUM"

            # Upgrade to CRITICAL if metadata explicitly marks impact as HIGH and likelihood HIGH
            if metadata.get("impact") == "HIGH" and metadata.get("likelihood") == "HIGH":
                severity = "CRITICAL"

            # Extract location
            file_path = self.to_relative_path(item.get("path", ""), project_path)
            start_pos = item.get("start", {})
            end_pos = item.get("end", {})
            line_num = start_pos.get("line")
            end_line_num = end_pos.get("line")

            # Extract title & description
            message = extra.get("message", "Semgrep security finding").strip()
            # Generate concise title from check_id (e.g. eval-detected)
            rule_short = check_id.split(".")[-1].replace("-", " ").title()
            title = f"{rule_short} ({check_id})"

            # Extract remediation and references
            remediation = extra.get("fix") or ""
            if not remediation:
                cwe_list = metadata.get("cwe", [])
                cwe_str = f" [CWE: {', '.join(cwe_list)}]" if cwe_list else ""
                remediation = f"Refactor code to mitigate potential security risk identified by rule {check_id}.{cwe_str}"

            references = list(metadata.get("references", []))
            rule_url = metadata.get("source")
            if rule_url and rule_url not in references:
                references.append(rule_url)

            normalized.append(
                NormalizedFinding(
                    title=title,
                    description=message,
                    scanner_name=self.name,
                    rule_id=check_id,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    end_line_number=end_line_num,
                    remediation=remediation,
                    reference_urls=references,
                    raw_details={
                        "check_id": check_id,
                        "category": metadata.get("category"),
                        "owasp": metadata.get("owasp"),
                        "cwe": metadata.get("cwe"),
                        "technology": metadata.get("technology"),
                    },
                )
            )

        return normalized

