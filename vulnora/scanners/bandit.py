import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, List

from .base import BaseScannerService
from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class BanditScannerService(BaseScannerService):
    """
    Modular scanner service for Bandit.
    Identifies common security flaws and vulnerabilities in Python source code
    (e.g., eval/exec usage, hardcoded passwords, unsafe shell execution, insecure hashes, SQLi).
    """

    name = "bandit"
    executable_name = "bandit"

    def scan(self, project_path: Path, timeout_seconds: int = 60) -> ScannerExecutionResult:
        start_time = time.time()
        exe = self.find_executable()

        if not exe:
            return ScannerExecutionResult(
                scanner_name=self.name,
                status="NOT_INSTALLED",
                duration_seconds=0.0,
                error_message="Bandit executable not found on system.",
            )

        try:
            # Bandit recursive scan with JSON format and exit-zero to guarantee complete output
            cmd = [
                exe,
                "-r",
                str(project_path),
                "-f", "json",
                "--exit-zero",
                "-x", ".venv,venv,__pycache__,.git,node_modules",
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
                    logger.warning(f"Failed to parse Bandit JSON output: {err}")

            if proc.returncode == 0 or raw_json.get("results") is not None:
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
                error_msg = proc.stderr.strip() or f"Bandit exited with code {proc.returncode}"
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
                error_message=f"Bandit execution timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception(f"Unexpected error executing Bandit: {exc}")
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

        # Known critical test IDs (Remote code execution, command injection, SQL injection)
        critical_tests = {"B602", "B604", "B605", "B608", "B102"}

        for item in raw_data:
            if not isinstance(item, dict):
                continue

            test_id = item.get("test_id", "B000")
            test_name = item.get("test_name", "bandit_issue")
            issue_text = item.get("issue_text", "Bandit Python security issue")
            file_path = self.to_relative_path(item.get("filename", ""), project_path)
            line = item.get("line_number")
            line_range = item.get("line_range", [])
            end_line = line_range[-1] if line_range else line

            # Severity mapping
            raw_sev = (item.get("issue_severity") or "MEDIUM").upper()
            if test_id in critical_tests and raw_sev == "HIGH":
                severity = "CRITICAL"
            elif raw_sev in ("HIGH", "MEDIUM", "LOW"):
                severity = raw_sev
            else:
                severity = "MEDIUM"

            # Remediation guidance
            remediation = self._get_bandit_remediation(test_id, issue_text)

            # References
            references = []
            more_info = item.get("more_info")
            if more_info:
                references.append(more_info)

            cwe_info = item.get("issue_cwe", {})
            if isinstance(cwe_info, dict) and cwe_info.get("link"):
                references.append(cwe_info["link"])

            normalized.append(
                NormalizedFinding(
                    title=f"Python Security Issue: {test_name} ({test_id})",
                    description=issue_text,
                    scanner_name=self.name,
                    rule_id=test_id,
                    severity=severity,
                    file_path=file_path,
                    line_number=line,
                    end_line_number=end_line,
                    remediation=remediation,
                    reference_urls=references,
                    raw_details={
                        "test_id": test_id,
                        "test_name": test_name,
                        "confidence": item.get("issue_confidence"),
                        "cwe": cwe_info.get("id"),
                    },
                )
            )

        return normalized

    def _get_bandit_remediation(self, test_id: str, issue_text: str) -> str:
        advice_map = {
            "B101": "Do not rely on assert statements for data validation or access control in production.",
            "B102": "Avoid using exec(). Refactor code to eliminate dynamic code evaluation.",
            "B105": "Remove hardcoded passwords from source code and load via environment variables.",
            "B106": "Do not pass hardcoded passwords as function arguments.",
            "B107": "Do not set hardcoded passwords in default parameters.",
            "B307": "Replace eval() with ast.literal_eval() or a safe parser to prevent arbitrary code execution.",
            "B602": "Do not call subprocesses with shell=True. Pass argument lists and avoid untrusted shell input.",
            "B605": "Avoid starting processes with shell commands. Use subprocess.run() with arguments list.",
            "B608": "Use parameterized queries or ORM methods instead of building raw SQL queries with string formatting.",
        }
        return advice_map.get(test_id, f"Review flagged code and address {issue_text}")

