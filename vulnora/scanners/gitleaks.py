"""
Gitleaks secret scanner adapter for Vulnora AI.

Scans repositories for exposed secrets, hardcoded API keys, private keys, and tokens
across all programming languages and file types.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext


class GitleaksScanner(BaseScanner):
    """
    Adapter for Gitleaks secrets detection engine.
    Applies universally across all languages.
    """

    scanner_name: str = "gitleaks"
    binary_name: str = "gitleaks"

    def should_run(self, context: ScanContext) -> bool:
        """Secrets can appear in any language or configuration file."""
        return True

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = Path(tmp.name)

        try:
            cmd = [
                self.executable,
                "dir",
                "--path",
                str(context.target_path),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
            ]

            proc = self.run_subprocess(cmd, cwd=context.target_path, timeout=context.timeout_seconds)

            # Gitleaks exit codes: 0 = no leaks, 1 = leaks found, 2+ = runtime error
            if proc.returncode not in (0, 1):
                err = proc.stderr.strip() or proc.stdout.strip() or f"Gitleaks exited with code {proc.returncode}"
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScanStatus.FAILED,
                    error_message=err,
                    raw_output=proc.stdout or proc.stderr,
                )

            findings: List[Finding] = []
            if report_path.exists() and report_path.stat().st_size > 0:
                try:
                    content = report_path.read_text(encoding="utf-8")
                    data = json.loads(content)
                    if isinstance(data, list):
                        findings = self._parse_findings(data)
                except Exception as exc:
                    return ScannerResult(
                        scanner_name=self.scanner_name,
                        status=ScanStatus.FAILED,
                        error_message=f"Failed to parse Gitleaks report JSON: {exc}",
                        raw_output=proc.stdout,
                    )

            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.COMPLETED,
                findings=findings,
                raw_output=proc.stdout,
            )
        finally:
            if report_path.exists():
                try:
                    report_path.unlink()
                except Exception:
                    pass

    def _parse_findings(self, raw_items: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for item in raw_items:
            rule_id = str(item.get("RuleID") or "secret-detected")
            description = str(item.get("Description") or f"Exposed secret ({rule_id})")
            file_path = str(item.get("File") or "")
            line_no = item.get("StartLine")
            end_line_no = item.get("EndLine")
            secret_match = str(item.get("Match") or "")
            secret_value = str(item.get("Secret") or "")

            # Mask snippet for safety
            snippet = secret_match
            if secret_value and len(secret_value) > 4:
                masked = secret_value[:2] + ("*" * (len(secret_value) - 4)) + secret_value[-2:]
                snippet = snippet.replace(secret_value, masked)

            # Secrets are high/critical severity
            sev = Severity.CRITICAL if any(k in rule_id.lower() for k in ("key", "token", "pass", "cred", "secret")) else Severity.HIGH

            findings.append(
                Finding(
                    title=f"Secret Leak: {description}",
                    description=description,
                    scanner_name=self.scanner_name,
                    rule_id=rule_id,
                    severity=sev,
                    file_path=file_path,
                    line_number=int(line_no) if line_no is not None else None,
                    end_line_number=int(end_line_no) if end_line_no is not None else None,
                    snippet=snippet,
                    remediation="Revoke the exposed secret or API key immediately, rotate credentials, and load sensitive values from environment variables or secrets vaults.",
                    reference_urls=["https://github.com/gitleaks/gitleaks"],
                    raw_details=item,
                    is_secret=True,
                )
            )
        return findings
