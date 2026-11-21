"""
Bandit Python AST security scanner adapter for Vulnora AI.

Performs static analysis of Python source code looking for common security issues
such as command injection, insecure deserialization, SQL injection, and weak cryptography.
Auto-gated on repositories containing Python files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext


class BanditScanner(BaseScanner):
    """
    Adapter for Bandit AST-based Python security analyzer.
    Auto-gated: only executes when Python files (.py, .pyi) exist in target.
    """

    scanner_name: str = "bandit"
    binary_name: str = "bandit"

    def should_run(self, context: ScanContext) -> bool:
        """Auto-gate: Only run if target contains Python source files."""
        return context.has_extension([".py", ".pyi"])

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        cmd = [
            self.executable,
            "-r",
            str(context.target_path),
            "-f",
            "json",
            "-q",
        ]

        proc = self.run_subprocess(cmd, cwd=context.target_path, timeout=context.timeout_seconds)

        # Bandit exit codes: 0 = clean, 1 = issues detected, 2+ = runtime error
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip() or proc.stdout.strip() or f"Bandit exited with code {proc.returncode}"
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.FAILED,
                error_message=err,
                raw_output=proc.stdout or proc.stderr,
            )

        findings: List[Finding] = []
        raw_output = proc.stdout.strip()

        if raw_output:
            try:
                data = json.loads(raw_output)
                raw_results = data.get("results", []) if isinstance(data, dict) else []
                findings = self._parse_findings(raw_results)
            except Exception as exc:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScanStatus.FAILED,
                    error_message=f"Failed to parse Bandit JSON output: {exc}",
                    raw_output=raw_output,
                )

        return ScannerResult(
            scanner_name=self.scanner_name,
            status=ScanStatus.COMPLETED,
            findings=findings,
            raw_output=raw_output,
        )

    def _parse_findings(self, raw_results: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for item in raw_results:
            test_id = str(item.get("test_id") or "B000")
            test_name = str(item.get("test_name") or test_id)
            issue_text = str(item.get("issue_text") or "Python security issue")
            filename = str(item.get("filename") or "")
            line_no = item.get("line_number")
            code_snippet = str(item.get("code") or "")

            raw_sev = str(item.get("issue_severity") or "MEDIUM").upper()
            if raw_sev == "HIGH":
                sev = Severity.HIGH
            elif raw_sev == "LOW":
                sev = Severity.LOW
            else:
                sev = Severity.MEDIUM

            more_info = str(item.get("more_info") or "")
            issue_cwe = item.get("issue_cwe", {})
            cwe_link = issue_cwe.get("link") if isinstance(issue_cwe, dict) else None

            ref_urls: List[str] = []
            if more_info:
                ref_urls.append(more_info)
            if cwe_link:
                ref_urls.append(str(cwe_link))

            findings.append(
                Finding(
                    title=f"Bandit: {test_name} ({test_id})",
                    description=issue_text,
                    scanner_name=self.scanner_name,
                    rule_id=test_id,
                    severity=sev,
                    file_path=filename,
                    line_number=int(line_no) if line_no is not None else None,
                    snippet=code_snippet,
                    remediation="Replace insecure API invocation with safer standard library or parameter-binding alternatives.",
                    reference_urls=ref_urls,
                    raw_details=item,
                    is_secret=False,
                )
            )
        return findings
