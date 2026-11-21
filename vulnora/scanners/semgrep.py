"""
Semgrep multi-language SAST adapter for Vulnora AI.

Executes Static Application Security Testing rules across Python, Go, Rust,
JavaScript, TypeScript, Java, C/C++, and other polyglot codebases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext


class SemgrepScanner(BaseScanner):
    """
    Adapter for Semgrep multi-language AST-based security rule scanner.
    """

    scanner_name: str = "semgrep"
    binary_name: str = "semgrep"

    def should_run(self, context: ScanContext) -> bool:
        """Semgrep applies across all languages and codebases."""
        return True

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        cmd = [
            self.executable,
            "scan",
            "--config",
            "auto",
            "--json",
            "--quiet",
            str(context.target_path),
        ]

        proc = self.run_subprocess(cmd, cwd=context.target_path, timeout=context.timeout_seconds)

        # Semgrep exit codes: 0 = clean, 1 = findings found, 2+ = fatal execution error
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip() or proc.stdout.strip() or f"Semgrep exited with code {proc.returncode}"
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
                    error_message=f"Failed to parse Semgrep JSON output: {exc}",
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
            check_id = str(item.get("check_id") or "semgrep-rule")
            file_path = str(item.get("path") or "")
            start = item.get("start", {})
            end = item.get("end", {})
            start_line = start.get("line") if isinstance(start, dict) else None
            end_line = end.get("line") if isinstance(end, dict) else None

            extra = item.get("extra", {}) if isinstance(item.get("extra"), dict) else {}
            message = str(extra.get("message") or check_id)
            title = message.splitlines()[0] if message else check_id

            raw_sev = str(extra.get("severity") or "WARNING").upper()
            if raw_sev == "ERROR":
                # Check for critical vulnerability categories in metadata
                meta = extra.get("metadata", {})
                cwe_list = meta.get("cwe", []) if isinstance(meta, dict) else []
                cwe_str = " ".join(str(c) for c in cwe_list).lower()
                sev = Severity.CRITICAL if any(kw in cwe_str for kw in ("injection", "rce", "exec")) else Severity.HIGH
            elif raw_sev in ("WARNING", "WARN"):
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            snippet = str(extra.get("lines") or "")
            meta_dict = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
            refs = meta_dict.get("references", [])
            ref_urls = [str(r) for r in refs if isinstance(r, str)] if isinstance(refs, list) else []

            findings.append(
                Finding(
                    title=f"SAST: {title}",
                    description=message,
                    scanner_name=self.scanner_name,
                    rule_id=check_id,
                    severity=sev,
                    file_path=file_path,
                    line_number=int(start_line) if start_line is not None else None,
                    end_line_number=int(end_line) if end_line is not None else None,
                    snippet=snippet,
                    remediation="Refactor code to sanitize inputs, avoid unsafe functions, and follow secure API patterns.",
                    reference_urls=ref_urls,
                    raw_details=item,
                    is_secret=False,
                )
            )
        return findings
