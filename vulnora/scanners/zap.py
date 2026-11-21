"""
OWASP ZAP (Zed Attack Proxy) DAST scanner adapter for Vulnora AI.

Performs Dynamic Application Security Testing against live web targets.
Auto-gated: only executes when --target-url is explicitly provided.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext


class ZAPScanner(BaseScanner):
    """
    Adapter for OWASP ZAP baseline web vulnerability scanner.
    Auto-gated: strictly requires context.target_url to be configured.
    """

    scanner_name: str = "zap"
    binary_name: str = "zap-baseline.py"

    def should_run(self, context: ScanContext) -> bool:
        """Auto-gate: ZAP DAST scans ONLY execute when a target URL is provided."""
        return bool(context.target_url and str(context.target_url).strip())

    def get_gated_message(self, context: ScanContext) -> str:
        return "Gated: No target URL provided for OWASP ZAP DAST scan."

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        if not context.target_url:
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.SKIPPED,
                error_message="OWASP ZAP DAST scan skipped: no target URL provided.",
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = Path(tmp.name)

        try:
            cmd = [
                self.executable,
                "-t",
                str(context.target_url),
                "-J",
                str(report_path.name),
                "-m",
                "1",
                "-I",
            ]

            proc = self.run_subprocess(cmd, cwd=report_path.parent, timeout=context.timeout_seconds)

            findings: List[Finding] = []
            if report_path.exists() and report_path.stat().st_size > 0:
                try:
                    content = report_path.read_text(encoding="utf-8")
                    data = json.loads(content)
                    findings = self._parse_findings(data, context.target_url)
                except Exception as exc:
                    return ScannerResult(
                        scanner_name=self.scanner_name,
                        status=ScanStatus.FAILED,
                        error_message=f"Failed to parse ZAP JSON report: {exc}",
                        raw_output=proc.stdout or proc.stderr,
                    )

            # ZAP baseline script returns 0 for no warnings, 1 for warnings, 2 for failures
            status = ScanStatus.COMPLETED if proc.returncode in (0, 1) or findings else ScanStatus.FAILED
            err = None if status == ScanStatus.COMPLETED else (proc.stderr or proc.stdout)

            return ScannerResult(
                scanner_name=self.scanner_name,
                status=status,
                findings=findings,
                error_message=err,
                raw_output=proc.stdout or proc.stderr,
            )
        finally:
            if report_path.exists():
                try:
                    report_path.unlink()
                except Exception:
                    pass

    def _parse_findings(self, report_data: Dict[str, Any], target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        sites = report_data.get("site", []) if isinstance(report_data.get("site"), list) else []

        for site in sites:
            alerts = site.get("alerts", []) if isinstance(site.get("alerts"), list) else []
            for alert in alerts:
                plugin_id = str(alert.get("pluginId") or "ZAP-ALERT")
                alert_title = str(alert.get("alert") or f"DAST Alert {plugin_id}")
                desc = str(alert.get("desc") or alert_title)
                risk_desc = str(alert.get("riskdesc") or "Medium").split()[0].upper()
                solution = str(alert.get("solution") or "Consult OWASP guidelines to remediate.")
                ref_str = str(alert.get("reference") or "")

                if "HIGH" in risk_desc:
                    sev = Severity.HIGH
                elif "LOW" in risk_desc:
                    sev = Severity.LOW
                elif "INFO" in risk_desc:
                    sev = Severity.INFO
                else:
                    sev = Severity.MEDIUM

                instances = alert.get("instances", []) if isinstance(alert.get("instances"), list) else []
                sample_uri = target_url
                if instances and isinstance(instances[0], dict) and instances[0].get("uri"):
                    sample_uri = str(instances[0].get("uri"))

                ref_urls = [ref_str] if ref_str else ["https://www.zaproxy.org/docs/alerts/"]

                findings.append(
                    Finding(
                        title=f"DAST: {alert_title}",
                        description=desc,
                        scanner_name=self.scanner_name,
                        rule_id=plugin_id,
                        severity=sev,
                        file_path=sample_uri,
                        remediation=solution,
                        reference_urls=ref_urls,
                        raw_details=alert,
                        is_secret=False,
                    )
                )

        return findings
