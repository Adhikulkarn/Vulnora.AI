"""
Aqua Security Trivy scanner adapter for Vulnora AI.

Scans container configurations, Dockerfiles, Kubernetes manifests, Terraform IaC,
and software dependencies for CVE vulnerabilities and misconfigurations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext

TRIVY_TARGET_PATTERNS: List[str] = [
    "Dockerfile*",
    "*.dockerfile",
    "*.tf",
    "*.tfvars",
    "*.yaml",
    "*.yml",
    "package-lock.json",
    "yarn.lock",
    "Cargo.lock",
    "go.sum",
    "requirements.txt",
    "pom.xml",
]


class TrivyScanner(BaseScanner):
    """
    Adapter for Trivy container, IaC, and filesystem vulnerability scanner.
    Auto-gated: only executes when Dockerfiles, IaC, manifests, or full scan are requested.
    """

    scanner_name: str = "trivy"
    binary_name: str = "trivy"

    def should_run(self, context: ScanContext) -> bool:
        """Auto-gate: Evaluates if IaC, Dockerfiles, or lockfiles are present."""
        if context.is_full_scan:
            return True
        return (
            context.has_matching_filenames(TRIVY_TARGET_PATTERNS)
            or context.has_extension([".tf", ".yaml", ".yml"])
        )

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        cmd = [
            self.executable,
            "fs",
            "--format",
            "json",
            "--quiet",
            str(context.target_path),
        ]

        proc = self.run_subprocess(cmd, cwd=context.target_path, timeout=context.timeout_seconds)

        # Trivy exit codes: 0 = clean/found (unless --exit-code configured), 1+ = errors or findings
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip() or proc.stdout.strip() or f"Trivy exited with code {proc.returncode}"
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
                raw_results = data.get("Results", []) if isinstance(data, dict) else []
                findings = self._parse_findings(raw_results)
            except Exception as exc:
                return ScannerResult(
                    scanner_name=self.scanner_name,
                    status=ScanStatus.FAILED,
                    error_message=f"Failed to parse Trivy JSON output: {exc}",
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
        for res in raw_results:
            target_file = str(res.get("Target") or "")

            # 1. Parse Misconfigurations (IaC, Dockerfile rules)
            misconfs = res.get("Misconfigurations", []) if isinstance(res.get("Misconfigurations"), list) else []
            for item in misconfs:
                rule_id = str(item.get("ID") or "TRIVY-MISCONF")
                title = str(item.get("Title") or f"Misconfiguration ({rule_id})")
                desc = str(item.get("Description") or title)
                raw_sev = str(item.get("Severity") or "MEDIUM").upper()
                sev = Severity.from_string(raw_sev) if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else Severity.MEDIUM

                lines = item.get("Lines", {}) if isinstance(item.get("Lines"), dict) else {}
                line_no = lines.get("Begin")
                end_line = lines.get("End")
                resolution = str(item.get("Resolution") or "Follow best practices to remediate misconfiguration.")

                refs = item.get("References", []) if isinstance(item.get("References"), list) else []
                ref_urls = [str(r) for r in refs if isinstance(r, str)]

                findings.append(
                    Finding(
                        title=f"IaC Misconfiguration: {title}",
                        description=desc,
                        scanner_name=self.scanner_name,
                        rule_id=rule_id,
                        severity=sev,
                        file_path=target_file,
                        line_number=int(line_no) if line_no is not None else None,
                        end_line_number=int(end_line) if end_line is not None else None,
                        remediation=resolution,
                        reference_urls=ref_urls,
                        raw_details=item,
                        is_secret=False,
                    )
                )

            # 2. Parse Package Vulnerabilities (CVEs)
            vulns = res.get("Vulnerabilities", []) if isinstance(res.get("Vulnerabilities"), list) else []
            for item in vulns:
                vuln_id = str(item.get("VulnerabilityID") or "CVE-TRIVY")
                pkg_name = str(item.get("PkgName") or "package")
                installed_ver = str(item.get("InstalledVersion") or "")
                fixed_ver = str(item.get("FixedVersion") or "")
                title = str(item.get("Title") or f"{vuln_id} in {pkg_name}")
                desc = str(item.get("Description") or title)

                raw_sev = str(item.get("Severity") or "HIGH").upper()
                sev = Severity.from_string(raw_sev) if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else Severity.HIGH

                refs = item.get("References", []) if isinstance(item.get("References"), list) else []
                ref_urls = [str(r) for r in refs if isinstance(r, str)]

                remed = f"Upgrade {pkg_name} to version {fixed_ver}." if fixed_ver else f"Review {vuln_id} advisory for mitigations."

                findings.append(
                    Finding(
                        title=f"CVE Vulnerability: {pkg_name}@{installed_ver} - {title}",
                        description=desc,
                        scanner_name=self.scanner_name,
                        rule_id=vuln_id,
                        severity=sev,
                        file_path=target_file,
                        snippet=f"{pkg_name} == {installed_ver}" if installed_ver else None,
                        remediation=remed,
                        reference_urls=ref_urls,
                        raw_details=item,
                        is_secret=False,
                    )
                )

        return findings
