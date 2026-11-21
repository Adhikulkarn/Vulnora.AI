"""
OSV-Scanner dependency auditing adapter for Vulnora AI.

Scans open-source dependency manifests, package locks, and software bills of materials
against the Google Open Source Vulnerabilities (OSV) database.
Auto-gated on repositories containing dependency manifests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext

KNOWN_DEPENDENCY_MANIFESTS: List[str] = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "Cargo.lock",
    "go.sum",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.lock",
    "Package.resolved",
    "packages.lock.json",
]


class OSVScanner(BaseScanner):
    """
    Adapter for Google OSV-Scanner dependency vulnerability audit engine.
    Auto-gated: only executes when recognized dependency lockfiles/manifests are present.
    """

    scanner_name: str = "osv-scanner"
    binary_name: str = "osv-scanner"

    def should_run(self, context: ScanContext) -> bool:
        """Auto-gate: Only run if target contains dependency manifests or during full scan."""
        if context.is_full_scan:
            return True
        return context.has_matching_filenames(KNOWN_DEPENDENCY_MANIFESTS)

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        cmd = [
            self.executable,
            "--json",
            "-r",
            str(context.target_path),
        ]

        proc = self.run_subprocess(cmd, cwd=context.target_path, timeout=context.timeout_seconds)

        # OSV-Scanner exit codes: 0 = clean, 1 = vulnerabilities found, 128+ = error
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip() or proc.stdout.strip() or f"OSV-Scanner exited with code {proc.returncode}"
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
                    error_message=f"Failed to parse OSV-Scanner JSON output: {exc}",
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
        for result in raw_results:
            source = result.get("source", {}) if isinstance(result.get("source"), dict) else {}
            source_path = str(source.get("path") or "manifest")

            packages = result.get("packages", []) if isinstance(result.get("packages"), list) else []
            for pkg_entry in packages:
                pkg_info = pkg_entry.get("package", {}) if isinstance(pkg_entry.get("package"), dict) else {}
                pkg_name = str(pkg_info.get("name") or "unknown-package")
                pkg_ver = str(pkg_info.get("version") or "")

                vulns = pkg_entry.get("vulnerabilities", []) if isinstance(pkg_entry.get("vulnerabilities"), list) else []
                for vuln in vulns:
                    vuln_id = str(vuln.get("id") or "OSV-VULN")
                    summary = str(vuln.get("summary") or "")
                    details = str(vuln.get("details") or summary or f"Vulnerability {vuln_id} in {pkg_name}")
                    title = f"Vulnerable Dependency: {pkg_name}@{pkg_ver} - {summary or vuln_id}"

                    # Determine severity
                    db_spec = vuln.get("database_specific", {}) if isinstance(vuln.get("database_specific"), dict) else {}
                    raw_sev = str(db_spec.get("severity") or "HIGH").upper()
                    if raw_sev in ("CRITICAL", "HIGH"):
                        sev = Severity.CRITICAL if raw_sev == "CRITICAL" else Severity.HIGH
                    elif raw_sev in ("MEDIUM", "MODERATE"):
                        sev = Severity.MEDIUM
                    else:
                        sev = Severity.LOW

                    refs = vuln.get("references", []) if isinstance(vuln.get("references"), list) else []
                    ref_urls = [str(r.get("url")) for r in refs if isinstance(r, dict) and r.get("url")]

                    findings.append(
                        Finding(
                            title=title,
                            description=details,
                            scanner_name=self.scanner_name,
                            rule_id=vuln_id,
                            severity=sev,
                            file_path=source_path,
                            snippet=f"{pkg_name} == {pkg_ver}" if pkg_ver else pkg_name,
                            remediation=f"Upgrade {pkg_name} to a secure patched release according to {vuln_id} advisory guidance.",
                            reference_urls=ref_urls,
                            raw_details=vuln,
                            is_secret=False,
                        )
                    )
        return findings
