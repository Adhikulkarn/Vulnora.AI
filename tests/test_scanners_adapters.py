"""
Unit tests for all 6 Vulnora AI scanner adapters:
- Gitleaks (Secrets)
- Semgrep (Multi-language SAST)
- Bandit (Python AST)
- OSV-Scanner (Dependency Auditing)
- Trivy (Container, IaC, CVE)
- OWASP ZAP (DAST)
"""

import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vulnora.core.models import Finding, ScanStatus, Severity
from vulnora.scanners.bandit import BanditScanner
from vulnora.scanners.base import BaseScanner, ScanContext
from vulnora.scanners.gitleaks import GitleaksScanner
from vulnora.scanners.osv_scanner import OSVScanner
from vulnora.scanners.semgrep import SemgrepScanner
from vulnora.scanners.trivy import TrivyScanner
from vulnora.scanners.zap import ZAPScanner


class TestGitleaksScanner:
    """Tests for the Gitleaks secrets detection adapter."""

    def test_gitleaks_availability_check(self):
        scanner = GitleaksScanner()
        with patch("shutil.which", return_value="/usr/local/bin/gitleaks"):
            assert scanner.is_available() is True
        with patch("shutil.which", return_value=None):
            assert scanner.is_available() is False

    def test_gitleaks_parses_json_and_handles_exit_code_1(self, tmp_path: Path):
        scanner = GitleaksScanner()
        context = ScanContext(target_path=tmp_path)

        mock_findings = [
            {
                "Description": "AWS Access Key",
                "RuleID": "aws-access-key-id",
                "File": "config/settings.py",
                "StartLine": 14,
                "EndLine": 14,
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "Match": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            }
        ]

        def fake_run(cmd, **kwargs):
            # Write mock report to the file specified in --report-path
            report_arg_idx = cmd.index("--report-path") + 1
            report_file = Path(cmd[report_arg_idx])
            report_file.write_text(json.dumps(mock_findings), encoding="utf-8")
            # Gitleaks exits with 1 when leaks are discovered
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", side_effect=fake_run):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "aws-access-key-id"
        assert finding.severity == Severity.CRITICAL
        assert finding.is_secret is True
        assert finding.file_path == "config/settings.py"
        assert finding.line_number == 14
        # Secret should be masked in snippet
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet
        assert "AK****************LE" in finding.snippet

    def test_gitleaks_clean_run_returns_zero_findings(self, tmp_path: Path):
        scanner = GitleaksScanner()
        context = ScanContext(target_path=tmp_path)

        def fake_run(cmd, **kwargs):
            report_arg_idx = cmd.index("--report-path") + 1
            report_file = Path(cmd[report_arg_idx])
            report_file.write_text("[]", encoding="utf-8")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", side_effect=fake_run):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 0


class TestSemgrepScanner:
    """Tests for the Semgrep multi-language SAST adapter."""

    def test_semgrep_parsing_and_severity_mapping(self, tmp_path: Path):
        scanner = SemgrepScanner()
        context = ScanContext(target_path=tmp_path)

        mock_payload = {
            "results": [
                {
                    "check_id": "rules.python.security.sql_injection",
                    "path": "app/database.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 40},
                    "extra": {
                        "message": "User-supplied data in raw SQL statement.",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-89: SQL Injection"],
                            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                        },
                        "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                    },
                },
                {
                    "check_id": "rules.javascript.weak_random",
                    "path": "src/utils.js",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 15},
                    "extra": {
                        "message": "Math.random() is cryptographically insecure.",
                        "severity": "WARNING",
                        "metadata": {"references": []},
                        "lines": "const token = Math.random();",
                    },
                },
            ]
        }

        mock_proc = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=1,
            stdout=json.dumps(mock_payload),
            stderr="",
        )

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", return_value=mock_proc):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 2

        f1 = result.findings[0]
        assert f1.rule_id == "rules.python.security.sql_injection"
        assert f1.severity == Severity.CRITICAL  # Elevated from ERROR due to 'injection' CWE
        assert f1.file_path == "app/database.py"
        assert f1.line_number == 42
        assert "cursor.execute" in f1.snippet

        f2 = result.findings[1]
        assert f2.rule_id == "rules.javascript.weak_random"
        assert f2.severity == Severity.MEDIUM
        assert f2.file_path == "src/utils.js"


class TestBanditScanner:
    """Tests for the Bandit Python AST adapter."""

    def test_bandit_auto_gating_skips_when_no_python_files(self, tmp_path: Path):
        scanner = BanditScanner()
        # Non-python repository
        (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
        context = ScanContext(target_path=tmp_path, is_full_scan=True)

        with patch.object(scanner, "is_available", return_value=True):
            result = scanner.scan(context)

        assert result.status == ScanStatus.SKIPPED
        assert "Gated" in (result.error_message or "")

    def test_bandit_runs_and_parses_json_when_python_files_present(self, tmp_path: Path):
        scanner = BanditScanner()
        (tmp_path / "server.py").write_text("import eval\n", encoding="utf-8")
        context = ScanContext(target_path=tmp_path, is_full_scan=True)

        mock_payload = {
            "results": [
                {
                    "code": "eval(untrusted_payload)\n",
                    "filename": "server.py",
                    "issue_confidence": "HIGH",
                    "issue_cwe": {"id": 95, "link": "https://cwe.mitre.org/data/definitions/95.html"},
                    "issue_severity": "HIGH",
                    "issue_text": "Use of possibly insecure function - consider using safer ast.literal_eval.",
                    "line_number": 25,
                    "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b307_blacklist.html",
                    "test_id": "B307",
                    "test_name": "blacklist",
                }
            ]
        }

        mock_proc = subprocess.CompletedProcess(
            args=["bandit"],
            returncode=1,
            stdout=json.dumps(mock_payload),
            stderr="",
        )

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", return_value=mock_proc):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.rule_id == "B307"
        assert f.severity == Severity.HIGH
        assert f.file_path == "server.py"
        assert f.line_number == 25
        assert "https://cwe.mitre.org/data/definitions/95.html" in f.reference_urls


class TestOSVScanner:
    """Tests for the OSV-Scanner dependency auditor adapter."""

    def test_osv_scanner_auto_gating(self, tmp_path: Path):
        scanner = OSVScanner()
        # Plain text without lockfile
        (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
        context = ScanContext(target_path=tmp_path, is_full_scan=False)
        assert scanner.should_run(context) is False

        # Add lockfile
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        context2 = ScanContext(target_path=tmp_path, is_full_scan=False)
        assert scanner.should_run(context2) is True

    def test_osv_scanner_parses_nested_vulnerabilities(self, tmp_path: Path):
        scanner = OSVScanner()
        context = ScanContext(target_path=tmp_path, is_full_scan=True)

        mock_payload = {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-p6mc-m468-83gw",
                                    "summary": "Prototype Pollution in lodash",
                                    "details": "Lodash versions prior to 4.17.19 are vulnerable to Prototype Pollution.",
                                    "database_specific": {"severity": "HIGH"},
                                    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        mock_proc = subprocess.CompletedProcess(
            args=["osv-scanner"],
            returncode=1,
            stdout=json.dumps(mock_payload),
            stderr="",
        )

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", return_value=mock_proc):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.rule_id == "GHSA-p6mc-m468-83gw"
        assert f.severity == Severity.HIGH
        assert "Prototype Pollution" in f.title
        assert f.file_path == "package-lock.json"
        assert "https://nvd.nist.gov/vuln/detail/CVE-2020-8203" in f.reference_urls


class TestTrivyScanner:
    """Tests for the Trivy container & IaC adapter."""

    def test_trivy_auto_gating(self, tmp_path: Path):
        scanner = TrivyScanner()
        (tmp_path / "index.js").write_text("console.log()", encoding="utf-8")
        context = ScanContext(target_path=tmp_path, is_full_scan=False)
        assert scanner.should_run(context) is False

        (tmp_path / "Dockerfile").write_text("FROM alpine", encoding="utf-8")
        context2 = ScanContext(target_path=tmp_path, is_full_scan=False)
        assert scanner.should_run(context2) is True

    def test_trivy_parses_both_misconfigurations_and_vulnerabilities(self, tmp_path: Path):
        scanner = TrivyScanner()
        context = ScanContext(target_path=tmp_path, is_full_scan=True)

        mock_payload = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Image user should not be 'root'",
                            "Description": "Running containers as 'root' can lead to privilege escalation.",
                            "Severity": "HIGH",
                            "Resolution": "Specify 'USER <non-root-user>' in Dockerfile.",
                            "References": ["https://avd.aquasec.com/misconfig/ds002"],
                            "Lines": {"Begin": 1, "End": 1},
                        }
                    ],
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-44487",
                            "PkgName": "golang.org/x/net",
                            "InstalledVersion": "0.15.0",
                            "FixedVersion": "0.17.0",
                            "Title": "HTTP/2 Rapid Reset Attack",
                            "Description": "Stream cancellation vulnerability leading to DoS.",
                            "Severity": "CRITICAL",
                            "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                        }
                    ],
                }
            ]
        }

        mock_proc = subprocess.CompletedProcess(
            args=["trivy"],
            returncode=0,
            stdout=json.dumps(mock_payload),
            stderr="",
        )

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", return_value=mock_proc):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 2

        misconf = [f for f in result.findings if f.rule_id == "DS002"][0]
        assert misconf.severity == Severity.HIGH
        assert misconf.line_number == 1
        assert "USER <non-root-user>" in misconf.remediation

        cve = [f for f in result.findings if f.rule_id == "CVE-2023-44487"][0]
        assert cve.severity == Severity.CRITICAL
        assert "HTTP/2 Rapid Reset" in cve.title
        assert "0.17.0" in cve.remediation


class TestZAPScanner:
    """Tests for the OWASP ZAP DAST adapter."""

    def test_zap_strictly_skips_when_no_target_url_provided(self, tmp_path: Path):
        scanner = ZAPScanner()
        context = ScanContext(target_path=tmp_path, target_url=None)
        assert scanner.should_run(context) is False

        with patch.object(scanner, "is_available", return_value=True):
            result = scanner.scan(context)
        assert result.status == ScanStatus.SKIPPED
        assert "target url" in (result.error_message or "").lower()

    def test_zap_executes_and_parses_alerts_when_target_url_provided(self, tmp_path: Path):
        scanner = ZAPScanner()
        target_url = "https://testapp.local"
        context = ScanContext(target_path=tmp_path, target_url=target_url)
        assert scanner.should_run(context) is True

        mock_payload = {
            "site": [
                {
                    "@name": target_url,
                    "alerts": [
                        {
                            "pluginId": "10038",
                            "alert": "Content Security Policy (CSP) Header Not Set",
                            "riskdesc": "Medium (High)",
                            "desc": "CSP header was not sent by the server.",
                            "solution": "Configure a strong Content-Security-Policy header.",
                            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                            "instances": [{"uri": f"{target_url}/login", "method": "GET"}],
                        }
                    ],
                }
            ]
        }

        def fake_run(cmd, **kwargs):
            j_idx = cmd.index("-J") + 1
            report_name = cmd[j_idx]
            report_path = Path(kwargs.get("cwd", tmp_path)) / report_name
            report_path.write_text(json.dumps(mock_payload), encoding="utf-8")
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

        with patch.object(scanner, "is_available", return_value=True):
            with patch.object(scanner, "run_subprocess", side_effect=fake_run):
                result = scanner.scan(context)

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "10038"
        assert finding.severity == Severity.MEDIUM
        assert finding.file_path == f"{target_url}/login"
        assert "Configure a strong" in finding.remediation
