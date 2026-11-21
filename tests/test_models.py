"""
Unit tests for Vulnora AI data contracts and models (`vulnora.core.models`).
"""

import pytest

from vulnora.core.models import (
    Finding,
    GitRepoStatus,
    OrchestratorResult,
    PushRefUpdate,
    RepoLanguage,
    ScannerResult,
    ScannerStatus,
    ScanStatus,
    Severity,
)


class TestSeverity:
    """Tests for the Severity enum and ordering logic."""

    def test_severity_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert Severity.INFO < Severity.CRITICAL

    def test_severity_comparison_with_strings(self):
        assert Severity.CRITICAL > "HIGH"
        assert Severity.MEDIUM >= "MEDIUM"
        assert Severity.LOW < "HIGH"
        assert Severity.INFO <= "LOW"
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "high"

    def test_severity_from_string(self):
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("High") == Severity.HIGH
        assert Severity.from_string("medium") == Severity.MEDIUM
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("info") == Severity.INFO

    def test_severity_from_string_aliases(self):
        assert Severity.from_string("ERROR") == Severity.HIGH
        assert Severity.from_string("WARN") == Severity.MEDIUM
        assert Severity.from_string("warning") == Severity.MEDIUM
        assert Severity.from_string("MODERATE") == Severity.MEDIUM
        assert Severity.from_string("NOTE") == Severity.LOW
        assert Severity.from_string("NOTICE") == Severity.INFO

    def test_severity_from_string_empty_defaults_to_info(self):
        assert Severity.from_string("") == Severity.INFO

    def test_severity_from_string_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown severity level"):
            Severity.from_string("EXTREME_DANGER")

    def test_severity_sorting(self):
        severities = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.MEDIUM]
        sorted_severities = sorted(severities)
        assert sorted_severities == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]


class TestScanStatus:
    """Tests for ScanStatus enum."""

    def test_scan_status_values(self):
        assert ScanStatus.COMPLETED == "COMPLETED"
        assert ScanStatus.FAILED == "FAILED"
        assert ScanStatus.TIMED_OUT == "TIMED_OUT"
        assert ScanStatus.NOT_INSTALLED == "NOT_INSTALLED"
        assert ScanStatus.SKIPPED == "SKIPPED"

    def test_scan_status_from_string(self):
        assert ScanStatus.from_string("COMPLETED") == ScanStatus.COMPLETED
        assert ScanStatus.from_string("failed") == ScanStatus.FAILED
        assert ScanStatus.from_string("timed_out") == ScanStatus.TIMED_OUT
        assert ScanStatus.from_string("unknown_status") == ScanStatus.FAILED


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation_and_fingerprint_generation(self):
        finding = Finding(
            title="AWS Access Key Exposed",
            description="Found hardcoded AWS Secret Access Key in source.",
            scanner_name="gitleaks",
            rule_id="aws-secret-access-key",
            severity=Severity.CRITICAL,
            file_path="src/config.py",
            line_number=42,
            is_secret=True,
        )
        assert finding.fingerprint != ""
        assert len(finding.fingerprint) == 32
        # Deterministic generation
        same_finding = Finding(
            title="AWS Access Key Exposed",
            description="Different description",
            scanner_name="gitleaks",
            rule_id="aws-secret-access-key",
            severity=Severity.CRITICAL,
            file_path="src/config.py",
            line_number=42,
        )
        assert finding.fingerprint == same_finding.fingerprint

    def test_different_locations_produce_different_fingerprints(self):
        f1 = Finding(
            title="SQL Injection",
            description="Unsanitized query",
            scanner_name="semgrep",
            rule_id="sql-injection",
            severity=Severity.HIGH,
            file_path="src/db.go",
            line_number=10,
        )
        f2 = Finding(
            title="SQL Injection",
            description="Unsanitized query",
            scanner_name="semgrep",
            rule_id="sql-injection",
            severity=Severity.HIGH,
            file_path="src/db.go",
            line_number=20,
        )
        assert f1.fingerprint != f2.fingerprint

    def test_finding_string_severity_auto_conversion(self):
        finding = Finding(
            title="XSS Vulnerability",
            description="Reflected XSS",
            scanner_name="semgrep",
            rule_id="xss",
            severity="high",  # String instead of enum
            file_path="web/app.ts",
            line_number=15,
        )
        assert isinstance(finding.severity, Severity)
        assert finding.severity == Severity.HIGH

    def test_finding_explicit_fingerprint_retained(self):
        custom_fp = "custom-deterministic-hash-123456"
        finding = Finding(
            title="Test",
            description="Test",
            scanner_name="test",
            rule_id="r1",
            severity=Severity.LOW,
            file_path="main.rs",
            fingerprint=custom_fp,
        )
        assert finding.fingerprint == custom_fp

    def test_finding_to_dict_and_from_dict_roundtrip(self):
        original = Finding(
            title="Insecure Cipher",
            description="DES algorithm is deprecated",
            scanner_name="bandit",
            rule_id="B303",
            severity=Severity.MEDIUM,
            file_path="crypto/cipher.py",
            line_number=88,
            end_line_number=92,
            snippet="import DES",
            remediation="Migrate to AES-GCM.",
            reference_urls=["https://cwe.mitre.org/data/definitions/327.html"],
            raw_details={"cwe": "CWE-327"},
            is_secret=False,
        )

        d = original.to_dict()
        assert d["severity"] == "MEDIUM"
        assert d["scanner_name"] == "bandit"
        assert d["snippet"] == "import DES"

        reconstructed = Finding.from_dict(d)
        assert reconstructed.title == original.title
        assert reconstructed.severity == Severity.MEDIUM
        assert reconstructed.fingerprint == original.fingerprint
        assert reconstructed.reference_urls == original.reference_urls
        assert reconstructed.raw_details == original.raw_details


class TestScannerResult:
    """Tests for ScannerResult model."""

    def test_scanner_result_properties(self):
        f_crit = Finding(
            title="Root execution",
            description="Dangerous container user",
            scanner_name="trivy",
            rule_id="DS002",
            severity=Severity.CRITICAL,
            file_path="Dockerfile",
        )
        f_high = Finding(
            title="Vulnerable openssl",
            description="CVE-2024-0727",
            scanner_name="trivy",
            rule_id="CVE-2024-0727",
            severity=Severity.HIGH,
            file_path="Cargo.lock",
        )
        result = ScannerResult(
            scanner_name="trivy",
            status=ScanStatus.COMPLETED,
            duration_seconds=1.2345,
            findings=[f_crit, f_high],
        )

        assert result.has_findings is True
        assert len(result.critical_findings) == 1
        assert result.critical_findings[0].title == "Root execution"
        assert len(result.high_findings) == 1
        assert result.high_findings[0].rule_id == "CVE-2024-0727"

    def test_scanner_result_dict_findings_coercion(self):
        raw_finding_dict = {
            "title": "Secret in code",
            "description": "API token",
            "scanner_name": "gitleaks",
            "rule_id": "generic-api-key",
            "severity": "CRITICAL",
            "file_path": "api/keys.go",
            "line_number": 5,
        }
        result = ScannerResult(
            scanner_name="gitleaks",
            status="COMPLETED",  # String status coercion
            duration_seconds=0.45,
            findings=[raw_finding_dict],
        )
        assert isinstance(result.status, ScanStatus)
        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        assert isinstance(result.findings[0], Finding)
        assert result.findings[0].severity == Severity.CRITICAL

    def test_scanner_result_serialization_roundtrip(self):
        f = Finding(
            title="SQLi",
            description="SQL injection in repository",
            scanner_name="semgrep",
            rule_id="sqli-1",
            severity=Severity.HIGH,
            file_path="db.ts",
        )
        result = ScannerResult(
            scanner_name="semgrep",
            status=ScanStatus.COMPLETED,
            duration_seconds=2.5,
            findings=[f],
            error_message=None,
        )

        serialized = result.to_dict()
        assert serialized["findings_count"] == 1
        assert serialized["status"] == "COMPLETED"

        deserialized = ScannerResult.from_dict(serialized)
        assert deserialized.scanner_name == "semgrep"
        assert deserialized.status == ScanStatus.COMPLETED
        assert len(deserialized.findings) == 1
        assert deserialized.findings[0].rule_id == "sqli-1"


class TestPushRefUpdate:
    """Tests for PushRefUpdate model."""

    def test_push_ref_update_serialization(self):
        update = PushRefUpdate(
            local_ref="refs/heads/main",
            local_sha="1111111111111111111111111111111111111111",
            remote_ref="refs/heads/main",
            remote_sha="2222222222222222222222222222222222222222",
            branch_name="main",
            is_branch=True,
            is_deletion=False,
            is_tag=False,
        )
        d = update.to_dict()
        assert d["branch_name"] == "main"
        assert d["is_branch"] is True

        reconstructed = PushRefUpdate.from_dict(d)
        assert reconstructed.local_ref == update.local_ref
        assert reconstructed.is_deletion is False


class TestGitRepoStatus:
    """Tests for GitRepoStatus model."""

    def test_git_repo_status_serialization(self):
        status = GitRepoStatus(
            is_git=True,
            root_path="/repo",
            current_branch="main",
            current_commit="abcdef1",
            is_detached=False,
            is_dirty=True,
            protected_branches=["main", "production"],
            is_current_branch_protected=True,
            hooks_dir="/repo/.git/hooks",
            hook_installed=True,
            detected_languages=["Go", "TypeScript"],
        )
        d = status.to_dict()
        assert d["is_dirty"] is True
        assert d["is_current_branch_protected"] is True

        reconstructed = GitRepoStatus.from_dict(d)
        assert reconstructed.current_branch == "main"
        assert reconstructed.detected_languages == ["Go", "TypeScript"]


class TestRepoLanguage:
    """Tests for RepoLanguage model."""

    def test_repo_language_serialization(self):
        lang = RepoLanguage(
            primary_language="Rust",
            detected_languages=["Rust", "Python"],
            manifest_files=["Cargo.toml", "pyproject.toml"],
        )
        d = lang.to_dict()
        assert d["primary_language"] == "Rust"

        reconstructed = RepoLanguage.from_dict(d)
        assert reconstructed.manifest_files == ["Cargo.toml", "pyproject.toml"]


class TestScannerStatusAlias:
    """Tests that ScannerStatus alias matches ScanStatus."""

    def test_scanner_status_alias(self):
        assert ScannerStatus is ScanStatus
        assert ScannerStatus.COMPLETED == "COMPLETED"
        assert ScannerStatus.FAILED == "FAILED"
        assert ScannerStatus.TIMED_OUT == "TIMED_OUT"
        assert ScannerStatus.NOT_INSTALLED == "NOT_INSTALLED"
        assert ScannerStatus.SKIPPED == "SKIPPED"


class TestOrchestratorResultModel:
    """Tests for OrchestratorResult data contract."""

    def test_orchestrator_result_properties_and_serialization(self):
        f_crit = Finding(
            title="Exposed Secret",
            description="API key in settings.py",
            scanner_name="gitleaks",
            rule_id="generic-api-key",
            severity=Severity.CRITICAL,
            file_path="settings.py",
        )
        f_high = Finding(
            title="SQL Injection",
            description="SQLi in db.py",
            scanner_name="semgrep",
            rule_id="sqli",
            severity=Severity.HIGH,
            file_path="db.py",
        )
        sr = ScannerResult(
            scanner_name="gitleaks",
            status=ScanStatus.COMPLETED,
            duration_seconds=0.45,
            findings=[f_crit],
        )
        result = OrchestratorResult(
            target_path="/app",
            duration_seconds=1.23,
            scanner_results=[sr],
            findings=[f_crit, f_high],
            scanners_run=["gitleaks", "semgrep"],
            scanners_skipped=["zap"],
            scanners_failed=[],
            target_url=None,
            is_full_scan=True,
        )

        assert result.total_findings == 2
        assert len(result.critical_findings) == 1
        assert len(result.high_findings) == 1
        assert len(result.medium_findings) == 0
        assert result.has_critical_or_high is True

        d = result.to_dict()
        assert d["total_findings"] == 2
        assert d["critical_count"] == 1
        assert d["high_count"] == 1
        assert d["is_full_scan"] is True

        reconstructed = OrchestratorResult.from_dict(d)
        assert reconstructed.target_path == "/app"
        assert reconstructed.total_findings == 2
        assert reconstructed.has_critical_or_high is True
        assert len(reconstructed.scanner_results) == 1
        assert reconstructed.scanner_results[0].scanner_name == "gitleaks"

