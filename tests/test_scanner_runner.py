"""
Unit tests for the Vulnora AI multi-scanner orchestrator (`vulnora.scanners.runner`).
"""

from pathlib import Path
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from vulnora.core.config import VulnoraConfig
from vulnora.core.models import Finding, OrchestratorResult, ScannerResult, ScanStatus, Severity
from vulnora.scanners.base import BaseScanner, ScanContext
from vulnora.scanners.runner import SCANNER_REGISTRY, ScannerOrchestrator


class MockDummyScanner(BaseScanner):
    """Custom mock scanner for testing orchestrator features."""
    def __init__(self, name: str, status: ScanStatus = ScanStatus.COMPLETED, findings=None, delay: float = 0.0, raise_exc: bool = False, should_gate: bool = False):
        super().__init__()
        self.scanner_name = name
        self.binary_name = name
        self._status = status
        self._findings = findings or []
        self._delay = delay
        self._raise_exc = raise_exc
        self._should_gate = should_gate

    def is_available(self) -> bool:
        return self._status != ScanStatus.NOT_INSTALLED

    def should_run(self, context: ScanContext) -> bool:
        if self._should_gate:
            return False
        return self._status != ScanStatus.SKIPPED

    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        if self._delay > 0:
            time.sleep(self._delay)
        if self._raise_exc:
            raise RuntimeError("Scanner execution failed unexpectedly")
        return ScannerResult(
            scanner_name=self.scanner_name,
            status=self._status,
            findings=self._findings,
        )


class TestScannerOrchestrator:
    """Tests for concurrent orchestration, gating, resilience, and deduplication."""

    def test_orchestrator_initializes_all_registered_scanners(self):
        orchestrator = ScannerOrchestrator()
        assert set(orchestrator.scanners.keys()) == set(SCANNER_REGISTRY.keys())
        assert len(orchestrator.scanners) == 6

    def test_concurrent_execution_runs_faster_than_sequential(self, tmp_path: Path):
        # 3 scanners each sleeping for 0.05 seconds
        s1 = MockDummyScanner("s1", delay=0.05)
        s2 = MockDummyScanner("s2", delay=0.05)
        s3 = MockDummyScanner("s3", delay=0.05)

        orchestrator = ScannerOrchestrator(custom_scanners={"s1": s1, "s2": s2, "s3": s3})

        start = time.perf_counter()
        result = orchestrator.run_scanners(target_path=tmp_path, is_full_scan=True, requested_scanners=["s1", "s2", "s3"])
        elapsed = time.perf_counter() - start

        # If sequential: ~0.15s; if concurrent: ~0.05s-0.10s
        assert elapsed < 0.14
        assert result.scanners_run == ["s1", "s2", "s3"]
        assert len(result.scanner_results) == 3

    def test_auto_gating_skips_ineligible_scanners(self, tmp_path: Path):
        s_active = MockDummyScanner("active")
        s_gated = MockDummyScanner("gated", should_gate=True)

        orchestrator = ScannerOrchestrator(custom_scanners={"active": s_active, "gated": s_gated})
        result = orchestrator.run_scanners(target_path=tmp_path, requested_scanners=["active", "gated"])

        assert "active" in result.scanners_run
        assert "gated" in result.scanners_skipped
        gated_res = [r for r in result.scanner_results if r.scanner_name == "gated"][0]
        assert gated_res.status == ScanStatus.SKIPPED

    def test_missing_binary_degrades_gracefully(self, tmp_path: Path):
        s_installed = MockDummyScanner("installed")
        s_missing = MockDummyScanner("missing", status=ScanStatus.NOT_INSTALLED)

        orchestrator = ScannerOrchestrator(custom_scanners={"installed": s_installed, "missing": s_missing})
        result = orchestrator.run_scanners(target_path=tmp_path, requested_scanners=["installed", "missing"])

        assert "installed" in result.scanners_run
        assert "missing" in result.scanners_skipped
        missing_res = [r for r in result.scanner_results if r.scanner_name == "missing"][0]
        assert missing_res.status == ScanStatus.NOT_INSTALLED
        assert "not found in system PATH" in (missing_res.error_message or "")

    def test_scanner_exception_does_not_crash_pipeline(self, tmp_path: Path):
        s_normal = MockDummyScanner("normal")
        s_crash = MockDummyScanner("crash", raise_exc=True)

        orchestrator = ScannerOrchestrator(custom_scanners={"normal": s_normal, "crash": s_crash})
        result = orchestrator.run_scanners(target_path=tmp_path, requested_scanners=["normal", "crash"])

        assert "normal" in result.scanners_run
        assert "crash" in result.scanners_failed
        failed_res = [r for r in result.scanner_results if r.scanner_name == "crash"][0]
        assert failed_res.status == ScanStatus.FAILED
        assert "failed unexpectedly" in (failed_res.error_message or "")

    def test_deduplication_of_overlapping_findings(self, tmp_path: Path):
        # Two scanners detecting the same vulnerability with identical fingerprint
        f1 = Finding(
            title="Hardcoded Password",
            description="Found password",
            scanner_name="gitleaks",
            rule_id="password",
            severity=Severity.HIGH,
            file_path="src/auth.py",
            line_number=10,
        )
        # Duplicate with same fingerprint
        f2 = Finding(
            title="Insecure Credential",
            description="Found password",
            scanner_name="gitleaks",
            rule_id="password",
            severity=Severity.HIGH,
            file_path="src/auth.py",
            line_number=10,
            fingerprint=f1.fingerprint,  # Explicitly matches
        )
        # Unique finding
        f3 = Finding(
            title="SQL Injection",
            description="Found SQLi",
            scanner_name="semgrep",
            rule_id="sqli",
            severity=Severity.CRITICAL,
            file_path="src/db.py",
            line_number=50,
        )

        s1 = MockDummyScanner("s1", findings=[f1])
        s2 = MockDummyScanner("s2", findings=[f2, f3])

        orchestrator = ScannerOrchestrator(custom_scanners={"s1": s1, "s2": s2})
        result = orchestrator.run_scanners(target_path=tmp_path, requested_scanners=["s1", "s2"])

        # 3 raw findings reduced to 2 deduplicated findings
        assert result.total_findings == 2
        # CRITICAL sorted first
        assert result.findings[0].rule_id == "sqli"
        assert result.findings[1].rule_id == "password"
        assert result.has_critical_or_high is True

    def test_orchestrator_result_serialization_roundtrip(self, tmp_path: Path):
        f = Finding(
            title="Insecure Token",
            description="Hardcoded token",
            scanner_name="gitleaks",
            rule_id="tok",
            severity=Severity.CRITICAL,
            file_path="token.py",
        )
        sr = ScannerResult(
            scanner_name="gitleaks",
            status=ScanStatus.COMPLETED,
            duration_seconds=0.15,
            findings=[f],
        )
        res = OrchestratorResult(
            target_path=str(tmp_path),
            duration_seconds=0.5,
            scanner_results=[sr],
            findings=[f],
            scanners_run=["gitleaks"],
            scanners_skipped=["bandit"],
            scanners_failed=[],
        )

        d = res.to_dict()
        assert d["total_findings"] == 1
        assert d["critical_count"] == 1
        assert d["high_count"] == 0

        reconstructed = OrchestratorResult.from_dict(d)
        assert reconstructed.total_findings == 1
        assert reconstructed.critical_findings[0].rule_id == "tok"
        assert reconstructed.scanners_run == ["gitleaks"]
