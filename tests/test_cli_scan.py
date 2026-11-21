"""
Integration tests for the `vulnora scan` command (`vulnora.cli`).
"""

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from vulnora.cli import main
from vulnora.core.models import Finding, OrchestratorResult, ScannerResult, ScanStatus, Severity


class TestCLIScan:
    """Tests for the `vulnora scan` CLI command."""

    def test_cli_scan_diff_scoped_clean_repo(self, tmp_path: Path, capsys):
        # Create clean git repo
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        (tmp_path / "app.py").write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp_path, check=True)

        rc = main(["-C", str(tmp_path), "scan"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Working tree is clean" in captured.out or "Diff-Scoped" in captured.out

    def test_cli_scan_diff_scoped_clean_json(self, tmp_path: Path, capsys):
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        (tmp_path / "app.py").write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp_path, check=True)

        rc = main(["-C", str(tmp_path), "scan", "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total_findings"] == 0

    def test_cli_scan_full_with_mocked_orchestrator(self, tmp_path: Path, capsys):
        mock_finding = Finding(
            title="Exposed Secret API Key",
            description="Found AWS key in config.py",
            scanner_name="gitleaks",
            rule_id="aws-secret-key",
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_number=10,
            snippet="AWS_KEY = '***'",
            remediation="Rotate key immediately.",
        )
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            duration_seconds=1.25,
            scanner_results=[
                ScannerResult(
                    scanner_name="gitleaks",
                    status=ScanStatus.COMPLETED,
                    duration_seconds=0.2,
                    findings=[mock_finding],
                ),
                ScannerResult(
                    scanner_name="bandit",
                    status=ScanStatus.SKIPPED,
                    error_message="Gated: no Python files",
                ),
            ],
            findings=[mock_finding],
            scanners_run=["gitleaks"],
            scanners_skipped=["bandit"],
            is_full_scan=True,
        )

        with patch("vulnora.cli.ScannerOrchestrator.run_scanners", return_value=mock_result):
            rc = main(["-C", str(tmp_path), "scan", "--full"])

        assert rc == 0  # Without --block, returns 0
        captured = capsys.readouterr()
        assert "Vulnora AI Security Scan — Full Repository" in captured.out
        assert "Exposed Secret API Key" in captured.out
        assert "CRITICAL: 1" in captured.out

    def test_cli_scan_block_flag_exits_with_code_1_on_critical(self, tmp_path: Path):
        mock_finding = Finding(
            title="Critical SQL Injection",
            description="SQLi detected",
            scanner_name="semgrep",
            rule_id="sqli-1",
            severity=Severity.CRITICAL,
            file_path="db.py",
        )
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            duration_seconds=0.5,
            findings=[mock_finding],
            scanners_run=["semgrep"],
            is_full_scan=True,
        )

        with patch("vulnora.cli.ScannerOrchestrator.run_scanners", return_value=mock_result):
            rc = main(["-C", str(tmp_path), "scan", "--full", "--block"])

        assert rc == 1  # Block flag blocks execution

    def test_cli_scan_json_output(self, tmp_path: Path, capsys):
        mock_finding = Finding(
            title="High Severity Insecure Deserialization",
            description="Pickle load",
            scanner_name="bandit",
            rule_id="B301",
            severity=Severity.HIGH,
            file_path="cache.py",
        )
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            duration_seconds=0.8,
            scanner_results=[
                ScannerResult(
                    scanner_name="bandit",
                    status=ScanStatus.COMPLETED,
                    findings=[mock_finding],
                )
            ],
            findings=[mock_finding],
            scanners_run=["bandit"],
            is_full_scan=True,
        )

        with patch("vulnora.cli.ScannerOrchestrator.run_scanners", return_value=mock_result):
            rc = main(["-C", str(tmp_path), "scan", "--full", "--json"])

        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total_findings"] == 1
        assert data["critical_count"] == 0
        assert data["high_count"] == 1
        assert data["findings"][0]["rule_id"] == "B301"

    def test_cli_scan_passes_target_url_and_selected_scanners(self, tmp_path: Path):
        with patch("vulnora.cli.ScannerOrchestrator.run_scanners") as mock_run:
            mock_run.return_value = OrchestratorResult(target_path=str(tmp_path))
            rc = main([
                "-C", str(tmp_path),
                "scan",
                "--full",
                "--target-url", "https://api.mycorp.internal",
                "--scanners", "gitleaks,semgrep,zap",
                "--timeout", "30",
            ])

            assert rc == 0
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["target_url"] == "https://api.mycorp.internal"
            assert call_kwargs["requested_scanners"] == ["gitleaks", "semgrep", "zap"]
            assert call_kwargs["timeout_seconds"] == 30
            assert call_kwargs["is_full_scan"] is True
