"""
Integration tests for Phase 5 CLI subcommands (`vulnora fix`, `vulnora verify`, `vulnora mcp`).
"""

import json
from pathlib import Path
import pytest

from vulnora.cli import main
from vulnora.core.models import Finding, OrchestratorResult, ScannerResult, Severity


class TestCLIPhase5:
    """Tests for Phase 5 CLI commands."""

    @pytest.fixture
    def target_file(self, tmp_path: Path) -> Path:
        code = """import os

def handle_user_command(user_cmd):
    # Vulnerable line
    os.system(user_cmd)
    return True
"""
        file_path = tmp_path / "app.py"
        file_path.write_text(code, encoding="utf-8")
        return file_path

    def test_cli_fix_no_verify_dry_run(self, tmp_path: Path, target_file: Path, capsys):
        rc = main([
            "-C", str(tmp_path),
            "fix",
            "--file", target_file.name,
            "--line", "5",
            "--rule", "B605",
            "--scanner", "bandit",
            "--dry-run",
            "--no-verify",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Vulnora AI Remediation Proposal (B605)" in captured.out
        assert "Replacement Code:" in captured.out
        assert "subprocess.run" in captured.out

    def test_cli_fix_dry_run_with_verification(self, tmp_path: Path, target_file: Path, capsys, mocker):
        # Mock scanner orchestrator to return clean verification
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            is_full_scan=False,
            scanner_results=[
                ScannerResult(
                    scanner_name="bandit",
                    status="COMPLETED",
                    findings=[],
                )
            ],
            findings=[],
        )
        mocker.patch("vulnora.engine.verifier.ScannerOrchestrator.run_scanners", return_value=mock_result)

        rc = main([
            "-C", str(tmp_path),
            "fix",
            "--file", target_file.name,
            "--line", "5",
            "--rule", "B605",
            "--scanner", "bandit",
            "--dry-run",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Vulnora AI Fix & Verify — [✔] VERIFIED CLEAN" in captured.out
        assert "Antibody ID" in captured.out
        assert "AGENTS.md Rule:" in captured.out

        # Verify AGENTS.md was created in target_root
        assert (tmp_path / "AGENTS.md").exists()
        assert "B605" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")

    def test_cli_fix_json_output(self, tmp_path: Path, target_file: Path, capsys, mocker):
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            is_full_scan=False,
            scanner_results=[ScannerResult(scanner_name="bandit", status="COMPLETED", findings=[])],
            findings=[],
        )
        mocker.patch("vulnora.engine.verifier.ScannerOrchestrator.run_scanners", return_value=mock_result)

        rc = main([
            "-C", str(tmp_path),
            "fix",
            "--file", target_file.name,
            "--line", "5",
            "--rule", "B605",
            "--scanner", "bandit",
            "--dry-run",
            "--json",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "proposal" in data
        assert "verification" in data
        assert data["verification"]["success"] is True

    def test_cli_verify_command(self, tmp_path: Path, target_file: Path, capsys, mocker):
        mock_result = OrchestratorResult(
            target_path=str(tmp_path),
            is_full_scan=False,
            scanner_results=[ScannerResult(scanner_name="bandit", status="COMPLETED", findings=[])],
            findings=[],
        )
        mocker.patch("vulnora.engine.verifier.ScannerOrchestrator.run_scanners", return_value=mock_result)

        rc = main([
            "-C", str(tmp_path),
            "verify",
            "--file", target_file.name,
            "--scanner", "bandit",
            "--rule", "B605",
            "--rule-text", "Always avoid os.system in python.",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Vulnora AI Patch Verification — [✔] VERIFIED CLEAN" in captured.out
        assert "Antibody ID:" in captured.out
