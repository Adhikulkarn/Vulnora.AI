"""
Integration tests for Phase 6 CLI commands (`guard`, `pack export/import`, `hook`, `tui`).
"""

import json
from pathlib import Path
import sys

import pytest

from vulnora.cli import build_parser, main
from vulnora.core.models import Finding, ImmuneRecord, Severity
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestCLIPhase6:
    """Tests for Phase 6 CLI additions."""

    def test_pack_export_and_import(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora pack export` and `vulnora pack import` commands."""
        # Initialize immune store with 1 record
        vulnora_dir = tmp_path / ".vulnora"
        vulnora_dir.mkdir(parents=True, exist_ok=True)
        store = ImmuneMemoryStore(memory_path=vulnora_dir / "memory.json")
        rec = ImmuneRecord(
            id="ab_B605_test1",
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            language="python",
            exact_hash="hash123",
            ast_signature="ast_sig_123",
            anonymized_template="subprocess.run(VAR_1)",
            resolution="REMEDIATED",
            agents_rule="Use subprocess.run without shell=True.",
        )
        store.save_record(rec)

        # 1. Export pack to JSON
        pack_json = tmp_path / "test_pack.json"
        rc_export = main(["-C", str(tmp_path), "pack", "export", "--output", str(pack_json)])
        assert rc_export == 0
        assert pack_json.is_file()

        # 2. Clear store and import pack
        store.clear()
        assert store.count() == 0

        rc_import = main(["-C", str(tmp_path), "pack", "import", str(pack_json)])
        assert rc_import == 0
        assert store.count() == 1
        imported = store.get_record("ab_B605_test1")
        assert imported is not None
        assert imported.rule_id == "B605"

    def test_guard_headless_clean_repo(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora guard --no-tui` on clean repo exits with code 0."""
        # Mock scanner orchestrator returning zero findings
        class MockOrchestrator:
            def __init__(self, config=None):
                pass

            def run_scanners(self, **kwargs):
                from vulnora.core.models import OrchestratorResult
                return OrchestratorResult(target_path=str(tmp_path), is_full_scan=False, findings=[])

        monkeypatch.setattr("vulnora.cli.ScannerOrchestrator", MockOrchestrator)

        rc = main(["-C", str(tmp_path), "guard", "--no-tui"])
        assert rc == 0

    def test_guard_headless_blocks_on_critical_findings(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora guard --no-tui` blocks (exit 1) on CRITICAL/HIGH findings."""
        class MockOrchestrator:
            def __init__(self, config=None):
                pass

            def run_scanners(self, **kwargs):
                from vulnora.core.models import OrchestratorResult
                return OrchestratorResult(
                    target_path=str(tmp_path),
                    is_full_scan=False,
                    findings=[
                        Finding(
                            rule_id="B605",
                            scanner_name="bandit",
                            severity=Severity.HIGH,
                            title="Command Injection",
                            description="os.system call",
                            file_path="app.py",
                            line_number=12,
                        )
                    ],
                )

        monkeypatch.setattr("vulnora.cli.ScannerOrchestrator", MockOrchestrator)

        rc = main(["-C", str(tmp_path), "guard", "--no-tui"])
        assert rc == 1

    def test_guard_hook_subcommand(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora hook pre-push` routes to handle_guard."""
        class MockOrchestrator:
            def __init__(self, config=None):
                pass

            def run_scanners(self, **kwargs):
                from vulnora.core.models import OrchestratorResult
                return OrchestratorResult(target_path=str(tmp_path), is_full_scan=False, findings=[])

        monkeypatch.setattr("vulnora.cli.ScannerOrchestrator", MockOrchestrator)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        monkeypatch.setenv("VULNORA_NO_TUI", "1")

        rc = main(["-C", str(tmp_path), "hook", "pre-push"])
        assert rc == 0

    def test_tui_subcommand_dispatch(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora tui` invokes launch_tui."""
        launched = []

        def mock_launch_tui(target_dir=None, **kwargs):
            launched.append(target_dir)
            return 0

        monkeypatch.setattr("vulnora.tui.launch_tui", mock_launch_tui)

        rc = main(["-C", str(tmp_path), "tui"])
        assert rc == 0
        assert len(launched) == 1
        assert launched[0] == tmp_path.resolve()

    def test_default_launches_tui_when_interactive(self, tmp_path: Path, monkeypatch):
        """Verifies `vulnora` with no subcommand invokes launch_tui when sys.stdin.isatty() is True."""
        launched = []

        def mock_launch_tui(target_dir=None, **kwargs):
            launched.append(target_dir)
            return 0

        monkeypatch.setattr("vulnora.tui.launch_tui", mock_launch_tui)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        rc = main(["-C", str(tmp_path)])
        assert rc == 0
        assert len(launched) == 1
