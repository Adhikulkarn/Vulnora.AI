"""
Unit and integration tests for Vulnora security scanner installer and activity logging.
"""

from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from vulnora.cli import main
from vulnora.core.models import Finding, RemediationProposal, Severity, VerificationResult
from vulnora.scanners.installer import (
    detect_platform,
    get_extended_path,
    get_missing_scanners,
    get_missing_standalone_scanners,
    get_vulnora_bin_dir,
    install_missing_scanners,
    install_scanner,
    is_binary_installed,
    verify_all_scanners,
    _safe_extract_tar_binary,
    _safe_extract_zip_binary,
)
from vulnora.tui.app import VulnoraTUIApp


class TestScannerInstaller:
    """Tests for platform detection, archive extraction, PATH resolution, and installation."""

    def test_detect_platform(self):
        system, arch = detect_platform()
        assert system in ("linux", "darwin", "windows")
        assert arch in ("amd64", "arm64")

    def test_get_vulnora_bin_dir_and_extended_path(self, tmp_path: Path, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))
        resolved_bin = get_vulnora_bin_dir()
        assert resolved_bin == custom_bin.resolve()

        ext_path = get_extended_path()
        parts = ext_path.split(os.pathsep)
        assert str(custom_bin.resolve()) in parts
        assert str(Path(sys.executable).parent.resolve()) in parts

    def test_is_binary_installed_with_custom_dir(self, tmp_path: Path, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        custom_bin.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))

        assert not is_binary_installed("test-mock-scanner-xyz")

        # Create mock executable
        mock_file = custom_bin / "test-mock-scanner-xyz"
        mock_file.write_text("#!/bin/sh\necho mock\n", encoding="utf-8")
        if os.name != "nt":
            mock_file.chmod(0o755)

        assert is_binary_installed("test-mock-scanner-xyz")

    def test_safe_extract_tar_prevents_path_traversal(self, tmp_path: Path):
        dest_dir = tmp_path / "extracted_bin"
        dest_dir.mkdir()

        tar_path = tmp_path / "archive.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            # Safe member
            safe_content = b"#!/bin/sh\necho safe\n"
            safe_info = tarfile.TarInfo(name="gitleaks")
            safe_info.size = len(safe_content)
            tar.addfile(safe_info, BytesIO(safe_content))

            # Dangerous traversal member (should NOT overwrite anything outside dest_dir)
            evil_content = b"evil payload"
            evil_info = tarfile.TarInfo(name="../evil.txt")
            evil_info.size = len(evil_content)
            tar.addfile(evil_info, BytesIO(evil_content))

        extracted = _safe_extract_tar_binary(tar_path, dest_dir, "gitleaks")
        assert extracted is not None
        assert extracted.is_file()
        assert extracted.name == "gitleaks"
        # Ensure evil.txt was never extracted outside
        assert not (tmp_path / "evil.txt").exists()

    def test_safe_extract_zip_prevents_path_traversal(self, tmp_path: Path):
        dest_dir = tmp_path / "extracted_bin"
        dest_dir.mkdir()

        zip_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("trivy", b"#!/bin/sh\necho trivy\n")
            zf.writestr("../evil_zip.txt", b"evil zip content")

        extracted = _safe_extract_zip_binary(zip_path, dest_dir, "trivy")
        assert extracted is not None
        assert extracted.is_file()
        assert extracted.name == "trivy"
        assert not (tmp_path / "evil_zip.txt").exists()

    def test_install_scanner_offline_graceful_handling(self, tmp_path: Path, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))

        logs = []
        # Attempt to install with network failure
        with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
            success = install_scanner("gitleaks", on_log=logs.append, force=True)

        assert success is False
        assert any("Failed to download gitleaks" in log for log in logs)

    def test_install_missing_scanners_skips_installed(self, tmp_path: Path, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        custom_bin.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))

        # Pretend all 3 standalone scanners are installed
        for name in ("gitleaks", "osv-scanner", "trivy"):
            f = custom_bin / name
            f.write_text("mock", encoding="utf-8")
            if os.name != "nt":
                f.chmod(0o755)

        logs = []
        results = install_missing_scanners(on_log=logs.append, force=False)
        assert results["gitleaks"] is True
        assert results["osv-scanner"] is True
        assert results["trivy"] is True
        assert any("already installed" in log for log in logs)

    def test_verify_all_scanners_output_schema(self, tmp_path: Path, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))

        statuses = verify_all_scanners()
        for expected in ("bandit", "semgrep", "gitleaks", "osv-scanner", "trivy", "zap"):
            assert expected in statuses
            info = statuses[expected]
            assert "name" in info
            assert "installed" in info
            assert "type" in info
            assert "required" in info


class TestCLISetup:
    """Tests for `vulnora setup` and `vulnora init --no-download` CLI commands."""

    def test_cli_setup_json_output(self, tmp_path: Path, capsys, monkeypatch):
        custom_bin = tmp_path / "custom_bin"
        custom_bin.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("VULNORA_BIN_DIR", str(custom_bin))

        # Create mock binaries so all required pass
        for name in ("bandit", "semgrep", "gitleaks", "osv-scanner", "trivy"):
            f = custom_bin / name
            f.write_text("mock", encoding="utf-8")
            if os.name != "nt":
                f.chmod(0o755)

        rc = main(["-C", str(tmp_path), "setup", "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["all_required_installed"] is True
        assert "gitleaks" in data["scanners"]
        assert data["scanners"]["gitleaks"]["installed"] is True

    def test_cli_init_with_no_download_flag(self, tmp_path: Path, capsys):
        import subprocess
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)

        with patch("vulnora.scanners.installer.install_missing_scanners") as mock_install:
            rc = main(["-C", str(tmp_path), "init", "--no-download"])
            assert rc == 0
            mock_install.assert_not_called()

        captured = capsys.readouterr()
        assert "Vulnora initialization complete!" in captured.out


@pytest.mark.anyio
class TestTUIActivityLogs:
    """Tests for live RichLog activity logs and auto-focus transitions."""

    async def test_tui_activity_log_streaming_and_tab_focus(self, tmp_path: Path):
        finding = Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Insecure Shell Execution",
            description="Use of os.system",
            file_path="app.py",
            line_number=5,
        )

        app = VulnoraTUIApp(
            target_dir=tmp_path,
            findings=[finding],
            auto_scan_on_mount=False,
        )

        async with app.run_test() as pilot:
            # 1. Verify Activity Logs tab exists in TabbedContent
            assert "tab-logs" in [pane.id for pane in app.details_tabs.query("TabPane")]

            # 2. Test thread-safe logging
            app._append_log("[bold cyan]Test stream log message[/bold cyan]")
            await pilot.pause()

            log_widget = app.query_one("#activity-log")
            assert log_widget is not None

            # 3. Trigger auto-fix -> verify focus switches to tab-logs during work
            with patch.object(app, "run_background_fix"):
                app._execute_auto_fix(finding)
                assert app.details_tabs._tabbed_content.active == "tab-logs"

            # 4. When scan completes with findings, focus switches to tab-snippet
            app._on_scan_completed([finding], None)
            assert app.details_tabs._tabbed_content.active == "tab-snippet"

            # 5. When scan completes with 0 findings, focus stays on tab-logs
            app._on_scan_completed([], None)
            assert app.details_tabs._tabbed_content.active == "tab-logs"

            # 6. When remediation finishes, focus switches to tab-diff
            proposal = RemediationProposal(
                finding_id="f-001",
                rule_id="B605",
                file_path="app.py",
                root_cause="os.system call",
                explanation="Safe subprocess",
                replacement_code="subprocess.run(['echo'], shell=False)",
            )
            res = VerificationResult(
                success=True,
                file_path="app.py",
                scanner_name="bandit",
                rule_id="B605",
                diff_unified="+subprocess.run(['echo'], shell=False)",
                antibody_id="ab_B605_test",
                message="Clean",
            )
            app._on_fix_completed(finding=finding, proposal=proposal, res=res, error=None)
            assert app.details_tabs._tabbed_content.active == "tab-diff"
