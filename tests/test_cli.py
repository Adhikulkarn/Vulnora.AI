"""
Integration and CLI tests for Vulnora AI (`vulnora.cli`).
"""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from vulnora.cli import build_parser, main


class TestCLI:
    """Tests for the Vulnora CLI entry point."""

    def test_cli_version(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "vulnora 0.1.0" in captured.out

    def test_cli_help_no_args(self, capsys):
        rc = main([])
        assert rc == 0
        captured = capsys.readouterr()
        assert "usage: vulnora" in captured.out

    def test_cli_init_command(self, tmp_path: Path, capsys):
        # Create git repo in tmp_path
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        (tmp_path / "Cargo.toml").write_text("[package]\nname = 'test-cli'\n", encoding="utf-8")

        rc = main(["-C", str(tmp_path), "init"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Initializing Vulnora AI" in captured.out
        assert "Detected Primary Language: Rust" in captured.out
        assert "Vulnora initialization complete!" in captured.out

        # Verify config exists
        assert (tmp_path / ".vulnora" / "config.yaml").exists()
        # Verify pre-push hook installed
        assert (tmp_path / ".git" / "hooks" / "pre-push").exists()
        # Verify .gitignore updated
        assert (tmp_path / ".gitignore").exists()

    def test_cli_init_force_flag(self, tmp_path: Path, capsys):
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        # First init
        main(["-C", str(tmp_path), "init", "--name", "first-name"])
        # Second init without force
        rc = main(["-C", str(tmp_path), "init", "--name", "second-name"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Configuration already exists" in captured.out

        # Second init with force
        rc_force = main(["-C", str(tmp_path), "init", "--name", "second-name", "--force"])
        assert rc_force == 0

    def test_cli_status_command(self, tmp_path: Path, capsys):
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        main(["-C", str(tmp_path), "init"])
        capsys.readouterr()  # clear buffer

        rc = main(["-C", str(tmp_path), "status"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Vulnora AI Diagnostic Status" in captured.out
        assert "Git Installed    : Yes" in captured.out
        assert "Git Repository   : Yes" in captured.out
        assert "Protected Branch : YES (Protected)" in captured.out

    def test_cli_status_json_format(self, tmp_path: Path, capsys):
        subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
        main(["-C", str(tmp_path), "init"])
        capsys.readouterr()

        rc = main(["-C", str(tmp_path), "check-git", "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["git_installed"] is True
        assert data["repository"]["is_git"] is True
        assert data["repository"]["current_branch"] == "main"
        assert data["repository"]["is_current_branch_protected"] is True
        assert data["config"]["config_exists"] is True
