"""
Tests for Vulnora AI CLI foundation.
Covers init, scan, and guard commands, git utils, and configuration loading.
"""

import json
from pathlib import Path
import tempfile
import unittest
from typer.testing import CliRunner

from vulnora.cli.config import get_protected_branches, load_config
from vulnora.cli.git_utils import is_git_repository, is_protected_branch, update_gitignore
from vulnora.cli.main import app

runner = CliRunner()


class VulnoraCLITestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_version(self):
        result = runner.invoke(app, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Vulnora AI version", result.output)

    def test_cli_help(self):
        result = runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("init", result.output)
        self.assertIn("scan", result.output)
        self.assertIn("guard", result.output)

    def test_init_command_creates_files(self):
        result = runner.invoke(app, ["init", "--path", str(self.project_path)])
        self.assertEqual(result.exit_code, 0)

        # Check .vulnora directory created
        vulnora_dir = self.project_path / ".vulnora"
        self.assertTrue(vulnora_dir.exists())

        # Check config.yaml created
        config_file = vulnora_dir / "config.yaml"
        self.assertTrue(config_file.exists())
        config = load_config(self.project_path)
        self.assertEqual(config["git"]["protected_branches"], ["main", "production"])

        # Check memory.json created
        memory_file = vulnora_dir / "memory.json"
        self.assertTrue(memory_file.exists())
        with memory_file.open("r", encoding="utf-8") as f:
            mem_data = json.load(f)
            self.assertIn("issue_memory", mem_data)

    def test_guard_command_protected_branch(self):
        # Initialize project first
        runner.invoke(app, ["init", "--path", str(self.project_path)])

        # Test evaluating protected branch 'main'
        result = runner.invoke(app, ["guard", "--path", str(self.project_path), "--branch", "main"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIGH-SECURITY GUARD ACTIVE", result.output)
        self.assertIn("ZERO CRITICAL", result.output)

    def test_guard_command_feature_branch(self):
        # Initialize project first
        runner.invoke(app, ["init", "--path", str(self.project_path)])

        # Test evaluating feature branch
        result = runner.invoke(app, ["guard", "--path", str(self.project_path), "--branch", "feat/security-fix"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("FEATURE BRANCH DETECTED", result.output)
        self.assertIn("STANDARD FEATURE GUARD", result.output)

    def test_scan_command_modular_execution(self):
        # Initialize project first
        runner.invoke(app, ["init", "--path", str(self.project_path)])

        result = runner.invoke(app, [
            "scan",
            "--path", str(self.project_path),
            "--scanner", "gitleaks",
            "--scanner", "trivy"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("GITLEAKS", result.output)
        self.assertIn("TRIVY", result.output)
        self.assertIn("Security Scanner Execution Summary", result.output)

    def test_gitignore_update(self):
        gitignore = self.project_path / ".gitignore"
        gitignore.write_text("*.pyc\n__pycache__/\n", encoding="utf-8")

        added = update_gitignore(self.project_path, [".vulnora/memory.json", ".vulnora/cache/"])
        self.assertEqual(len(added), 2)

        content = gitignore.read_text(encoding="utf-8")
        self.assertIn(".vulnora/memory.json", content)
        self.assertIn(".vulnora/cache/", content)

        # Running again should not duplicate
        added_second = update_gitignore(self.project_path, [".vulnora/memory.json"])
        self.assertEqual(len(added_second), 0)

    def test_is_protected_branch_helper(self):
        protected = ["main", "production"]
        self.assertTrue(is_protected_branch("main", protected))
        self.assertTrue(is_protected_branch("MAIN", protected))
        self.assertTrue(is_protected_branch("production", protected))
        self.assertFalse(is_protected_branch("feature/branch", protected))
        self.assertFalse(is_protected_branch("dev", protected))

