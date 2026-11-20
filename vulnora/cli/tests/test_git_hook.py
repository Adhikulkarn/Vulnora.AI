"""
Comprehensive tests for Vulnora AI Git Pre-Push Hook integration.
Verifies all 10 core safety, detection, and lifecycle requirements using temporary Git repositories.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
from typer.testing import CliRunner

from vulnora.cli.config import load_config, save_config
from vulnora.cli.git_utils import (
    PushRefUpdate,
    get_git_hooks_dir,
    is_protected_branch,
    parse_push_refs,
)
from vulnora.cli.hook_manager import (
    CHAINED_SUFFIX,
    HOOK_MARKER,
    HOOK_NAME,
    get_hook_path,
    install_pre_push_hook,
    is_hook_installed,
)
from vulnora.cli.main import app

runner = CliRunner()


class GitPrePushHookIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name)
        # Initialize a real Git repository in temp directory
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "TestUser"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "test@example.com"], check=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_init_installs_pre_push_hook(self):
        """1. Verify `vulnora init` creates an executable pre-push hook in .git/hooks/."""
        result = runner.invoke(app, ["init", "--path", str(self.repo_dir)])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Git Pre-Push Hook", result.output)

        hook_file = get_hook_path(self.repo_dir)
        self.assertIsNotNone(hook_file)
        self.assertTrue(hook_file.exists())
        self.assertTrue(is_hook_installed(self.repo_dir))

        content = hook_file.read_text(encoding="utf-8")
        self.assertIn(HOOK_MARKER, content)
        self.assertIn("vulnora guard", content)

    def test_2_init_idempotent_no_duplicate_hooks(self):
        """2. Verify running `vulnora init` multiple times does not duplicate or corrupt hooks."""
        # First run
        res1 = runner.invoke(app, ["init", "--path", str(self.repo_dir)])
        self.assertEqual(res1.exit_code, 0)
        hook_file = get_hook_path(self.repo_dir)
        original_content = hook_file.read_text(encoding="utf-8")

        # Second run
        res2 = runner.invoke(app, ["init", "--path", str(self.repo_dir)])
        self.assertEqual(res2.exit_code, 0)
        self.assertIn("idempotent", res2.output.lower())

        second_content = hook_file.read_text(encoding="utf-8")
        self.assertEqual(original_content, second_content)
        # Ensure marker occurs only once
        self.assertEqual(second_content.count(HOOK_MARKER), 1)

    def test_3_push_to_main_triggers_guard(self):
        """3. Verify pushing to refs/heads/main triggers the high-security guard intercept."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        stdin_data = "refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222\n"
        result = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=stdin_data,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIGH-SECURITY GUARD INTERCEPT", result.output)
        self.assertIn("main", result.output)
        self.assertIn("ZERO CRITICAL", result.output)

    def test_4_push_to_production_triggers_guard(self):
        """4. Verify pushing to refs/heads/production triggers the high-security guard intercept."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        stdin_data = "refs/heads/production aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/production bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        result = runner.invoke(
            app,
            ["guard", "origin", "git@github.com:org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=stdin_data,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIGH-SECURITY GUARD INTERCEPT", result.output)
        self.assertIn("production", result.output)

    def test_5_push_to_develop_allows_push_unprotected(self):
        """5. Verify pushing to an unprotected branch (e.g. develop) bypasses security checks."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        stdin_data = "refs/heads/develop 1234123412341234123412341234123412341234 refs/heads/develop 5678567856785678567856785678567856785678\n"
        result = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=stdin_data,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Push targeting unprotected branch(es): develop", result.output)
        self.assertIn("Security checks skipped for unprotected branches", result.output)

    def test_6_custom_protected_branches_yaml(self):
        """6. Verify custom protected branches defined in .vulnora/config.yaml are respected."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        # Override config.yaml with custom protected branches
        config = load_config(self.repo_dir)
        config["git"]["protected_branches"] = ["staging", "stable"]
        save_config(config, self.repo_dir)

        # 'main' should now be unprotected
        res_main = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input="refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222\n",
        )
        self.assertEqual(res_main.exit_code, 0)
        self.assertIn("Push targeting unprotected branch(es): main", res_main.output)

        # 'staging' should trigger the guard
        res_staging = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input="refs/heads/staging 3333333333333333333333333333333333333333 refs/heads/staging 4444444444444444444444444444444444444444\n",
        )
        self.assertEqual(res_staging.exit_code, 0)
        self.assertIn("HIGH-SECURITY GUARD INTERCEPT", res_staging.output)
        self.assertIn("staging", res_staging.output)

    def test_7_multiple_branch_updates(self):
        """7. Verify multiple ref updates in a single push intercept when any target is protected."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        stdin_data = (
            "refs/heads/feature/auth 1111111111111111111111111111111111111111 refs/heads/feature/auth 2222222222222222222222222222222222222222\n"
            "refs/heads/main 3333333333333333333333333333333333333333 refs/heads/main 4444444444444444444444444444444444444444\n"
        )
        result = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=stdin_data,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIGH-SECURITY GUARD INTERCEPT", result.output)
        self.assertIn("main", result.output)

    def test_8_preserves_and_chains_existing_hooks(self):
        """8. Verify existing developer hooks are preserved as .pre-vulnora and chained."""
        hooks_dir = get_git_hooks_dir(self.repo_dir)
        hooks_dir.mkdir(parents=True, exist_ok=True)
        existing_hook = hooks_dir / HOOK_NAME
        existing_code = "#!/bin/sh\necho 'CUSTOM PRE-EXISTING DEVELOPER HOOK'\nexit 0\n"
        existing_hook.write_text(existing_code, encoding="utf-8")

        # Run vulnora init
        result = runner.invoke(app, ["init", "--path", str(self.repo_dir)])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(".pre-vulnora", result.output)

        # Check chained backup exists with original content
        chained_file = hooks_dir / f"{HOOK_NAME}{CHAINED_SUFFIX}"
        self.assertTrue(chained_file.exists())
        self.assertEqual(chained_file.read_text(encoding="utf-8"), existing_code)

        # Active hook contains Vulnora and chains to .pre-vulnora
        active_content = existing_hook.read_text(encoding="utf-8")
        self.assertIn(HOOK_MARKER, active_content)
        self.assertIn("$0.pre-vulnora", active_content)

    def test_9_branch_deletion_and_tag_pushes(self):
        """9. Verify branch deletion and tag pushes bypass security scanning."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        # Tag push
        tag_stdin = "refs/tags/v1.0.0 1111111111111111111111111111111111111111 refs/tags/v1.0.0 0000000000000000000000000000000000000000\n"
        res_tag = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=tag_stdin,
        )
        self.assertEqual(res_tag.exit_code, 0)
        self.assertIn("Push contains only tags or branch deletions", res_tag.output)

        # Branch deletion (40 zeros as local sha)
        del_stdin = "refs/heads/feature-old 0000000000000000000000000000000000000000 refs/heads/feature-old 1111111111111111111111111111111111111111\n"
        res_del = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=del_stdin,
        )
        self.assertEqual(res_del.exit_code, 0)
        self.assertIn("Push contains only tags or branch deletions", res_del.output)

    def test_10_malformed_input_and_git_errors(self):
        """10. Verify malformed Git pre-push hook inputs fail safely with clear error messages."""
        runner.invoke(app, ["init", "--path", str(self.repo_dir)])

        # Malformed input (incomplete token line)
        malformed_stdin = "invalid_format_line_without_required_four_tokens\n"
        result = runner.invoke(
            app,
            ["guard", "origin", "https://github.com/org/repo.git", "--hook", "--path", str(self.repo_dir)],
            input=malformed_stdin,
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Git Pre-Push Error", result.output)
        self.assertIn("malformed ref update stream", result.output)

    def test_parse_push_refs_edge_cases(self):
        """Helper test: test parsing utility for edge cases."""
        # Empty input
        self.assertEqual(parse_push_refs(""), [])
        self.assertEqual(parse_push_refs("   \n  \n"), [])

        # Valid line
        line = "refs/heads/feat 1234567890123456789012345678901234567890 refs/heads/feat 0987654321098765432109876543210987654321"
        refs = parse_push_refs(line)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].branch_name, "feat")
        self.assertTrue(refs[0].is_branch)
        self.assertFalse(refs[0].is_deletion)
        self.assertFalse(refs[0].is_tag)


if __name__ == "__main__":
    unittest.main()
