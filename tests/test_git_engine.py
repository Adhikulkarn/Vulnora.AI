"""
Unit tests for Vulnora AI subprocess-safe Git engine (`vulnora.core.git_engine`).
"""

import os
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vulnora.core.git_engine import (
    DEFAULT_GIT_TIMEOUT,
    VULNORA_HOOK_MARKER,
    GitCommandError,
    GitEngine,
    GitEngineError,
    GitNotInstalledError,
    GitTimeoutError,
    NotAGitRepositoryError,
)
from vulnora.core.models import PushRefUpdate


class TestGitEngineSubprocessSafety:
    """Verifies that all external commands use shell=False and explicit timeouts."""

    def test_run_git_enforces_shell_false_and_timeout(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path, timeout=7.5)
        mock_res = subprocess.CompletedProcess(
            args=["git", "status"],
            returncode=0,
            stdout="clean",
            stderr="",
        )

        with patch("subprocess.run", return_value=mock_res) as mock_run:
            engine._run_git(["status"])

            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["shell"] is False
            assert call_kwargs["timeout"] == 7.5
            assert call_kwargs["capture_output"] is True
            assert call_kwargs["text"] is True
            assert mock_run.call_args[0][0] == ["git", "status"]

    def test_run_git_rejects_non_sequence_args(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path)
        with pytest.raises(TypeError, match="must be a sequence of strings"):
            # Attempting to pass raw shell string instead of list
            engine._run_git("status")  # type: ignore

    def test_timeout_expired_raises_git_timeout_error(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path, timeout=2.0)
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["git", "push"], timeout=2.0)):
            with pytest.raises(GitTimeoutError) as exc_info:
                engine._run_git(["push"])
            assert exc_info.value.timeout == 2.0
            assert "git push" in str(exc_info.value)

    def test_file_not_found_raises_git_not_installed_error(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path)
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(GitNotInstalledError):
                engine._run_git(["status"])

    def test_check_true_raises_git_command_error(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path)
        failed_proc = subprocess.CompletedProcess(
            args=["git", "rev-parse", "HEAD"],
            returncode=128,
            stdout="",
            stderr="fatal: ambiguous argument 'HEAD': unknown revision",
        )
        with patch("subprocess.run", return_value=failed_proc):
            with pytest.raises(GitCommandError) as exc_info:
                engine._run_git(["rev-parse", "HEAD"], check=True)
            assert exc_info.value.returncode == 128
            assert "fatal: ambiguous argument" in exc_info.value.stderr


class TestGitEngineWithRealRepository:
    """Tests GitEngine against real local Git repositories in temporary directories."""

    @pytest.fixture
    def real_git_repo(self, tmp_path: Path) -> Path:
        """Initializes a clean real Git repository in tmp_path."""
        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir()
        # Initialize git repo with safe options
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Vulnora Tester"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@vulnora.ai"], cwd=repo_dir, check=True, capture_output=True)
        return repo_dir

    def test_is_git_installed_on_system(self):
        engine = GitEngine()
        assert engine.is_git_installed() is True

    def test_is_git_repository(self, real_git_repo: Path, tmp_path: Path):
        engine = GitEngine(repo_path=real_git_repo)
        assert engine.is_git_repository() is True

        non_repo_dir = tmp_path / "not_a_repo"
        non_repo_dir.mkdir()
        non_repo_engine = GitEngine(repo_path=non_repo_dir)
        assert non_repo_engine.is_git_repository() is False

    def test_get_git_root(self, real_git_repo: Path):
        engine = GitEngine(repo_path=real_git_repo)
        assert engine.get_git_root() == real_git_repo.resolve()

        # Test from subdirectory
        sub = real_git_repo / "sub" / "pkg"
        sub.mkdir(parents=True)
        sub_engine = GitEngine(repo_path=sub)
        assert sub_engine.get_git_root() == real_git_repo.resolve()

    def test_get_current_branch_and_head_commit(self, real_git_repo: Path):
        engine = GitEngine(repo_path=real_git_repo)
        assert engine.get_current_branch() == "main"
        # No commits yet
        assert engine.get_head_commit() is None

        # Create initial commit
        test_file = real_git_repo / "README.md"
        test_file.write_text("# Vulnora Test Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=real_git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=real_git_repo, check=True)

        commit = engine.get_head_commit()
        assert commit is not None
        assert len(commit) >= 40
        short_commit = engine.get_head_commit(short=True)
        assert short_commit is not None
        assert len(short_commit) < len(commit)

    def test_is_dirty(self, real_git_repo: Path):
        engine = GitEngine(repo_path=real_git_repo)
        # Untracked file makes it dirty
        assert engine.is_dirty() is False
        new_file = real_git_repo / "dirty.txt"
        new_file.write_text("changes\n", encoding="utf-8")
        assert engine.is_dirty(include_untracked=True) is True
        assert engine.is_dirty(include_untracked=False) is False

        # Stage and commit
        subprocess.run(["git", "add", "dirty.txt"], cwd=real_git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "add dirty"], cwd=real_git_repo, check=True)
        assert engine.is_dirty() is False

        # Modify tracked file
        new_file.write_text("modified\n", encoding="utf-8")
        assert engine.is_dirty(include_untracked=False) is True

    def test_get_changed_files_and_diff(self, real_git_repo: Path):
        engine = GitEngine(repo_path=real_git_repo)
        f1 = real_git_repo / "file1.txt"
        f1.write_text("line 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "file1.txt"], cwd=real_git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "commit 1"], cwd=real_git_repo, check=True)

        f2 = real_git_repo / "file2.txt"
        f2.write_text("line 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "file2.txt"], cwd=real_git_repo, check=True)

        staged = engine.get_changed_files(staged_only=True)
        assert staged == ["file2.txt"]

        subprocess.run(["git", "commit", "-m", "commit 2"], cwd=real_git_repo, check=True)
        changed = engine.get_changed_files(base_ref="HEAD~1", target_ref="HEAD")
        assert changed == ["file2.txt"]

        diff = engine.get_diff(base_ref="HEAD~1", target_ref="HEAD")
        assert "+line 2" in diff


class TestPrePushHookManagement:
    """Tests safe installation, preservation of third-party hooks, and removal."""

    def test_install_and_detect_hook(self, tmp_path: Path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)

        engine = GitEngine(repo_path=repo_dir)
        assert engine.is_hook_installed() is False

        hook_path = engine.install_pre_push_hook()
        assert hook_path.exists()
        assert engine.is_hook_installed() is True
        # Verify executable permissions
        assert os.access(hook_path, os.X_OK)

        # Content has Vulnora marker
        content = hook_path.read_text(encoding="utf-8")
        assert VULNORA_HOOK_MARKER in content

    def test_install_preserves_existing_user_hook_via_chaining(self, tmp_path: Path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)

        engine = GitEngine(repo_path=repo_dir)
        hooks_dir = engine.get_hooks_dir()
        assert hooks_dir is not None
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # User's existing custom pre-push hook
        existing_hook = hooks_dir / "pre-push"
        existing_hook.write_text("#!/bin/sh\necho 'custom developer hook running'\nexit 0\n", encoding="utf-8")
        existing_hook.chmod(0o755)

        # Install Vulnora pre-push hook
        new_hook = engine.install_pre_push_hook(force=False)
        assert new_hook.exists()

        # Verify backup was created
        backup_hook = hooks_dir / "pre-push.vulnora-orig"
        assert backup_hook.exists()
        assert "custom developer hook running" in backup_hook.read_text(encoding="utf-8")

        # Verify chaining call in new hook
        new_content = new_hook.read_text(encoding="utf-8")
        assert "pre-push.vulnora-orig" in new_content

        # Test hook removal restores the user's original hook
        removed = engine.remove_pre_push_hook()
        assert removed is True
        assert existing_hook.exists()
        assert not backup_hook.exists()
        assert "custom developer hook running" in existing_hook.read_text(encoding="utf-8")

    def test_install_fails_outside_git_repo(self, tmp_path: Path):
        non_git = tmp_path / "not_git"
        non_git.mkdir()
        engine = GitEngine(repo_path=non_git)
        with pytest.raises(NotAGitRepositoryError):
            engine.install_pre_push_hook()


class TestPushRefParsing:
    """Tests parsing of Git pre-push hook stdin."""

    def test_parse_normal_branch_push(self):
        engine = GitEngine()
        raw = "refs/heads/feature-auth 1111111111111111111111111111111111111111 refs/heads/feature-auth 2222222222222222222222222222222222222222\n"
        updates = engine.parse_push_refs(raw)
        assert len(updates) == 1
        u = updates[0]
        assert u.branch_name == "feature-auth"
        assert u.is_branch is True
        assert u.is_deletion is False
        assert u.is_tag is False

    def test_parse_protected_branch_push(self):
        engine = GitEngine()
        raw = "refs/heads/main aaaaaaaa refs/heads/main bbbbbbbb\n"
        updates = engine.parse_push_refs(raw)
        assert len(updates) == 1
        assert updates[0].branch_name == "main"
        assert engine.is_protected_branch(updates[0].branch_name) is True

    def test_parse_branch_deletion(self):
        engine = GitEngine()
        # All zeros local SHA indicates branch deletion in git pre-push
        raw = "(delete) 0000000000000000000000000000000000000000 refs/heads/feature-old 1111111111111111111111111111111111111111\n"
        updates = engine.parse_push_refs(raw)
        assert len(updates) == 1
        assert updates[0].is_deletion is True
        assert updates[0].branch_name == "feature-old"

    def test_parse_tag_push(self):
        engine = GitEngine()
        raw = "refs/tags/v1.0.0 aaaa refs/tags/v1.0.0 bbbb\n"
        updates = engine.parse_push_refs(raw)
        assert len(updates) == 1
        assert updates[0].is_tag is True
        assert updates[0].is_branch is False

    def test_parse_multiple_refs_and_empty_input(self):
        engine = GitEngine()
        assert engine.parse_push_refs("") == []
        assert engine.parse_push_refs("   \n\n  ") == []

        multi = (
            "refs/heads/main 1111 refs/heads/main 2222\n"
            "refs/heads/dev 3333 refs/heads/dev 4444\n"
        )
        updates = engine.parse_push_refs(multi)
        assert len(updates) == 2
        assert updates[0].branch_name == "main"
        assert updates[1].branch_name == "dev"


class TestGitIgnoreUpdate:
    """Tests updating .gitignore with Vulnora artifacts."""

    def test_update_gitignore_creates_file_and_adds_patterns(self, tmp_path: Path):
        engine = GitEngine(repo_path=tmp_path)
        added = engine.update_gitignore()
        assert len(added) > 0
        gitignore_path = tmp_path / ".gitignore"
        assert gitignore_path.exists()

        content = gitignore_path.read_text(encoding="utf-8")
        assert ".vulnora/memory.json" in content
        assert ".vulnora/cache/" in content

        # Repeated run should not duplicate
        added_second = engine.update_gitignore()
        assert len(added_second) == 0


class TestLanguageAgnosticDetection:
    """Verifies that the engine detects diverse languages from project manifests."""

    def test_detect_rust_repo(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\nname = 'test'\n", encoding="utf-8")
        engine = GitEngine(repo_path=tmp_path)
        langs = engine.detect_repository_languages()
        assert langs.primary_language == "Rust"
        assert "Rust" in langs.detected_languages
        assert "Cargo.toml" in langs.manifest_files

    def test_detect_go_repo(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module example.com/test\ngo 1.22\n", encoding="utf-8")
        engine = GitEngine(repo_path=tmp_path)
        langs = engine.detect_repository_languages()
        assert langs.primary_language == "Go"
        assert "Go" in langs.detected_languages
        assert "go.mod" in langs.manifest_files

    def test_detect_typescript_repo(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
        engine = GitEngine(repo_path=tmp_path)
        langs = engine.detect_repository_languages()
        assert "TypeScript" in langs.detected_languages
        assert "JavaScript" in langs.detected_languages

    def test_detect_python_repo(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        engine = GitEngine(repo_path=tmp_path)
        langs = engine.detect_repository_languages()
        assert langs.primary_language == "Python"

    def test_detect_polyglot_repo(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        engine = GitEngine(repo_path=tmp_path)
        langs = engine.detect_repository_languages()
        assert "Rust" in langs.detected_languages
        assert "Python" in langs.detected_languages
        # Rust has 2 manifests, Python has 1 -> Rust primary
        assert langs.primary_language == "Rust"


class TestRepoStatusDiagnostics:
    """Tests assembling full repo diagnostic status."""

    def test_get_repo_status_on_real_repo(self, tmp_path: Path):
        repo_dir = tmp_path / "diag_repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init", "-b", "production"], cwd=repo_dir, check=True, capture_output=True)
        (repo_dir / "go.mod").write_text("module test\n", encoding="utf-8")

        engine = GitEngine(repo_path=repo_dir)
        status = engine.get_repo_status(protected_branches=["main", "production"])

        assert status.is_git is True
        assert status.current_branch == "production"
        assert status.is_current_branch_protected is True
        assert "Go" in status.detected_languages
        assert status.is_dirty is True  # untracked go.mod
