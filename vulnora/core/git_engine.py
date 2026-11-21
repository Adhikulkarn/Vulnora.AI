"""
Subprocess-safe, language-agnostic Git engine for Vulnora AI.

Provides repository inspection, branch protection enforcement, ref parsing,
safe pre-push hook management, and project language detection.
Strictly executes all external commands with shell=False and explicit timeouts.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Union

from vulnora.core.config import DEFAULT_PROTECTED_BRANCHES
from vulnora.core.models import GitRepoStatus, PushRefUpdate, RepoLanguage

# Markers used to identify and chain hooks safely
VULNORA_HOOK_MARKER = "# VULNORA_PRE_PUSH_HOOK"
DEFAULT_GIT_TIMEOUT: float = 15.0


class GitEngineError(Exception):
    """Base exception for GitEngine operations."""
    pass


class GitNotInstalledError(GitEngineError):
    """Raised when the git executable is not found in PATH."""
    pass


class NotAGitRepositoryError(GitEngineError):
    """Raised when the target directory is not a Git repository."""
    pass


class GitTimeoutError(GitEngineError):
    """Raised when a Git command exceeds its execution timeout."""
    def __init__(self, command: Sequence[str], timeout: float):
        self.command = list(command)
        self.timeout = timeout
        super().__init__(f"Git command timed out after {timeout}s: {' '.join(self.command)}")


class GitCommandError(GitEngineError):
    """Raised when a Git command exits with a non-zero return code."""
    def __init__(self, command: Sequence[str], returncode: int, stdout: str, stderr: str):
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout.strip()
        self.stderr = stderr.strip()
        msg = f"Git command failed ({returncode}): {' '.join(self.command)}\n{self.stderr or self.stdout}"
        super().__init__(msg)


class GitEngine:
    """
    Subprocess-safe Git execution engine.
    Ensures safe, bounded execution of Git commands without shell interpolation.
    """

    def __init__(
        self,
        repo_path: Optional[Union[str, Path]] = None,
        timeout: float = DEFAULT_GIT_TIMEOUT,
    ):
        self.repo_path = Path(repo_path).resolve() if repo_path else Path.cwd().resolve()
        self.default_timeout = max(1.0, float(timeout))

    def _run_git(
        self,
        args: Sequence[str],
        check: bool = False,
        timeout: Optional[float] = None,
        cwd: Optional[Path] = None,
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Executes a Git command with strict subprocess isolation.

        Enforces:
        - `shell=False` to prevent shell injection.
        - Explicit timeout to prevent hanging worker threads.
        - Captured stdout and stderr.
        """
        if not isinstance(args, (list, tuple)):
            raise TypeError(f"Command arguments must be a sequence of strings, got {type(args).__name__}")

        cmd = ["git", *args]
        effective_timeout = timeout if timeout is not None else self.default_timeout
        effective_cwd = cwd if cwd is not None else self.repo_path

        try:
            result = subprocess.run(
                cmd,
                shell=False,
                timeout=effective_timeout,
                capture_output=True,
                text=True,
                cwd=effective_cwd,
                input=input_text,
            )
        except subprocess.TimeoutExpired:
            raise GitTimeoutError(command=cmd, timeout=effective_timeout)
        except FileNotFoundError:
            raise GitNotInstalledError("The 'git' executable was not found in the system PATH.")

        if check and result.returncode != 0:
            raise GitCommandError(
                command=cmd,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )

        return result

    def is_git_installed(self) -> bool:
        """Verifies that the git executable is installed and responding."""
        try:
            res = self._run_git(["--version"], timeout=5.0)
            return res.returncode == 0
        except (GitEngineError, Exception):
            return False

    def is_git_repository(self) -> bool:
        """Checks if the target path is inside a valid Git work tree."""
        try:
            res = self._run_git(["rev-parse", "--is-inside-work-tree"], timeout=5.0)
            if res.returncode == 0 and res.stdout.strip().lower() == "true":
                return True
        except GitEngineError:
            pass

        # Fallback filesystem check: inspect upward for .git
        curr = self.repo_path
        while curr != curr.parent:
            if (curr / ".git").exists():
                return True
            curr = curr.parent
        return False

    def get_git_root(self) -> Optional[Path]:
        """Returns the absolute root directory of the current Git repository."""
        try:
            res = self._run_git(["rev-parse", "--show-toplevel"], timeout=5.0)
            if res.returncode == 0 and res.stdout.strip():
                return Path(res.stdout.strip()).resolve()
        except GitEngineError:
            pass

        # Fallback traversal
        curr = self.repo_path
        while curr != curr.parent:
            if (curr / ".git").exists():
                return curr
            curr = curr.parent
        return None

    def get_current_branch(self) -> Optional[str]:
        """
        Extracts the name of the active Git branch.
        Works across committed branches, unborn initial branches, and detached HEAD.
        Returns 'HEAD (detached)' if HEAD is detached, or None if outside a repo.
        """
        if not self.is_git_repository():
            return None

        # 1. Try git branch --show-current (accurate for unborn and committed branches)
        try:
            res = self._run_git(["branch", "--show-current"], timeout=5.0)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except GitEngineError:
            pass

        # 2. Try git symbolic-ref --short HEAD
        try:
            res = self._run_git(["symbolic-ref", "--short", "HEAD"], timeout=5.0)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except GitEngineError:
            pass

        # 3. Direct inspection of .git/HEAD for branch ref
        root = self.get_git_root()
        if root:
            head_file = root / ".git" / "HEAD"
            if head_file.is_file():
                try:
                    content = head_file.read_text(encoding="utf-8").strip()
                    if content.startswith("ref: refs/heads/"):
                        return content[len("ref: refs/heads/"):].strip()
                except Exception:
                    pass

        # 4. Check if detached
        try:
            res = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], timeout=5.0)
            if res.returncode == 0:
                branch = res.stdout.strip()
                if branch == "HEAD":
                    return "HEAD (detached)"
                if branch:
                    return branch
        except GitEngineError:
            pass

        return "HEAD (detached)"

    def get_head_commit(self, short: bool = False) -> Optional[str]:
        """Returns the HEAD commit SHA, or None if repo has no commits."""
        args = ["rev-parse", "HEAD"] if not short else ["rev-parse", "--short", "HEAD"]
        try:
            res = self._run_git(args, timeout=5.0)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except GitEngineError:
            pass
        return None

    def is_dirty(self, include_untracked: bool = True) -> bool:
        """Returns True if the working directory has uncommitted or untracked changes."""
        args = ["status", "--porcelain"]
        if include_untracked:
            args.append("-uall")
        else:
            args.append("-uno")
        try:
            res = self._run_git(args, timeout=5.0)
            if res.returncode == 0:
                lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                return len(lines) > 0
        except GitEngineError:
            pass
        return False

    def get_hooks_dir(self) -> Optional[Path]:
        """
        Determines the repository's active Git hooks directory.
        Respects custom core.hooksPath configuration and Git worktrees/submodules.
        """
        root = self.get_git_root()
        if not root:
            return None

        # Check for user-defined core.hooksPath
        try:
            res = self._run_git(["config", "--get", "core.hooksPath"], timeout=5.0, cwd=root)
            if res.returncode == 0 and res.stdout.strip():
                configured = Path(res.stdout.strip())
                return (root / configured).resolve() if not configured.is_absolute() else configured
        except GitEngineError:
            pass

        dot_git = root / ".git"
        if dot_git.is_dir():
            return dot_git / "hooks"
        elif dot_git.is_file():
            # Git worktree or submodule pointing to gitdir
            try:
                content = dot_git.read_text(encoding="utf-8").strip()
                if content.startswith("gitdir:"):
                    gitdir_path = Path(content[len("gitdir:"):].strip())
                    resolved_gitdir = (root / gitdir_path).resolve() if not gitdir_path.is_absolute() else gitdir_path
                    return resolved_gitdir / "hooks"
            except Exception:
                pass

        return root / ".git" / "hooks"

    def install_pre_push_hook(
        self,
        force: bool = False,
        hook_script_content: Optional[str] = None,
    ) -> Path:
        """
        Safely installs or updates the Git pre-push hook.

        Safety Guardrail:
        If a third-party or custom developer hook already exists, it is backed up
        to `pre-push.vulnora-orig` and invoked via execution chaining so developer
        workflows are never destructively overwritten.
        """
        hooks_dir = self.get_hooks_dir()
        if not hooks_dir:
            raise NotAGitRepositoryError(f"Cannot install Git hook: {self.repo_path} is not a Git repository.")

        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-push"
        backup_path = hooks_dir / "pre-push.vulnora-orig"

        existing_content = ""
        if hook_path.exists():
            try:
                existing_content = hook_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                existing_content = ""

        # Check if existing hook is already a Vulnora-managed hook
        is_vulnora_hook = VULNORA_HOOK_MARKER in existing_content

        if hook_path.exists() and not is_vulnora_hook and not force:
            # Backup the developer's original pre-push hook
            hook_path.rename(backup_path)
            # Make sure backup retains executable permissions
            try:
                backup_path.chmod(backup_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except Exception:
                pass

        if hook_script_content:
            script_body = hook_script_content
        else:
            # Standard pre-push wrapper script
            chain_call = ""
            if backup_path.exists():
                chain_call = """
# Execute previously installed chained pre-push hook
if [ -x "$(dirname "$0")/pre-push.vulnora-orig" ]; then
    "$(dirname "$0")/pre-push.vulnora-orig" "$@" || exit $?
fi
"""
            script_body = f"""#!/bin/sh
{VULNORA_HOOK_MARKER}
# Vulnora AI Autonomous Push Interception Hook
# Safe branch-aware pre-push verification.

# Run Vulnora guard if installed
if command -v vulnora >/dev/null 2>&1; then
    vulnora guard --hook || exit 1
fi
{chain_call}
exit 0
"""

        hook_path.write_text(script_body, encoding="utf-8")
        # Ensure hook script is executable (chmod +x)
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        return hook_path

    def remove_pre_push_hook(self) -> bool:
        """
        Safely removes the Vulnora pre-push hook.
        Restores `pre-push.vulnora-orig` if a backup exists.
        Returns True if uninstalled, False if no Vulnora hook existed.
        """
        hooks_dir = self.get_hooks_dir()
        if not hooks_dir:
            return False

        hook_path = hooks_dir / "pre-push"
        backup_path = hooks_dir / "pre-push.vulnora-orig"

        if not hook_path.exists():
            return False

        try:
            content = hook_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""

        if VULNORA_HOOK_MARKER not in content:
            return False

        hook_path.unlink()

        # Restore original developer hook if it was chained
        if backup_path.exists():
            backup_path.rename(hook_path)

        return True

    def is_hook_installed(self) -> bool:
        """Checks if the Vulnora pre-push hook is installed."""
        hooks_dir = self.get_hooks_dir()
        if not hooks_dir:
            return False
        hook_path = hooks_dir / "pre-push"
        if not hook_path.exists():
            return False
        try:
            content = hook_path.read_text(encoding="utf-8", errors="replace")
            return VULNORA_HOOK_MARKER in content
        except Exception:
            return False

    def parse_push_refs(self, raw_input: str) -> List[PushRefUpdate]:
        """
        Parses standard input streamed by Git to the pre-push hook.
        Git passes lines formatted as:
          <local_ref> SP <local_sha> SP <remote_ref> SP <remote_sha> LF
        """
        updates: List[PushRefUpdate] = []
        if not raw_input or not raw_input.strip():
            return updates

        for line in raw_input.strip().splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            parts = line_str.split()
            if len(parts) < 4:
                continue

            local_ref, local_sha, remote_ref, remote_sha = parts[0], parts[1], parts[2], parts[3]

            # Ref deletion: local_sha is all zeros (40 or 64 hex zeros) or local_ref is (delete)
            zero_sha = set(local_sha) == {"0"} or local_sha == ("0" * 40) or local_sha == ("0" * 64)
            is_deletion = zero_sha or local_ref in ("(delete)", "", "(deleted)")

            is_tag = remote_ref.startswith("refs/tags/") or local_ref.startswith("refs/tags/")
            is_branch = remote_ref.startswith("refs/heads/")

            branch_name = None
            if is_branch:
                branch_name = remote_ref[len("refs/heads/"):]
            elif not is_tag and not is_deletion and not remote_ref.startswith("refs/"):
                branch_name = remote_ref
                is_branch = True

            updates.append(
                PushRefUpdate(
                    local_ref=local_ref,
                    local_sha=local_sha,
                    remote_ref=remote_ref,
                    remote_sha=remote_sha,
                    branch_name=branch_name,
                    is_branch=is_branch,
                    is_deletion=is_deletion,
                    is_tag=is_tag,
                )
            )

        return updates

    def is_protected_branch(
        self,
        branch_name: Optional[str],
        protected_branches: Optional[List[str]] = None,
    ) -> bool:
        """
        Determines whether the branch is in the protected branches list.
        Comparison is case-insensitive.
        """
        if not branch_name:
            return False
        targets = protected_branches if protected_branches is not None else DEFAULT_PROTECTED_BRANCHES
        norm = branch_name.strip().lower()
        return any(norm == b.strip().lower() for b in targets)

    def update_gitignore(self, patterns_to_add: Optional[List[str]] = None) -> List[str]:
        """
        Ensures local Vulnora runtime state and artifacts are ignored in .gitignore.
        Returns the list of newly appended entries.
        """
        root = self.get_git_root() or self.repo_path
        gitignore_path = root / ".gitignore"

        patterns = patterns_to_add or [
            ".vulnora/memory.json",
            ".vulnora/cache/",
            ".vulnora/*.tmp",
            ".vulnora/credentials.local",
        ]

        existing_lines: List[str] = []
        if gitignore_path.exists():
            try:
                existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()
            except Exception:
                existing_lines = []

        existing_set = {line.strip() for line in existing_lines if line.strip()}
        newly_added: List[str] = []

        for p in patterns:
            clean = p.strip()
            if clean and clean not in existing_set:
                newly_added.append(clean)

        if newly_added:
            header_marker = "# Vulnora AI State & Cache"
            has_header = header_marker in existing_set

            with gitignore_path.open("a", encoding="utf-8") as f:
                if existing_lines and existing_lines[-1].strip():
                    f.write("\n")
                if not has_header:
                    f.write(f"{header_marker}\n")
                for item in newly_added:
                    f.write(f"{item}\n")

        return newly_added

    def get_changed_files(
        self,
        base_ref: Optional[str] = None,
        target_ref: Optional[str] = None,
        staged_only: bool = False,
    ) -> List[str]:
        """
        Safely retrieves the list of modified or added file paths.
        """
        if staged_only:
            args = ["diff", "--name-only", "--cached"]
        elif base_ref and target_ref:
            args = ["diff", "--name-only", base_ref, target_ref]
        elif base_ref:
            args = ["diff", "--name-only", base_ref]
        else:
            args = ["diff", "--name-only"]

        try:
            res = self._run_git(args, check=True)
            return [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except GitEngineError:
            return []

    def get_diff_scoped_files(
        self,
        base_ref: Optional[str] = None,
        target_ref: Optional[str] = None,
        include_untracked: bool = True,
        existing_only: bool = True,
    ) -> List[Path]:
        """
        Retrieves a clean list of file paths scoped to active changes.
        Combines staged, unstaged, and untracked files (or diff between refs).
        Filters for existing files so deleted paths do not cause scanner errors.
        """
        root = self.get_git_root() or self.repo_path
        file_set: set[str] = set()

        if base_ref and target_ref:
            file_set.update(self.get_changed_files(base_ref=base_ref, target_ref=target_ref))
        elif base_ref:
            file_set.update(self.get_changed_files(base_ref=base_ref))
        else:
            # Both staged and working directory diffs
            file_set.update(self.get_changed_files(staged_only=True))
            file_set.update(self.get_changed_files(staged_only=False))

            # Also check untracked files if requested
            if include_untracked:
                try:
                    res = self._run_git(["status", "--porcelain", "-uall"], timeout=5.0)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            line_str = line.strip()
                            if line_str.startswith("??"):
                                file_path = line_str[2:].strip()
                                if file_path:
                                    file_set.add(file_path)
                except GitEngineError:
                    pass

        paths: List[Path] = []
        for rel in sorted(file_set):
            p = (root / rel).resolve()
            if existing_only:
                if p.is_file():
                    paths.append(p)
            else:
                paths.append(p)

        return paths

    def get_diff(
        self,
        base_ref: Optional[str] = None,
        target_ref: Optional[str] = None,
        file_paths: Optional[List[str]] = None,
    ) -> str:
        """
        Safely extracts the git unified diff.
        """
        args = ["diff"]
        if base_ref and target_ref:
            args.extend([base_ref, target_ref])
        elif base_ref:
            args.append(base_ref)

        if file_paths:
            args.append("--")
            args.extend(file_paths)

        try:
            res = self._run_git(args, check=True)
            return res.stdout
        except GitEngineError:
            return ""

    def detect_repository_languages(self) -> RepoLanguage:
        """
        Language-agnostic repository inspection.
        Scans for standard build manifests across Go, Rust, TypeScript, Python, Java, etc.
        """
        root = self.get_git_root() or self.repo_path

        manifest_map: Dict[str, str] = {
            # Rust
            "Cargo.toml": "Rust",
            "Cargo.lock": "Rust",
            # Go
            "go.mod": "Go",
            "go.sum": "Go",
            # TypeScript / JavaScript
            "tsconfig.json": "TypeScript",
            "package.json": "JavaScript",
            "pnpm-lock.yaml": "JavaScript",
            "yarn.lock": "JavaScript",
            "bun.lockb": "JavaScript",
            # Python
            "pyproject.toml": "Python",
            "requirements.txt": "Python",
            "setup.py": "Python",
            "Pipfile": "Python",
            # Java / Kotlin
            "pom.xml": "Java",
            "build.gradle": "Java",
            "build.gradle.kts": "Kotlin",
            # C / C++
            "CMakeLists.txt": "C/C++",
            "meson.build": "C/C++",
            "Makefile": "C/C++",
            # Ruby
            "Gemfile": "Ruby",
            # PHP
            "composer.json": "PHP",
            # Swift
            "Package.swift": "Swift",
        }

        detected_langs: Dict[str, int] = {}
        found_manifests: List[str] = []

        try:
            for item in root.iterdir():
                name = item.name
                if name in manifest_map:
                    lang = manifest_map[name]
                    detected_langs[lang] = detected_langs.get(lang, 0) + 1
                    found_manifests.append(name)
                elif name.endswith(".csproj") or name.endswith(".sln"):
                    detected_langs["C#"] = detected_langs.get("C#", 0) + 1
                    found_manifests.append(name)
        except Exception:
            pass

        unique_langs = sorted(list(detected_langs.keys()))
        if not unique_langs:
            primary = "Unknown"
        elif len(unique_langs) == 1:
            primary = unique_langs[0]
        else:
            # Sort by manifest frequency
            primary = sorted(detected_langs.items(), key=lambda x: x[1], reverse=True)[0][0]

        return RepoLanguage(
            primary_language=primary,
            detected_languages=unique_langs,
            manifest_files=sorted(found_manifests),
        )

    def get_repo_status(
        self,
        protected_branches: Optional[List[str]] = None,
    ) -> GitRepoStatus:
        """
        Assembles comprehensive diagnostic status of the Git repository.
        """
        is_git = self.is_git_repository()
        if not is_git:
            return GitRepoStatus(is_git=False)

        root = self.get_git_root()
        branch = self.get_current_branch()
        commit = self.get_head_commit(short=True)
        detached = branch == "HEAD (detached)"
        dirty = self.is_dirty()
        hooks = self.get_hooks_dir()
        hook_installed = self.is_hook_installed()

        target_protected = protected_branches if protected_branches is not None else DEFAULT_PROTECTED_BRANCHES
        branch_protected = self.is_protected_branch(branch, target_protected) if branch and not detached else False

        lang_info = self.detect_repository_languages()

        return GitRepoStatus(
            is_git=True,
            root_path=str(root) if root else None,
            current_branch=branch,
            current_commit=commit,
            is_detached=detached,
            is_dirty=dirty,
            protected_branches=list(target_protected),
            is_current_branch_protected=branch_protected,
            hooks_dir=str(hooks) if hooks else None,
            hook_installed=hook_installed,
            detected_languages=lang_info.detected_languages,
        )
