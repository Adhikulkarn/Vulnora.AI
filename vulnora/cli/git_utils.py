"""
Git utility helpers for Vulnora CLI.
Handles repository detection, branch extraction, and .gitignore maintenance.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class PushRefUpdate:
    """Represents a single ref update provided by Git to the pre-push hook."""
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str
    branch_name: Optional[str] = None
    is_branch: bool = False
    is_deletion: bool = False
    is_tag: bool = False


def is_git_installed() -> bool:
    """Verifies that git executable is installed and available in PATH."""
    try:
        res = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


def is_git_repository(target_path: Optional[Path] = None) -> bool:
    """
    Checks if the specified path (or current directory) is inside a Git repository.
    """
    cwd = target_path or Path.cwd()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        return res.returncode == 0 and res.stdout.strip().lower() == "true"
    except Exception:
        # Fallback check for .git directory directly
        curr = cwd.resolve()
        while curr != curr.parent:
            if (curr / ".git").exists():
                return True
            curr = curr.parent
        return False


def get_git_root(target_path: Optional[Path] = None) -> Optional[Path]:
    """
    Returns the top-level root directory of the current Git repository.
    """
    cwd = target_path or Path.cwd()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except Exception:
        pass

    curr = cwd.resolve()
    while curr != curr.parent:
        if (curr / ".git").exists():
            return curr
        curr = curr.parent
    return None


def get_current_branch(target_path: Optional[Path] = None) -> Optional[str]:
    """
    Extracts the name of the currently checked out Git branch.
    Returns None if in detached HEAD state or not a Git repository.
    """
    cwd = target_path or Path.cwd()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0:
            branch = res.stdout.strip()
            return branch if branch != "HEAD" else "HEAD (detached)"
    except Exception:
        pass
    return None


def get_repo_name(target_path: Optional[Path] = None) -> str:
    """
    Returns the repository name or root directory name.
    """
    root = get_git_root(target_path)
    if root:
        return root.name
    cwd = target_path or Path.cwd()
    return cwd.resolve().name


def get_git_hooks_dir(target_path: Optional[Path] = None) -> Optional[Path]:
    """
    Returns the path to the repository's .git/hooks directory.
    Supports standard git directories and core.hooksPath if configured.
    """
    root = get_git_root(target_path)
    if not root:
        return None

    # Check for custom core.hooksPath
    try:
        res = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            custom_path = Path(res.stdout.strip())
            return (root / custom_path).resolve() if not custom_path.is_absolute() else custom_path
    except Exception:
        pass

    # Check standard .git/hooks
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git / "hooks"
    elif dot_git.is_file():
        # Handle git worktrees or submodules (gitdir file)
        try:
            content = dot_git.read_text(encoding="utf-8").strip()
            if content.startswith("gitdir:"):
                actual_gitdir = Path(content[len("gitdir:"):].strip())
                actual_gitdir = (root / actual_gitdir).resolve() if not actual_gitdir.is_absolute() else actual_gitdir
                return actual_gitdir / "hooks"
        except Exception:
            pass

    return root / ".git" / "hooks"


def parse_push_refs(raw_input: str) -> List[PushRefUpdate]:
    """
    Parses Git pre-push hook standard input.
    Each line from Git contains:
      <local_ref> SP <local_sha> SP <remote_ref> SP <remote_sha> LF
    """
    updates: List[PushRefUpdate] = []
    if not raw_input:
        return updates

    for line in raw_input.strip().splitlines():
        parts = line.strip().split()
        if len(parts) < 4:
            continue

        local_ref, local_sha, remote_ref, remote_sha = parts[0], parts[1], parts[2], parts[3]

        # Branch or ref deletion: local_sha is all zeros (40 or 64 hex zeros) or local_ref is (delete)
        zero_sha_check = set(local_sha) == {"0"} or local_sha == "0" * 40
        is_deletion = zero_sha_check or local_ref in ("(delete)", "", "(deleted)")

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


def is_protected_branch(branch_name: Optional[str], protected_branches: List[str]) -> bool:
    """
    Determines if a branch is in the configured list of protected branches.
    """
    if not branch_name:
        return False
    norm_branch = branch_name.strip().lower()
    return any(norm_branch == p.strip().lower() for p in protected_branches)


def update_gitignore(git_root: Path, patterns_to_add: List[str]) -> List[str]:
    """
    Ensures that local Vulnora memory, cache, and sensitive files are ignored in .gitignore.
    Returns the list of newly appended entries.
    """
    gitignore_path = git_root / ".gitignore"
    existing_lines: List[str] = []

    if gitignore_path.exists():
        try:
            existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            existing_lines = []

    existing_set = {line.strip() for line in existing_lines if line.strip()}
    newly_added = []

    for pattern in patterns_to_add:
        clean = pattern.strip()
        if clean and clean not in existing_set:
            newly_added.append(clean)

    if newly_added:
        header_needed = "# Vulnora AI Local State & Cache" not in existing_set
        with gitignore_path.open("a", encoding="utf-8") as f:
            if existing_lines and existing_lines[-1].strip():
                f.write("\n")
            if header_needed:
                f.write("# Vulnora AI Local State & Cache\n")
            for item in newly_added:
                f.write(f"{item}\n")

    return newly_added

