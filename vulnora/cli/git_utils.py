"""
Git utility helpers for Vulnora CLI.
Handles repository detection, branch extraction, and .gitignore maintenance.
"""

import subprocess
from pathlib import Path
from typing import List, Optional


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
