"""
Git pre-push hook installer and lifecycle manager for Vulnora AI.
Supports safe installation, non-destructive chaining of pre-existing hooks,
and cross-platform compatibility (Windows Git Bash, macOS, Linux).
"""

import os
from pathlib import Path
import shutil
import stat
from typing import Optional, Tuple

from .git_utils import get_git_hooks_dir, get_git_root

HOOK_NAME = "pre-push"
CHAINED_SUFFIX = ".pre-vulnora"
HOOK_MARKER = "# Vulnora AI Git Pre-Push Hook - BEGIN"

HOOK_SCRIPT_TEMPLATE = """#!/usr/bin/env sh
# ==============================================================================
# Vulnora AI Git Pre-Push Hook - BEGIN
# Managed automatically by Vulnora AI. Safe to chain with existing hooks.
# ==============================================================================

# Prevent recursive hook execution loops
if [ -n "$VULNORA_GUARD_RUNNING" ]; then
    exit 0
fi
export VULNORA_GUARD_RUNNING=1

# Capture standard input once so it can be passed to chained hooks and Vulnora
VULNORA_HOOK_INPUT=$(cat)

# 1. Execute pre-existing chained hook if present
CHAINED_HOOK="$0.pre-vulnora"
if [ -f "$CHAINED_HOOK" ]; then
    if [ -x "$CHAINED_HOOK" ]; then
        printf "%s\\n" "$VULNORA_HOOK_INPUT" | "$CHAINED_HOOK" "$@"
    else
        printf "%s\\n" "$VULNORA_HOOK_INPUT" | sh "$CHAINED_HOOK" "$@"
    fi
    PRE_HOOK_EXIT=$?
    if [ $PRE_HOOK_EXIT -ne 0 ]; then
        exit $PRE_HOOK_EXIT
    fi
fi

# 2. Invoke Vulnora Guard with captured ref updates
if command -v vulnora >/dev/null 2>&1; then
    printf "%s\\n" "$VULNORA_HOOK_INPUT" | vulnora guard --hook "$@"
    EXIT_CODE=$?
elif [ -f "./.venv/Scripts/vulnora.exe" ]; then
    printf "%s\\n" "$VULNORA_HOOK_INPUT" | ./.venv/Scripts/vulnora.exe guard --hook "$@"
    EXIT_CODE=$?
elif [ -f "./.venv/bin/vulnora" ]; then
    printf "%s\\n" "$VULNORA_HOOK_INPUT" | ./.venv/bin/vulnora guard --hook "$@"
    EXIT_CODE=$?
elif python -m vulnora.cli.main --version >/dev/null 2>&1; then
    printf "%s\\n" "$VULNORA_HOOK_INPUT" | python -m vulnora.cli.main guard --hook "$@"
    EXIT_CODE=$?
elif python3 -m vulnora.cli.main --version >/dev/null 2>&1; then
    printf "%s\\n" "$VULNORA_HOOK_INPUT" | python3 -m vulnora.cli.main guard --hook "$@"
    EXIT_CODE=$?
else
    echo "[Vulnora Guard] Notice: Vulnora CLI not found in active PATH; bypassing guard."
    EXIT_CODE=0
fi

exit $EXIT_CODE
# Vulnora AI Git Pre-Push Hook - END
"""


def get_hook_path(target_path: Optional[Path] = None) -> Optional[Path]:
    """Returns the absolute path to .git/hooks/pre-push, if hooks directory exists."""
    hooks_dir = get_git_hooks_dir(target_path)
    if not hooks_dir:
        return None
    return hooks_dir / HOOK_NAME


def is_hook_installed(target_path: Optional[Path] = None) -> bool:
    """Checks whether the Vulnora pre-push hook is installed in the target repository."""
    hook_file = get_hook_path(target_path)
    if not hook_file or not hook_file.exists():
        return False

    try:
        content = hook_file.read_text(encoding="utf-8", errors="ignore")
        return HOOK_MARKER in content
    except Exception:
        return False


def make_executable(file_path: Path):
    """Sets executable permissions (chmod +x) for POSIX and Windows Git environments."""
    try:
        current_stat = os.stat(file_path)
        os.chmod(file_path, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def install_pre_push_hook(target_path: Optional[Path] = None, force: bool = False) -> Tuple[bool, str]:
    """
    Installs the Vulnora pre-push hook into .git/hooks/pre-push.
    - If already installed: Idempotent no-op.
    - If existing non-Vulnora hook found: Backs up to pre-push.pre-vulnora and chains safely.
    - If no hook found: Creates pre-push directly.
    Returns:
        (success: bool, status_message: str)
    """
    hooks_dir = get_git_hooks_dir(target_path)
    if not hooks_dir:
        return False, "Not a Git repository or hooks directory unavailable."

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / HOOK_NAME
    chained_file = hooks_dir / f"{HOOK_NAME}{CHAINED_SUFFIX}"

    # Idempotent check
    if hook_file.exists() and not force:
        try:
            content = hook_file.read_text(encoding="utf-8", errors="ignore")
            if HOOK_MARKER in content:
                # Ensure it remains executable
                make_executable(hook_file)
                return True, "Pre-push hook already installed and active (idempotent)."
        except Exception:
            pass

    # Non-destructive preservation of pre-existing hook
    if hook_file.exists():
        try:
            content = hook_file.read_text(encoding="utf-8", errors="ignore")
            if HOOK_MARKER not in content:
                # Move existing hook to chained backup
                shutil.copy2(hook_file, chained_file)
                make_executable(chained_file)
        except Exception as exc:
            return False, f"Failed to preserve existing pre-push hook: {exc}"

    # Write hook with strictly LF line endings for POSIX / Git Bash compatibility
    script_bytes = HOOK_SCRIPT_TEMPLATE.replace("\r\n", "\n").encode("utf-8")
    with hook_file.open("wb") as f:
        f.write(script_bytes)

    make_executable(hook_file)

    if chained_file.exists():
        return True, "Preserved existing pre-push hook (.pre-vulnora) and chained with Vulnora."
    return True, "Installed Git pre-push hook at .git/hooks/pre-push."


def uninstall_pre_push_hook(target_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Uninstalls the Vulnora pre-push hook.
    If a chained hook (.pre-vulnora) exists, restores it as the active pre-push hook.
    """
    hooks_dir = get_git_hooks_dir(target_path)
    if not hooks_dir:
        return False, "Not a Git repository."

    hook_file = hooks_dir / HOOK_NAME
    chained_file = hooks_dir / f"{HOOK_NAME}{CHAINED_SUFFIX}"

    if not hook_file.exists():
        return True, "No pre-push hook found to uninstall."

    try:
        content = hook_file.read_text(encoding="utf-8", errors="ignore")
        if HOOK_MARKER not in content:
            return False, "Active pre-push hook was not created by Vulnora; leaving untouched."

        hook_file.unlink()

        if chained_file.exists():
            shutil.move(chained_file, hook_file)
            make_executable(hook_file)
            return True, "Removed Vulnora hook and restored original pre-push hook."

        return True, "Removed Vulnora pre-push hook."
    except Exception as exc:
        return False, f"Failed to uninstall hook: {exc}"
