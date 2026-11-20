"""
Configuration management for Vulnora AI CLI.
Handles reading and generating .vulnora/config.yaml.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

DEFAULT_PROTECTED_BRANCHES = ["main", "production"]

DEFAULT_CONFIG_TEMPLATE: Dict[str, Any] = {
    "version": "1.0",
    "project": {
        "name": "vulnora-project",
        "language": "auto",
        "write_permission": "prompt",
    },
    "git": {
        "protected_branches": DEFAULT_PROTECTED_BRANCHES,
        "pre_push_hook": {
            "enabled": True,
        },
        "enforce_pre_push": True,
        "block_on_critical": True,
    },
    "scanners": {
        "enabled": ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"],
        "timeout_seconds": 60,
        "auto_install_missing": False,
    },
    "ai": {
        "enabled": True,
        "base_url": "http://127.0.0.1:11435",
        "model": "qwen2.5-coder:7b",
        "timeout_seconds": 90,
        "think": False,
    },
    "backend": {
        "url": "http://127.0.0.1:8000",
        "sync_history": False,
    },
}


def _deep_merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merges override dictionary into base dictionary."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge_dict(merged[key], val)
        else:
            merged[key] = val
    return merged


def get_vulnora_dir(base_path: Optional[Path] = None) -> Path:
    """Returns the .vulnora directory path for the given base path or CWD."""
    root = base_path or Path.cwd()
    return root.resolve() / ".vulnora"


def get_config_path(base_path: Optional[Path] = None) -> Path:
    """Returns the path to .vulnora/config.yaml."""
    return get_vulnora_dir(base_path) / "config.yaml"


def load_config(base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads .vulnora/config.yaml if it exists, otherwise returns DEFAULT_CONFIG_TEMPLATE.
    Performs recursive deep merge so existing config files cleanly inherit new default keys.
    """
    cfg_file = get_config_path(base_path)
    if not cfg_file.exists():
        return dict(DEFAULT_CONFIG_TEMPLATE)

    try:
        with cfg_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                return dict(DEFAULT_CONFIG_TEMPLATE)
            return _deep_merge_dict(DEFAULT_CONFIG_TEMPLATE, data)
    except Exception:
        return dict(DEFAULT_CONFIG_TEMPLATE)


def save_config(config_data: Dict[str, Any], base_path: Optional[Path] = None) -> Path:
    """
    Writes configuration dictionary to .vulnora/config.yaml.
    Creates parent directories if missing.
    """
    cfg_file = get_config_path(base_path)
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    with cfg_file.open("w", encoding="utf-8") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
    return cfg_file


def get_protected_branches(base_path: Optional[Path] = None) -> List[str]:
    """
    Returns the list of configured protected branches, falling back to defaults.
    """
    config = load_config(base_path)
    git_cfg = config.get("git", {})
    branches = git_cfg.get("protected_branches")
    if isinstance(branches, list) and branches:
        return [str(b).strip() for b in branches if str(b).strip()]
    return list(DEFAULT_PROTECTED_BRANCHES)


def is_pre_push_hook_enabled(base_path: Optional[Path] = None) -> bool:
    """
    Checks if the Git pre-push hook is enabled in .vulnora/config.yaml.
    """
    config = load_config(base_path)
    git_cfg = config.get("git", {})
    hook_cfg = git_cfg.get("pre_push_hook", {})
    if isinstance(hook_cfg, dict):
        return bool(hook_cfg.get("enabled", True))
    if isinstance(hook_cfg, bool):
        return hook_cfg
    return True


def get_ai_config(base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Returns the configured AI inference settings dictionary.
    """
    config = load_config(base_path)
    return dict(config.get("ai", DEFAULT_CONFIG_TEMPLATE["ai"]))


def get_write_permission(base_path: Optional[Path] = None) -> str:
    """
    Returns the configured write permission mode ('prompt' or 'auto').
    """
    config = load_config(base_path)
    perm = (
        config.get("project", {}).get("write_permission")
        or config.get("write_permission")
        or "prompt"
    )
    return str(perm).strip().lower()


def ensure_django_setup():
    """
    Ensures Django settings and applications are initialized when running
    via the standalone CLI without manage.py.
    """
    import os
    import sys

    curr = Path(__file__).resolve().parent
    repo_root = None
    for p in [curr, curr.parent, curr.parent.parent]:
        if (p / "manage.py").exists() and (p / "apps").exists():
            repo_root = p
            break
    if not repo_root:
        repo_root = Path.cwd().resolve()

    apps_dir = repo_root / "apps"
    if str(apps_dir) not in sys.path:
        sys.path.insert(0, str(apps_dir))
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnora.settings.development")
    try:
        import django
        from django.apps import apps
        if not apps.ready:
            django.setup()
    except Exception:
        pass



