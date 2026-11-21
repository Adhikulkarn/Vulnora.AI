"""
Configuration management and validation for Vulnora AI.

Handles loading, validating, merging, and persisting `.vulnora/config.yaml`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

DEFAULT_PROTECTED_BRANCHES: List[str] = ["main", "master", "production", "staging"]
DEFAULT_SCANNERS: List[str] = ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy"]

DEFAULT_CONFIG_TEMPLATE: Dict[str, Any] = {
    "version": "1.0",
    "project": {
        "name": "vulnora-project",
        "language": "auto",
        "write_permission": "prompt",
    },
    "git": {
        "protected_branches": list(DEFAULT_PROTECTED_BRANCHES),
        "enforce_pre_push": True,
        "block_on_critical": True,
        "hooks_dir": None,
    },
    "scanners": {
        "enabled": list(DEFAULT_SCANNERS),
        "timeout_seconds": 60,
        "auto_install_missing": False,
    },
    "ai": {
        "enabled": False,
        "provider": "ollama",
        "model": "qwen2.5-coder:7b",
        "endpoint": "http://localhost:11434",
        "timeout_seconds": 90,
    },
}


@dataclass
class ProjectConfig:
    """Project-level metadata and permission configuration."""
    name: str = "vulnora-project"
    language: str = "auto"
    write_permission: str = "prompt"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProjectConfig:
        return cls(
            name=str(data.get("name", "vulnora-project")),
            language=str(data.get("language", "auto")),
            write_permission=str(data.get("write_permission", "prompt")),
        )


@dataclass
class GitConfig:
    """Git hook and branch protection configuration."""
    protected_branches: List[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_BRANCHES))
    enforce_pre_push: bool = True
    block_on_critical: bool = True
    hooks_dir: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protected_branches": list(self.protected_branches),
            "enforce_pre_push": self.enforce_pre_push,
            "block_on_critical": self.block_on_critical,
            "hooks_dir": self.hooks_dir,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GitConfig:
        raw_branches = data.get("protected_branches", DEFAULT_PROTECTED_BRANCHES)
        branches = [str(b).strip() for b in raw_branches if str(b).strip()] if isinstance(raw_branches, list) else list(DEFAULT_PROTECTED_BRANCHES)
        return cls(
            protected_branches=branches,
            enforce_pre_push=bool(data.get("enforce_pre_push", True)),
            block_on_critical=bool(data.get("block_on_critical", True)),
            hooks_dir=data.get("hooks_dir"),
        )


@dataclass
class ScannersConfig:
    """Security scanner orchestration settings."""
    enabled: List[str] = field(default_factory=lambda: list(DEFAULT_SCANNERS))
    timeout_seconds: int = 60
    auto_install_missing: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": list(self.enabled),
            "timeout_seconds": self.timeout_seconds,
            "auto_install_missing": self.auto_install_missing,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScannersConfig:
        raw_enabled = data.get("enabled", DEFAULT_SCANNERS)
        enabled = [str(s).strip() for s in raw_enabled if str(s).strip()] if isinstance(raw_enabled, list) else list(DEFAULT_SCANNERS)
        return cls(
            enabled=enabled,
            timeout_seconds=int(data.get("timeout_seconds", 60)),
            auto_install_missing=bool(data.get("auto_install_missing", False)),
        )


@dataclass
class AIConfig:
    """Local and remote AI inference settings."""
    enabled: bool = False
    provider: str = "ollama"
    model: str = "qwen2.5-coder:7b"
    endpoint: str = "http://localhost:11434"
    timeout_seconds: int = 90
    api_key: Optional[str] = None
    agents_budget_lines: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AIConfig:
        return cls(
            enabled=bool(data.get("enabled", False)),
            provider=str(data.get("provider", "ollama")),
            model=str(data.get("model", "qwen2.5-coder:7b")),
            endpoint=str(data.get("endpoint", "http://localhost:11434")),
            timeout_seconds=int(data.get("timeout_seconds", 90)),
            api_key=data.get("api_key"),
            agents_budget_lines=int(data.get("agents_budget_lines", 100)),
        )


@dataclass
class VulnoraConfig:
    """Top-level configuration object for Vulnora AI."""
    version: str = "1.0"
    project: ProjectConfig = field(default_factory=ProjectConfig)
    git: GitConfig = field(default_factory=GitConfig)
    scanners: ScannersConfig = field(default_factory=ScannersConfig)
    ai: AIConfig = field(default_factory=AIConfig)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "project": self.project.to_dict(),
            "git": self.git.to_dict(),
            "scanners": self.scanners.to_dict(),
            "ai": self.ai.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VulnoraConfig:
        return cls(
            version=str(data.get("version", "1.0")),
            project=ProjectConfig.from_dict(data.get("project", {})),
            git=GitConfig.from_dict(data.get("git", {})),
            scanners=ScannersConfig.from_dict(data.get("scanners", {})),
            ai=AIConfig.from_dict(data.get("ai", {})),
        )


DEFAULT_CONFIG: VulnoraConfig = VulnoraConfig()


def _deep_merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merges override dictionary into base dictionary.
    Ensures missing configuration fields automatically take default values.
    """
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge_dict(merged[key], val)
        else:
            merged[key] = val
    return merged


def get_vulnora_dir(base_path: Optional[Union[Path, str]] = None) -> Path:
    """Returns the .vulnora directory path for the given base path or CWD."""
    root = Path(base_path) if base_path else Path.cwd()
    return root.resolve() / ".vulnora"


def get_config_path(base_path: Optional[Union[Path, str]] = None) -> Path:
    """Returns the path to .vulnora/config.yaml."""
    return get_vulnora_dir(base_path) / "config.yaml"


class ConfigManager:
    """
    Manages Vulnora AI configuration lifecycle, local credentials, and repository hygiene.
    """

    @staticmethod
    def ensure_gitignore(base_path: Optional[Union[Path, str]] = None) -> List[str]:
        """
        Ensures .gitignore contains required Vulnora rules including credentials.local.
        """
        root = Path(base_path or Path.cwd()).resolve()
        gitignore_path = root / ".gitignore"

        patterns = [
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


def load_local_credentials(base_path: Optional[Union[Path, str]] = None) -> Dict[str, str]:
    """
    Reads `.vulnora/credentials.local` and returns a dictionary of credentials.
    """
    root = Path(base_path or Path.cwd()).resolve()
    cred_file = root / ".vulnora" / "credentials.local"
    creds: Dict[str, str] = {}
    if not cred_file.is_file():
        return creds

    try:
        content = cred_file.read_text(encoding="utf-8").strip()
        if content.startswith("{"):
            import json
            data = json.loads(content)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "=" in line_str:
                k, v = line_str.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k:
                    creds[k] = v
            elif not creds and len(line_str) >= 16:
                creds["GEMINI_API_KEY"] = line_str
    except Exception:
        pass
    return creds


def save_local_credential(
    key_name: str,
    key_val: str,
    base_path: Optional[Union[Path, str]] = None,
) -> Path:
    """
    Saves a credential to `.vulnora/credentials.local` with strict 0o600 file permissions
    and guarantees `.vulnora/credentials.local` is present in `.gitignore`.
    """
    root = Path(base_path or Path.cwd()).resolve()
    vulnora_dir = root / ".vulnora"
    vulnora_dir.mkdir(parents=True, exist_ok=True)
    cred_file = vulnora_dir / "credentials.local"

    creds = load_local_credentials(root)
    creds[key_name] = key_val

    lines = [f"{k}={v}" for k, v in creds.items()]
    content = "\n".join(lines) + "\n"

    cred_file.write_text(content, encoding="utf-8")
    try:
        cred_file.chmod(0o600)
    except Exception:
        pass

    ConfigManager.ensure_gitignore(root)
    return cred_file


def load_dotenv(base_path: Optional[Union[Path, str]] = None) -> None:
    """
    Lightweight, pure-Python .env and credentials file loader.
    Reads .env and .vulnora/credentials.local and populates missing os.environ keys.
    """
    root = Path(base_path or Path.cwd()).resolve()
    env_file = root / ".env"
    if env_file.is_file():
        try:
            content = env_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                if "=" in line_str:
                    key, val = line_str.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    if key and key not in os.environ:
                        os.environ[key] = val
        except Exception:
            pass

    # Load local session credentials if not already populated
    local_creds = load_local_credentials(root)
    for k, v in local_creds.items():
        if k and k not in os.environ:
            os.environ[k] = v


def load_config(base_path: Optional[Union[Path, str]] = None) -> VulnoraConfig:
    """
    Loads configuration from `.vulnora/config.yaml` if it exists.
    Performs recursive deep-merge with defaults so newly added configuration
    keys are cleanly populated without breaking older configs.
    Automatically loads .env if present in project root.
    """
    load_dotenv(base_path)
    cfg_file = get_config_path(base_path)
    if not cfg_file.is_file():
        return VulnoraConfig.from_dict(DEFAULT_CONFIG_TEMPLATE)

    try:
        with cfg_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return VulnoraConfig.from_dict(DEFAULT_CONFIG_TEMPLATE)
            merged = _deep_merge_dict(DEFAULT_CONFIG_TEMPLATE, data)
            return VulnoraConfig.from_dict(merged)
    except Exception:
        # Fall back cleanly to defaults if parsing fails
        return VulnoraConfig.from_dict(DEFAULT_CONFIG_TEMPLATE)


def save_config(
    config: Union[VulnoraConfig, Dict[str, Any]],
    base_path: Optional[Union[Path, str]] = None,
) -> Path:
    """
    Persists configuration data to `.vulnora/config.yaml`.
    Creates parent directories if they do not exist.
    """
    cfg_file = get_config_path(base_path)
    cfg_file.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(config, VulnoraConfig):
        data = config.to_dict()
    elif isinstance(config, dict):
        data = config
    else:
        raise TypeError(f"Expected VulnoraConfig or dict, got {type(config).__name__}")

    with cfg_file.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    return cfg_file


def init_config(
    base_path: Optional[Union[Path, str]] = None,
    project_name: Optional[str] = None,
    language: str = "auto",
    force: bool = False,
) -> Path:
    """
    Initializes a new `.vulnora/config.yaml` file.
    If the file exists and force is False, raises FileExistsError.
    """
    cfg_file = get_config_path(base_path)
    if cfg_file.exists() and not force:
        raise FileExistsError(f"Configuration file already exists at {cfg_file}")

    target_root = Path(base_path) if base_path else Path.cwd()
    resolved_name = project_name or target_root.resolve().name or "vulnora-project"

    config_dict = dict(DEFAULT_CONFIG_TEMPLATE)
    config_dict["project"] = {
        "name": resolved_name,
        "language": language,
        "write_permission": "prompt",
    }

    return save_config(config_dict, base_path=base_path)


def is_branch_protected(
    branch_name: Optional[str],
    config: Optional[VulnoraConfig] = None,
    protected_branches: Optional[List[str]] = None,
) -> bool:
    """
    Determines if a branch is configured as a protected branch.
    Comparison is case-insensitive and whitespace-trimmed.
    """
    if not branch_name:
        return False

    branches = protected_branches
    if branches is None:
        if config is not None:
            branches = config.git.protected_branches
        else:
            branches = DEFAULT_PROTECTED_BRANCHES

    norm_branch = branch_name.strip().lower()
    return any(norm_branch == p.strip().lower() for p in branches)
