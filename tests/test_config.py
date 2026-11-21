"""
Unit tests for Vulnora AI configuration engine (`vulnora.core.config`).
"""

from pathlib import Path
import pytest
import yaml

from vulnora.core.config import (
    DEFAULT_CONFIG_TEMPLATE,
    DEFAULT_PROTECTED_BRANCHES,
    DEFAULT_SCANNERS,
    AIConfig,
    GitConfig,
    ProjectConfig,
    ScannersConfig,
    VulnoraConfig,
    _deep_merge_dict,
    get_config_path,
    get_vulnora_dir,
    init_config,
    is_branch_protected,
    load_config,
    save_config,
)


class TestConfigModels:
    """Tests for dataclass configuration models."""

    def test_default_config_instantiation(self):
        config = VulnoraConfig()
        assert config.version == "1.0"
        assert config.project.name == "vulnora-project"
        assert config.project.language == "auto"
        assert config.git.protected_branches == DEFAULT_PROTECTED_BRANCHES
        assert config.git.enforce_pre_push is True
        assert config.scanners.enabled == DEFAULT_SCANNERS
        assert config.ai.enabled is False
        assert config.ai.provider == "ollama"

    def test_config_to_dict_and_from_dict_roundtrip(self):
        config = VulnoraConfig(
            version="1.0",
            project=ProjectConfig(name="backend-service", language="go", write_permission="auto"),
            git=GitConfig(protected_branches=["main", "staging"], enforce_pre_push=False),
            scanners=ScannersConfig(enabled=["gitleaks", "semgrep"], timeout_seconds=45),
            ai=AIConfig(enabled=True, model="devstral:latest"),
        )
        d = config.to_dict()
        assert d["project"]["name"] == "backend-service"
        assert d["git"]["protected_branches"] == ["main", "staging"]
        assert d["scanners"]["timeout_seconds"] == 45
        assert d["ai"]["model"] == "devstral:latest"

        reconstructed = VulnoraConfig.from_dict(d)
        assert reconstructed.project.language == "go"
        assert reconstructed.git.enforce_pre_push is False
        assert reconstructed.scanners.enabled == ["gitleaks", "semgrep"]
        assert reconstructed.ai.enabled is True


class TestDeepMerge:
    """Tests for the recursive dictionary merge utility."""

    def test_deep_merge_preserves_unspecified_defaults(self):
        base = {
            "a": 1,
            "nested": {
                "x": "keep",
                "y": "keep_too",
            },
            "list": [1, 2],
        }
        override = {
            "nested": {
                "y": "overridden",
            },
            "extra": 99,
        }
        merged = _deep_merge_dict(base, override)
        assert merged["a"] == 1
        assert merged["nested"]["x"] == "keep"
        assert merged["nested"]["y"] == "overridden"
        assert merged["extra"] == 99


class TestPathHelpers:
    """Tests for config and directory path resolution."""

    def test_get_vulnora_dir(self, tmp_path: Path):
        v_dir = get_vulnora_dir(tmp_path)
        assert v_dir == (tmp_path / ".vulnora").resolve()

    def test_get_config_path(self, tmp_path: Path):
        cfg_path = get_config_path(tmp_path)
        assert cfg_path == (tmp_path / ".vulnora" / "config.yaml").resolve()


class TestConfigLoadSaveInit:
    """Tests for config loading, saving, and initialization."""

    def test_load_config_missing_file_returns_defaults(self, tmp_path: Path):
        config = load_config(tmp_path)
        assert isinstance(config, VulnoraConfig)
        assert config.project.name == "vulnora-project"
        assert config.git.protected_branches == DEFAULT_PROTECTED_BRANCHES

    def test_save_and_load_config(self, tmp_path: Path):
        config = VulnoraConfig(
            project=ProjectConfig(name="rust-agent", language="rust"),
            git=GitConfig(protected_branches=["main"]),
        )
        saved_file = save_config(config, base_path=tmp_path)
        assert saved_file.exists()

        loaded = load_config(tmp_path)
        assert loaded.project.name == "rust-agent"
        assert loaded.project.language == "rust"
        assert loaded.git.protected_branches == ["main"]
        # Defaults merged in
        assert loaded.scanners.enabled == DEFAULT_SCANNERS

    def test_load_config_handles_partial_yaml(self, tmp_path: Path):
        cfg_file = get_config_path(tmp_path)
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        # Write only partial config
        cfg_file.write_text("git:\n  protected_branches:\n    - release\n", encoding="utf-8")

        loaded = load_config(tmp_path)
        assert loaded.git.protected_branches == ["release"]
        # Scanners and project still inherited defaults
        assert loaded.scanners.enabled == DEFAULT_SCANNERS
        assert loaded.project.name == "vulnora-project"

    def test_load_config_handles_corrupt_yaml(self, tmp_path: Path):
        cfg_file = get_config_path(tmp_path)
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_file.write_text(":::invalid: yaml :::\n", encoding="utf-8")

        # Must not crash; cleanly returns defaults
        loaded = load_config(tmp_path)
        assert isinstance(loaded, VulnoraConfig)
        assert loaded.git.protected_branches == DEFAULT_PROTECTED_BRANCHES

    def test_init_config_creates_file(self, tmp_path: Path):
        cfg_file = init_config(base_path=tmp_path, project_name="my-service", language="go")
        assert cfg_file.exists()

        loaded = load_config(tmp_path)
        assert loaded.project.name == "my-service"
        assert loaded.project.language == "go"

    def test_init_config_fails_if_exists_without_force(self, tmp_path: Path):
        init_config(base_path=tmp_path, project_name="first-run")
        with pytest.raises(FileExistsError):
            init_config(base_path=tmp_path, project_name="second-run", force=False)

    def test_init_config_overwrites_with_force(self, tmp_path: Path):
        init_config(base_path=tmp_path, project_name="first-run")
        init_config(base_path=tmp_path, project_name="second-run", force=True)
        loaded = load_config(tmp_path)
        assert loaded.project.name == "second-run"


class TestBranchProtectionCheck:
    """Tests for is_branch_protected helper."""

    def test_is_branch_protected_with_defaults(self):
        assert is_branch_protected("main") is True
        assert is_branch_protected("MAIN") is True
        assert is_branch_protected("master") is True
        assert is_branch_protected("production") is True
        assert is_branch_protected("staging") is True
        assert is_branch_protected("feature/auth") is False
        assert is_branch_protected("bugfix/123") is False

    def test_is_branch_protected_with_none_or_empty(self):
        assert is_branch_protected(None) is False
        assert is_branch_protected("") is False
        assert is_branch_protected("   ") is False

    def test_is_branch_protected_with_custom_config(self):
        config = VulnoraConfig(
            git=GitConfig(protected_branches=["prod", "stable"])
        )
        assert is_branch_protected("prod", config=config) is True
        assert is_branch_protected("stable", config=config) is True
        assert is_branch_protected("main", config=config) is False
