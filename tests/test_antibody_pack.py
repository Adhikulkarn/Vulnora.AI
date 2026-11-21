"""
Unit tests for Antibody Pack export, import, sanitization, and CLI commands (`vulnora.immune.antibody_pack`).
"""

import json
from pathlib import Path
import pytest
import yaml

from vulnora.cli import main
from vulnora.core.models import Finding, ImmuneRecord, Severity
from vulnora.immune.antibody_pack import AntibodyPackError, AntibodyPackManager
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestAntibodyPack:
    """Tests for export, import, data sanitization, and CLI immune integration."""

    @pytest.fixture
    def store_with_records(self, tmp_path: Path) -> ImmuneMemoryStore:
        memory_file = tmp_path / ".vulnora" / "memory.json"
        store = ImmuneMemoryStore(memory_path=memory_file)

        finding1 = Finding(
            title="Insecure Token Comparison",
            description="Timing attack vulnerability",
            scanner_name="bandit",
            rule_id="B105",
            severity=Severity.HIGH,
            file_path="src/auth/tokens.py",
        )
        code1 = "def verify_token(user_token):\n    secret = 'super_secret_admin_token'\n    return user_token == secret"
        store.remember_finding(
            finding1,
            code_snippet=code1,
            resolution="REMEDIATED",
            language="python",
            agents_rule="Use hmac.compare_digest for all secret string comparisons.",
            metadata={"file_path": "/Users/developer/repo/src/auth/tokens.py", "user": "alice@corp.internal"},
        )

        finding2 = Finding(
            title="SQL Injection",
            description="Format string in query",
            scanner_name="semgrep",
            rule_id="sqli-02",
            severity=Severity.CRITICAL,
            file_path="src/db/users.go",
        )
        code2 = "func GetUser(id string) { db.Query(fmt.Sprintf('SELECT * FROM users WHERE id=%s', id)) }"
        store.remember_finding(
            finding2,
            code_snippet=code2,
            resolution="ACCEPTED_RISK",
            language="go",
            agents_rule="Never use fmt.Sprintf to format SQL queries.",
            metadata={"git_commit": "abcdef123456"},
        )

        return store

    def test_export_and_import_json_pack(self, store_with_records: ImmuneMemoryStore, tmp_path: Path):
        pack_file = tmp_path / "antibodies.json"
        exported_path = AntibodyPackManager.export_pack(store_with_records, pack_file, pack_name="core-security-pack")
        assert exported_path.exists()

        content = json.loads(pack_file.read_text(encoding="utf-8"))
        assert content["format_version"] == "1.0"
        assert content["pack_name"] == "core-security-pack"
        assert content["antibodies_count"] == 2
        assert len(content["antibodies"]) == 2

        # Import into fresh store
        fresh_store = ImmuneMemoryStore(memory_path=tmp_path / "fresh_mem.json")
        assert len(fresh_store.get_all_records()) == 0

        count = AntibodyPackManager.import_pack(pack_file, fresh_store)
        assert count == 2
        assert len(fresh_store.get_all_records()) == 2

        # Repeated import without overwrite should not duplicate
        repeat_count = AntibodyPackManager.import_pack(pack_file, fresh_store, overwrite=False)
        assert repeat_count == 0
        assert len(fresh_store.get_all_records()) == 2

    def test_export_and_import_yaml_pack(self, store_with_records: ImmuneMemoryStore, tmp_path: Path):
        pack_file = tmp_path / "antibodies.yaml"
        exported_path = AntibodyPackManager.export_pack(store_with_records, pack_file, pack_name="yaml-pack")
        assert exported_path.exists()

        with pack_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert data["pack_name"] == "yaml-pack"
        assert len(data["antibodies"]) == 2

        fresh_store = ImmuneMemoryStore(memory_path=tmp_path / "fresh_yaml_mem.json")
        count = AntibodyPackManager.import_pack(pack_file, fresh_store)
        assert count == 2

    def test_proprietary_code_leak_sanitization(self, store_with_records: ImmuneMemoryStore, tmp_path: Path):
        """CRITICAL: Verifies zero proprietary file paths, usernames, or secrets leak into packs."""
        pack_file = tmp_path / "safe_antibodies.json"
        AntibodyPackManager.export_pack(store_with_records, pack_file)
        raw_text = pack_file.read_text(encoding="utf-8")

        # Must not contain proprietary local filesystem paths
        assert "/Users/developer/" not in raw_text
        assert "src/auth/tokens.py" not in raw_text
        assert "src/db/users.go" not in raw_text

        # Must not contain proprietary developer email or raw commit metadata
        assert "alice@corp.internal" not in raw_text
        assert "abcdef123456" not in raw_text

        # Must contain anonymized placeholders and agent rules
        assert "VAR_" in raw_text
        assert "hmac.compare_digest" in raw_text

    def test_cli_immune_stats_and_inspect_commands(self, store_with_records: ImmuneMemoryStore, tmp_path: Path, capsys):
        # Point CLI to the directory hosting memory.json
        repo_dir = store_with_records.memory_path.parent.parent

        rc = main(["-C", str(repo_dir), "immune", "stats"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Vulnora AI AST Immune Memory Stats" in captured.out
        assert "Total Antibodies   : 2" in captured.out

        # Inspect
        rc_inspect = main(["-C", str(repo_dir), "immune", "inspect"])
        assert rc_inspect == 0
        captured_inspect = capsys.readouterr()
        assert "Stored Antibodies (2 records)" in captured_inspect.out
        assert "B105" in captured_inspect.out

    def test_cli_immune_export_and_import(self, store_with_records: ImmuneMemoryStore, tmp_path: Path, capsys):
        repo_dir = store_with_records.memory_path.parent.parent
        export_target = tmp_path / "cli_exported_pack.json"

        rc_exp = main(["-C", str(repo_dir), "immune", "export", "-o", str(export_target)])
        assert rc_exp == 0
        assert export_target.exists()

        # Import into another directory
        dest_repo = tmp_path / "dest_repo"
        dest_repo.mkdir()
        rc_imp = main(["-C", str(dest_repo), "immune", "import", str(export_target)])
        assert rc_imp == 0
        captured = capsys.readouterr()
        assert "Successfully imported 2 antibodies" in captured.out
