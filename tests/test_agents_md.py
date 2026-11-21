"""
Unit tests for Self-Evolving AGENTS.md writer (`vulnora.engine.agents_md`).
"""

from pathlib import Path
import pytest

from vulnora.core.models import AgentRule
from vulnora.engine.agents_md import AGENTS_MD_HEADER, AgentsMDWriter


class TestAgentsMDWriter:
    """Tests for preventative rule distillation, deduplication, and line budgeting."""

    @pytest.fixture
    def writer(self, tmp_path: Path) -> AgentsMDWriter:
        return AgentsMDWriter(repo_root=tmp_path, max_lines_budget=50)

    def test_add_rule_creates_file(self, writer: AgentsMDWriter):
        rule = AgentRule(
            rule_id="B605",
            language="python",
            rule_text="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
        )
        added = writer.add_rule(rule)
        assert added is True
        assert writer.file_path.exists()

        content = writer.file_path.read_text(encoding="utf-8")
        assert "Autonomous Agent Security Rules" in content
        assert "## Python Security Guardrails" in content
        assert "- **[B605]**: Never use os.system()" in content

    def test_rule_deduplication(self, writer: AgentsMDWriter):
        rule1 = AgentRule(
            rule_id="B605",
            language="python",
            rule_text="Avoid os.system calls.",
        )
        writer.add_rule(rule1)

        # Add updated rule with same rule_id
        rule2 = AgentRule(
            rule_id="B605",
            language="python",
            rule_text="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
        )
        writer.add_rule(rule2)

        rules = writer.load_rules()
        assert len(rules) == 1
        assert rules[0].rule_id == "B605"
        assert "always pass argument list" in rules[0].rule_text

    def test_line_budget_pruning(self, tmp_path: Path):
        # Strict low budget of 20 lines
        writer = AgentsMDWriter(repo_root=tmp_path, max_lines_budget=20)

        for i in range(15):
            writer.add_rule(
                AgentRule(
                    rule_id=f"RULE_{i:03d}",
                    language="python",
                    rule_text=f"Rule specification number {i} for secure coding.",
                )
            )

        rules = writer.load_rules()
        # Enforced budget keeps max 5-8 rules
        assert len(rules) <= 8
        # Ensure latest rule was preserved
        assert any(r.rule_id == "RULE_014" for r in rules)

        # Check total file lines is within budget
        line_count = len(writer.file_path.read_text(encoding="utf-8").splitlines())
        assert line_count <= 25

    def test_sync_to_agent_files(self, writer: AgentsMDWriter, tmp_path: Path):
        writer.add_rule(
            AgentRule(
                rule_id="G204",
                language="go",
                rule_text="Do not invoke sh -c with unvalidated variables.",
            )
        )
        synced = writer.sync_to_agent_files([".cursorrules", "CLAUDE.md"])
        assert len(synced) == 2
        assert (tmp_path / ".cursorrules").exists()
        assert (tmp_path / "CLAUDE.md").exists()
        assert "G204" in (tmp_path / ".cursorrules").read_text(encoding="utf-8")
