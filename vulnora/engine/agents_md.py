"""
Self-evolving AGENTS.md writer for Vulnora AI.

Automatically distills verified fixes into concise, deduplicated preventative rules
appended to AGENTS.md, capped under a strict line budget to keep AI coding agent
contexts clean and efficient.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union

from vulnora.core.models import AgentRule

AGENTS_MD_HEADER = """# Autonomous Agent Security Rules (Managed by Vulnora AI)
> DO NOT remove or bypass these rules. They prevent known security regressions detected and verified in this repository.
"""


class AgentsMDWriter:
    """
    Manages reading, deduplicating, pruning, and writing AGENTS.md.
    """

    def __init__(
        self,
        repo_root: Optional[Union[str, Path]] = None,
        agents_filename: str = "AGENTS.md",
        max_lines_budget: int = 100,
    ):
        self.repo_root = Path(repo_root or Path.cwd()).resolve()
        self.file_path = self.repo_root / agents_filename
        self.max_lines_budget = max_lines_budget

    def add_rule(self, rule: AgentRule, on_log: Optional[Callable[[str], None]] = None) -> bool:
        """
        Appends or updates a preventative security rule in AGENTS.md.
        Deduplicates by rule_id and enforces line budget.
        Returns True if rule was added or updated.
        """
        if not rule.rule_text or not rule.rule_id:
            return False

        existing_rules = self.load_rules()

        # Deduplication: check if exact rule_id already present
        found_idx = -1
        for idx, existing in enumerate(existing_rules):
            if existing.rule_id.lower() == rule.rule_id.lower():
                found_idx = idx
                break

        if found_idx >= 0:
            # Update existing rule with newer instruction if different
            if on_log:
                on_log(f"[bold cyan][AGENTS][/bold cyan] Updating existing guardrail rule for [{rule.rule_id}].")
            existing_rules[found_idx] = rule
        else:
            if on_log:
                on_log(f"[bold cyan][AGENTS][/bold cyan] Appending new guardrail rule for [{rule.rule_id}] in {rule.language.capitalize()} section.")
            existing_rules.append(rule)

        # Enforce budget by pruning oldest low-severity rules if needed
        pruned_rules = self._enforce_budget(existing_rules)
        if len(pruned_rules) < len(existing_rules) and on_log:
            on_log(f"[dim][AGENTS][/dim] Enforced {self.max_lines_budget}-line budget (pruned {len(existing_rules) - len(pruned_rules)} rule(s)).")

        self._save_rules(pruned_rules)
        if on_log:
            on_log(f"[bold green][AGENTS][/bold green] AGENTS.md successfully updated and saved ({len(pruned_rules)} active rules).")
        return True

    def load_rules(self) -> List[AgentRule]:
        """Parses all existing rules from AGENTS.md."""
        if not self.file_path.exists():
            return []

        try:
            content = self.file_path.read_text(encoding="utf-8")
        except Exception:
            return []

        rules: List[AgentRule] = []
        current_lang = "General"

        # Regex to parse rule lines: - **[RULE_ID]** (Lang): Description
        rule_pattern = re.compile(r"^-\s+\*\*\[([^\]]+)\]\*\*(?:\s+\(([^)]+)\))?:\s*(.+)$")

        for line in content.splitlines():
            line_str = line.strip()
            if line_str.startswith("## "):
                section_title = line_str.lstrip("#").strip()
                if " " in section_title:
                    current_lang = section_title.split()[0]
                else:
                    current_lang = section_title
                continue

            match = rule_pattern.match(line_str)
            if match:
                rule_id = match.group(1).strip()
                lang = match.group(2) or current_lang
                desc = match.group(3).strip()
                rules.append(
                    AgentRule(
                        rule_id=rule_id,
                        language=lang.lower(),
                        rule_text=desc,
                    )
                )

        return rules

    def _enforce_budget(self, rules: List[AgentRule]) -> List[AgentRule]:
        """
        Prunes rules to stay strictly under max_lines_budget.
        Keeps newest rules while respecting budget.
        """
        header_lines = len(AGENTS_MD_HEADER.splitlines()) + 4
        available_rule_lines = max(10, self.max_lines_budget - header_lines)

        # Each rule roughly takes 1-2 lines (including section headers)
        max_allowed_rules = max(5, available_rule_lines // 2)

        if len(rules) > max_allowed_rules:
            # Keep the latest rules
            return rules[-max_allowed_rules:]
        return rules

    def _save_rules(self, rules: List[AgentRule]) -> None:
        """Formats and atomically writes AGENTS.md."""
        # Group rules by language
        grouped: Dict[str, List[AgentRule]] = {}
        for r in rules:
            lang_key = r.language.capitalize() if r.language else "General"
            grouped.setdefault(lang_key, []).append(r)

        lines: List[str] = [AGENTS_MD_HEADER.strip(), ""]

        for lang, lang_rules in sorted(grouped.items()):
            lines.append(f"## {lang} Security Guardrails")
            for r in lang_rules:
                lines.append(f"- **[{r.rule_id}]**: {r.rule_text}")
            lines.append("")

        output_text = "\n".join(lines).strip() + "\n"

        # Atomic file write
        temp_file = self.file_path.with_suffix(".tmp")
        temp_file.write_text(output_text, encoding="utf-8")
        os.replace(temp_file, self.file_path)

    def sync_to_agent_files(self, targets: Optional[List[str]] = None) -> List[Path]:
        """
        Optionally copies AGENTS.md rules to IDE rule files like .cursorrules,
        .windsurfrules, or CLAUDE.md.
        """
        if not self.file_path.exists():
            return []

        target_names = targets or [".cursorrules", ".windsurfrules", "CLAUDE.md"]
        synced: List[Path] = []
        content = self.file_path.read_text(encoding="utf-8")

        for name in target_names:
            dest = self.repo_root / name
            dest.write_text(content, encoding="utf-8")
            synced.append(dest)

        return synced
