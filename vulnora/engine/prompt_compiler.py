"""
Surgical Fix-Prompt Compiler for Vulnora AI.

Compiles ultra-targeted, copy-ready Markdown remediation prompts for AI coding agents
(Cursor, Claude Code, GitHub Copilot, Antigravity).
Guarantees zero-secret egress via `SecretRedactor` and extracts enclosing AST context
via `ASTNormalizer`.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from vulnora.core.models import Finding, ImmuneMatch, ImmunityTier, RedactionResult, Severity, SurgicalPrompt
from vulnora.engine.redactor import SecretRedactor
from vulnora.immune.ast_normalizer import ASTNormalizer
from vulnora.immune.memory_store import ImmuneMemoryStore


class SurgicalPromptCompiler:
    """
    Extracts enclosing AST context, scrubs secrets, consults immune memory,
    and formats one-shot surgical fix prompts for external coding agents.
    """

    def __init__(
        self,
        target_root: Optional[Union[str, Path]] = None,
        immune_store: Optional[ImmuneMemoryStore] = None,
        redactor: Optional[SecretRedactor] = None,
        normalizer: Optional[ASTNormalizer] = None,
        max_context_lines: int = 120,
    ):
        self.target_root = Path(target_root or Path.cwd()).resolve()
        self.immune_store = immune_store
        self.redactor = redactor or SecretRedactor()
        self.normalizer = normalizer or ASTNormalizer()
        self.max_context_lines = max_context_lines

    def compile(
        self,
        finding: Finding,
        file_override_content: Optional[str] = None,
    ) -> SurgicalPrompt:
        """
        Compiles a targeted SurgicalPrompt for a security finding.
        """
        file_path_str = finding.file_path
        full_file_path = (self.target_root / file_path_str).resolve()
        language = self.normalizer.detect_language(file_path_str)

        raw_code = ""
        if file_override_content is not None:
            raw_code = file_override_content
        elif full_file_path.is_file():
            try:
                raw_code = full_file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw_code = ""

        # Step 1: Extract enclosing block around line_number using ASTNormalizer
        line_no = finding.line_number
        enclosing_block = ""
        enclosing_symbol = None

        if raw_code and line_no:
            enclosing_block = self.normalizer.extract_enclosing_block(
                code=raw_code,
                line_number=line_no,
                language=language,
            )
            enclosing_symbol = self._infer_symbol_name(enclosing_block, language)
        elif finding.snippet:
            enclosing_block = finding.snippet
        else:
            enclosing_block = f"# Vulnerability detected at {file_path_str}:{line_no or 'unknown'}"

        # Cap oversized enclosing blocks
        block_lines = enclosing_block.splitlines()
        if len(block_lines) > self.max_context_lines:
            enclosing_block = "\n".join(block_lines[:self.max_context_lines]) + "\n... [truncated for context limit]"

        # Step 2: Pre-Egress Secret Scrubbing
        redaction_result = self.redactor.redact(enclosing_block)
        sanitized_block = redaction_result.redacted_text

        # Step 3: Consult Immune Memory
        immune_hint: Optional[str] = None
        if self.immune_store:
            try:
                match = self.immune_store.query(finding, code_snippet=enclosing_block, language=language)
                if finding.snippet and (not match.matched or match.tier != ImmunityTier.TIER_1_EXACT):
                    alt_match = self.immune_store.query(finding, code_snippet=finding.snippet, language=language)
                    if alt_match.matched and (not match.matched or alt_match.similarity_score > match.similarity_score):
                        match = alt_match

                if match.matched and match.record:
                    rule_info = f" Agent Rule: {match.record.agents_rule}" if match.record.agents_rule else ""
                    if match.tier == ImmunityTier.TIER_1_EXACT:
                        immune_hint = f"**Tier 1 Antibody Match (100% exact):** Previously resolved as `{match.record.resolution}`.{rule_info}"
                    elif match.tier == ImmunityTier.TIER_2_STRUCTURAL:
                        immune_hint = f"**Tier 2 Structural Variant Match ({match.similarity_score:.1%}):** Similar pattern previously resolved as `{match.record.resolution}`.{rule_info}"
                    elif match.tier == ImmunityTier.TIER_3_PARTIAL:
                        immune_hint = f"**Tier 3 Partial Antibody Match ({match.similarity_score:.1%}):** Related vulnerability previously handled as `{match.record.resolution}`.{rule_info}"
            except Exception:
                pass

        # Step 4: Build line-highlighted presentation
        highlighted_code = self._build_highlighted_block(raw_code, line_no, sanitized_block)

        # Step 5: Format full Markdown prompt
        markdown = self._format_markdown_prompt(
            finding=finding,
            language=language,
            enclosing_symbol=enclosing_symbol,
            highlighted_code=highlighted_code,
            immune_hint=immune_hint,
            redaction_count=redaction_result.secrets_found_count,
        )

        return SurgicalPrompt(
            finding_id=finding.fingerprint or finding.compute_fingerprint(),
            rule_id=finding.rule_id,
            scanner_name=finding.scanner_name,
            severity=finding.severity,
            file_path=file_path_str,
            line_number=line_no,
            enclosing_symbol=enclosing_symbol,
            vulnerable_code_block=sanitized_block,
            compiled_markdown=markdown,
            immune_hint=immune_hint,
            redaction_summary=redaction_result,
        )

    def _infer_symbol_name(self, block: str, language: str) -> Optional[str]:
        """Infers function, method, or class name from code block."""
        first_few_lines = "\n".join(block.splitlines()[:5])
        # Python: def foo(...) or class Bar:
        m = re.search(r"\b(?:def|class)\s+([A-Za-z0-9_]+)", first_few_lines)
        if m:
            return m.group(1)
        # Go / Rust: func Foo(...) or fn bar(...)
        m = re.search(r"\b(?:func|fn)\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)", first_few_lines)
        if m:
            return m.group(1)
        # JS / TS: function foo(...) or const foo = (...)
        m = re.search(r"\b(?:function\s+([A-Za-z0-9_]+)|const\s+([A-Za-z0-9_]+)\s*=)", first_few_lines)
        if m:
            return m.group(1) or m.group(2)
        # Java / C++: void/int/type foo(...)
        m = re.search(r"\b(?:public|private|protected|static|\w+)\s+[\w<>]+\s+([A-Za-z0-9_]+)\s*\(", first_few_lines)
        if m:
            return m.group(1)
        return None

    def _build_highlighted_block(
        self,
        full_code: str,
        target_line: Optional[int],
        sanitized_block: str,
    ) -> str:
        """Formats the code block with line indicators."""
        if not target_line or not full_code:
            return sanitized_block

        lines = sanitized_block.splitlines()
        # If block is short or line numbers match
        output_lines: List[str] = []
        for line in lines:
            output_lines.append(f"  {line}")
        return "\n".join(output_lines)

    def _format_markdown_prompt(
        self,
        finding: Finding,
        language: str,
        enclosing_symbol: Optional[str],
        highlighted_code: str,
        immune_hint: Optional[str],
        redaction_count: int,
    ) -> str:
        """Constructs copy-ready Markdown Surgical Prompt."""
        symbol_desc = f"`{enclosing_symbol}`" if enclosing_symbol else "*Top-level / module scope*"
        loc_str = f"`{finding.file_path}:{finding.line_number}`" if finding.line_number else f"`{finding.file_path}`"

        redaction_badge = f"\n> [!NOTE]\n> **Zero-Secret Egress Active:** {redaction_count} sensitive token(s) scrubbed with `***REDACTED***`.\n" if redaction_count > 0 else ""

        immune_section = ""
        if immune_hint:
            immune_section = f"""## Local Immune Memory Guidance
{immune_hint}
"""

        remediation_section = ""
        if finding.remediation:
            remediation_section = f"""## Scanner Remediation Advice
{finding.remediation}
"""

        prompt = f"""# Surgical Fix Prompt: {finding.title}
{redaction_badge}
## Target Context
- **Target File:** `{finding.file_path}`
- **Vulnerable Line:** {loc_str}
- **Enclosing Scope:** {symbol_desc}
- **Language:** `{language}`
- **Scanner Rule:** `{finding.scanner_name}` (`{finding.rule_id}`)
- **Severity:** **{finding.severity.value}**

## Vulnerability Description
{finding.description}
{remediation_section}
{immune_section}
## Target Vulnerable Code Block
```{language}
{highlighted_code}
```

## Instructions for AI Coding Agent
Please generate a surgical, drop-in replacement patch for `{finding.file_path}`:
1. **Surgical Precision:** Modify **only** the vulnerable statement/function. Do not refactor unrelated code or alter surrounding whitespace.
2. **Security Integrity:** Follow secure coding guidelines for `{language}` to remediate `{finding.rule_id}` completely without workarounds.
3. **No Placeholders:** Provide complete, runnable code suitable for direct insertion.
"""
        return prompt.strip()
