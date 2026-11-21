"""
Automated Fix Verification & Learning Loop for Vulnora AI.

After a patch is applied (by Cloud AI or developer coding agent):
1. Re-runs ONLY the flagging security scanner on that single file.
2. If clean, diffs before/after code, extracts AST shape, and commits verified
   antibody to Immune Memory.
3. Distills fix into AGENTS.md preventative guardrails.
4. If still vulnerable, automatically rolls back changes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import difflib
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Union

from vulnora.core.config import VulnoraConfig, load_config
from vulnora.core.models import AgentRule, Finding, ImmuneRecord, RemediationProposal, Severity, VerificationResult
from vulnora.engine.agents_md import AgentsMDWriter
from vulnora.immune.ast_normalizer import ASTNormalizer
from vulnora.immune.memory_store import ImmuneMemoryStore
from vulnora.scanners.runner import ScannerOrchestrator


class FixVerifier:
    """
    Subprocess-safe verification engine and immune learning loop.
    """

    def __init__(
        self,
        target_root: Optional[Union[str, Path]] = None,
        config: Optional[VulnoraConfig] = None,
        immune_store: Optional[ImmuneMemoryStore] = None,
        normalizer: Optional[ASTNormalizer] = None,
        agents_writer: Optional[AgentsMDWriter] = None,
    ):
        self.target_root = Path(target_root or Path.cwd()).resolve()
        self.config = config or load_config(base_path=self.target_root)
        self.normalizer = normalizer or ASTNormalizer()

        # Initialize Immune Memory Store
        if immune_store:
            self.immune_store = immune_store
        else:
            mem_path = self.target_root / ".vulnora" / "memory.json"
            self.immune_store = ImmuneMemoryStore(memory_path=mem_path)

        # Initialize AGENTS.md writer
        self.agents_writer = agents_writer or AgentsMDWriter(
            repo_root=self.target_root,
            max_lines_budget=self.config.ai.agents_budget_lines if hasattr(self.config.ai, "agents_budget_lines") else 100,
        )

    def verify_and_learn(
        self,
        finding: Finding,
        proposal: RemediationProposal,
        auto_rollback: bool = True,
    ) -> VerificationResult:
        """
        Applies patch, runs targeted single-scanner re-scan, commits to Immune Memory
        and AGENTS.md if clean, or rolls back if still flagged.
        """
        start_time = time.perf_counter()
        file_path_str = finding.file_path
        target_file = (self.target_root / file_path_str).resolve()

        if not target_file.is_file():
            return VerificationResult(
                success=False,
                file_path=file_path_str,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                message=f"Target file does not exist: {target_file}",
            )

        original_content = target_file.read_text(encoding="utf-8", errors="replace")

        # Step 1: Apply replacement into the file
        replacement = proposal.replacement_code
        original_snippet = proposal.original_code or finding.snippet

        patched_content = original_content
        if replacement:
            if original_snippet and original_snippet in original_content:
                patched_content = original_content.replace(original_snippet, replacement, 1)
            elif finding.snippet and finding.snippet in original_content:
                patched_content = original_content.replace(finding.snippet, replacement, 1)
            else:
                # If enclosing block was sanitized or has minor whitespace differences
                patched_content = self._apply_fuzzy_replacement(original_content, original_snippet, replacement)

            if patched_content == original_content and replacement != original_snippet:
                return VerificationResult(
                    success=False,
                    file_path=file_path_str,
                    scanner_name=finding.scanner_name,
                    rule_id=finding.rule_id,
                    message="Could not locate target vulnerable snippet in file to apply replacement.",
                )

            # Write patched code to disk
            target_file.write_text(patched_content, encoding="utf-8")

        # Compute unified diff
        diff_lines = list(
            difflib.unified_diff(
                original_content.splitlines(keepends=True),
                patched_content.splitlines(keepends=True),
                fromfile=f"a/{file_path_str}",
                tofile=f"b/{file_path_str}",
            )
        )
        unified_diff = "".join(diff_lines)

        # Step 2: Re-run ONLY the flagging scanner on this single file
        orchestrator = ScannerOrchestrator(config=self.config)
        scan_result = orchestrator.run_scanners(
            target_path=self.target_root,
            is_full_scan=False,
            changed_files=[target_file],
            requested_scanners=[finding.scanner_name],
            timeout_seconds=20,
        )

        # Check if the specific finding/rule still appears in scanner findings
        remaining_flags = [
            f for f in scan_result.findings
            if f.rule_id.lower() == finding.rule_id.lower()
            and (f.file_path == file_path_str or Path(f.file_path).name == target_file.name)
        ]

        duration = time.perf_counter() - start_time

        # Check if scanner is installed
        scanner_res = next(
            (sr for sr in scan_result.scanner_results if sr.scanner_name.lower() == finding.scanner_name.lower()),
            None,
        )
        if scanner_res and str(scanner_res.status) == "NOT_INSTALLED":
            if auto_rollback:
                target_file.write_text(original_content, encoding="utf-8")
            return VerificationResult(
                success=False,
                file_path=file_path_str,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                remaining_findings_count=0,
                diff_unified=unified_diff,
                message=f"Scanner '{finding.scanner_name}' is not installed in system PATH. Cannot verify fix.",
                duration_seconds=duration,
            )

        # Step 3: Handle Verification Failure
        if remaining_flags:
            if auto_rollback:
                target_file.write_text(original_content, encoding="utf-8")
            return VerificationResult(
                success=False,
                file_path=file_path_str,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                remaining_findings_count=len(remaining_flags),
                diff_unified=unified_diff,
                message=f"Scanner {finding.scanner_name} still flagged {len(remaining_flags)} finding(s) after patch.",
                duration_seconds=duration,
            )

        # Step 4: Verification Succeeded! Commit to Immune Memory and AGENTS.md
        language = self.normalizer.detect_language(file_path_str)
        snippet_for_ast = original_snippet or finding.snippet or "vulnerability"

        antibody = self.immune_store.remember_finding(
            finding=finding,
            code_snippet=snippet_for_ast,
            resolution="REMEDIATED",
            language=language,
            agents_rule=proposal.agents_rule,
            metadata={
                "verified_patch": unified_diff,
                "verified_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        rule_added = False
        if proposal.agents_rule:
            rule_obj = AgentRule(
                rule_id=finding.rule_id,
                language=language,
                rule_text=proposal.agents_rule,
                severity=finding.severity.value,
            )
            rule_added = self.agents_writer.add_rule(rule_obj)

        return VerificationResult(
            success=True,
            file_path=file_path_str,
            scanner_name=finding.scanner_name,
            rule_id=finding.rule_id,
            remaining_findings_count=0,
            diff_unified=unified_diff,
            verified_patch=unified_diff,
            antibody_id=antibody.id,
            agents_rule_added=rule_added,
            message="Patch verified clean by scanner; committed to AST memory and AGENTS.md.",
            duration_seconds=duration,
        )

    def _apply_fuzzy_replacement(self, source: str, target: Optional[str], replacement: str) -> str:
        """Fallback whitespace-tolerant replacement when exact snippet match fails."""
        if not target:
            return source

        target_lines = [l.strip() for l in target.strip().splitlines() if l.strip()]
        if not target_lines:
            return source

        source_lines = source.splitlines()
        first_line = target_lines[0]

        start_idx = -1
        for idx, line in enumerate(source_lines):
            if first_line in line:
                start_idx = idx
                break

        if start_idx >= 0:
            end_idx = min(len(source_lines), start_idx + len(target_lines))
            new_lines = source_lines[:start_idx] + [replacement] + source_lines[end_idx:]
            return "\n".join(new_lines)

        return source
