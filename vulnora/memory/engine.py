"""
Deterministic lookup engine for the Vulnora AI Local Issue Memory System.
Matches incoming scanner findings against stored resolutions using exact signatures,
rule IDs, and language targets with explicit confidence scores.
"""

from typing import List, Optional

from vulnora.scanners.data_structures import NormalizedFinding
from .models import MatchConfidence, MemoryMatchResult, MemoryRecord
from .signatures import detect_file_type, generate_vulnerability_signature
from .store import MemoryStore


class MemoryLookupEngine:
    """
    Evaluates findings against `.vulnora/memory.json` without semantic/AI ambiguity.
    Matching Hierarchy:
      1. EXACT: Exact signature match (rule + language + normalized code pattern).
      2. RULE_MATCH: Scanner name + Rule/CVE ID + File type match.
      3. PARTIAL: Scanner name + Rule/CVE ID match across projects/languages.
      4. NONE: No relevant resolution pattern found.
    """

    def __init__(self, store: Optional[MemoryStore] = None):
        self.store = store or MemoryStore()

    def match_finding(self, finding: NormalizedFinding) -> MemoryMatchResult:
        """
        Queries stored memory records for a match against the given NormalizedFinding.
        """
        records = self.store.get_records()
        if not records:
            return MemoryMatchResult(
                finding_fingerprint=finding.fingerprint,
                finding_title=finding.title,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                confidence=MatchConfidence.NONE,
                confidence_score=0.0,
                match_reason="Memory store is empty",
            )

        # 1. Generate finding signature
        file_type = detect_file_type(finding.file_path)
        # Check if description or remediation contains code pattern hint
        finding_sig = generate_vulnerability_signature(
            scanner_name=finding.scanner_name,
            rule_id=finding.rule_id,
            file_path_or_type=file_type,
            code_snippet=None,
        )

        norm_scanner = finding.scanner_name.strip().lower()
        norm_rule = finding.rule_id.strip().lower()

        exact_matches: List[MemoryRecord] = []
        rule_type_matches: List[MemoryRecord] = []
        rule_only_matches: List[MemoryRecord] = []

        for rec in records:
            # Check 1: Exact signature
            if rec.vulnerability_signature == finding_sig:
                exact_matches.append(rec)
                continue

            # Check 2 & 3: Match on scanner and rule ID
            rec_scanner = rec.scanner_name.strip().lower()
            rec_rule = rec.rule_id.strip().lower()

            if rec_scanner == norm_scanner and rec_rule == norm_rule:
                if rec.file_type == file_type:
                    rule_type_matches.append(rec)
                else:
                    rule_only_matches.append(rec)

        # Helper to sort candidates by match_count desc, last_used_at desc
        def _sort_key(r: MemoryRecord):
            return (r.match_count, r.last_used_at or "")

        # 1. Return highest exact match
        if exact_matches:
            best_exact = max(exact_matches, key=_sort_key)
            return MemoryMatchResult(
                finding_fingerprint=finding.fingerprint,
                finding_title=finding.title,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                confidence=MatchConfidence.EXACT,
                confidence_score=MatchConfidence.SCORE_MAP[MatchConfidence.EXACT],
                record=best_exact,
                match_reason=f"Exact signature match ({best_exact.vulnerability_signature})",
            )

        # 2. Return rule + file_type match
        if rule_type_matches:
            best_rule_type = max(rule_type_matches, key=_sort_key)
            return MemoryMatchResult(
                finding_fingerprint=finding.fingerprint,
                finding_title=finding.title,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                confidence=MatchConfidence.RULE_MATCH,
                confidence_score=MatchConfidence.SCORE_MAP[MatchConfidence.RULE_MATCH],
                record=best_rule_type,
                match_reason=f"Rule ID '{best_rule_type.rule_id}' & language '{best_rule_type.file_type}' matched",
            )

        # 3. Return rule-only match
        if rule_only_matches:
            best_rule_only = max(rule_only_matches, key=_sort_key)
            return MemoryMatchResult(
                finding_fingerprint=finding.fingerprint,
                finding_title=finding.title,
                scanner_name=finding.scanner_name,
                rule_id=finding.rule_id,
                confidence=MatchConfidence.PARTIAL,
                confidence_score=MatchConfidence.SCORE_MAP[MatchConfidence.PARTIAL],
                record=best_rule_only,
                match_reason=f"Rule ID '{best_rule_only.rule_id}' matched (file type: {best_rule_only.file_type})",
            )

        # 4. Safe Fallback: No match
        return MemoryMatchResult(
            finding_fingerprint=finding.fingerprint,
            finding_title=finding.title,
            scanner_name=finding.scanner_name,
            rule_id=finding.rule_id,
            confidence=MatchConfidence.NONE,
            confidence_score=0.0,
            match_reason="No verified resolution pattern in local memory",
        )

    def match_findings(
        self,
        findings: List[NormalizedFinding],
        update_usage: bool = False,
    ) -> List[MemoryMatchResult]:
        """
        Evaluates a collection of findings against memory records.
        If `update_usage` is True, increments match counts for any matched records.
        """
        results = []
        for finding in findings:
            res = self.match_finding(finding)
            if update_usage and res.has_match and res.record:
                self.store.increment_match(res.record.id)
            results.append(res)
        return results
