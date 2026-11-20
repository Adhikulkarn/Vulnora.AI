"""
High-level service API for the Vulnora AI Local Issue Memory System.
Coordinates storage, deterministic signature matching, record saving, and stats calculation.
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from vulnora.scanners.data_structures import NormalizedFinding, Severity, mask_secret
from .engine import MemoryLookupEngine
from .models import MatchConfidence, MemoryMatchResult, MemoryRecord
from .signatures import detect_file_type, generate_code_fingerprint, generate_vulnerability_signature
from .store import MemoryStore


class MemoryService:
    """
    Central service interface for interacting with Vulnora's local memory system.
    """

    def __init__(self, base_path: Optional[Path] = None):
        self.store = MemoryStore(base_path)
        self.engine = MemoryLookupEngine(self.store)

    def save_verified_resolution(
        self,
        title: str,
        scanner_name: str,
        rule_id: str,
        severity: str,
        root_cause: str,
        remediation: str,
        file_path_or_type: Optional[str] = None,
        code_snippet: Optional[str] = None,
        fix_metadata: Optional[Dict[str, Any]] = None,
        verified: bool = True,
    ) -> MemoryRecord:
        """
        Stores a previously resolved and verified vulnerability resolution.
        Requirement 6: Only save when explicitly marked resolved and verified.
        """
        if not verified:
            raise ValueError("Only verified vulnerability resolutions can be saved to local memory.")

        if not remediation or not remediation.strip():
            raise ValueError("Remediation instructions cannot be empty.")

        file_type = detect_file_type(file_path_or_type)
        signature = generate_vulnerability_signature(
            scanner_name=scanner_name,
            rule_id=rule_id,
            file_path_or_type=file_type,
            code_snippet=code_snippet,
        )

        code_fp = generate_code_fingerprint(code_snippet)

        # Generate a deterministic unique ID based on signature
        id_hash = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:10]
        record_id = f"mem_{id_hash}"

        meta = dict(fix_metadata or {})
        meta["verified_at"] = datetime.now(timezone.utc).isoformat()
        meta["verification_status"] = "VERIFIED_RESCAN"

        # Sanitize sensitive credentials from title if it looks like an exposed token
        clean_title = mask_secret(title.strip()) if len(title) > 60 and " " not in title else title.strip()
        clean_root_cause = root_cause.strip()
        clean_remediation = remediation.strip()

        record = MemoryRecord(
            id=record_id,
            title=clean_title,
            scanner_name=scanner_name.strip().lower(),
            rule_id=rule_id.strip(),
            severity=Severity.normalize(severity),
            vulnerability_signature=signature,
            file_type=file_type,
            root_cause=clean_root_cause,
            remediation=clean_remediation,
            code_fingerprint=code_fp,
            fix_metadata=meta,
        )

        return self.store.save_record(record)

    def lookup_finding(self, finding: NormalizedFinding) -> MemoryMatchResult:
        """Looks up memory matches for a single NormalizedFinding."""
        return self.engine.match_finding(finding)

    def lookup_findings(
        self,
        findings: List[NormalizedFinding],
        update_usage: bool = False,
    ) -> List[MemoryMatchResult]:
        """Looks up memory matches for a list of findings."""
        return self.engine.match_findings(findings, update_usage=update_usage)

    def list_records(self) -> List[MemoryRecord]:
        """Returns all memory records sorted by creation date descending."""
        records = self.store.get_records()
        return sorted(records, key=lambda r: r.created_at, reverse=True)

    def get_record(self, record_id: str) -> Optional[MemoryRecord]:
        """Retrieves a single record by its ID."""
        return self.store.get_record(record_id)

    def delete_record(self, record_id: str) -> bool:
        """Deletes a record by ID."""
        return self.store.delete_record(record_id)

    def search_records(
        self,
        query: Optional[str] = None,
        scanner: Optional[str] = None,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[MemoryRecord]:
        """
        Searches records using deterministic filters and keyword matching.
        """
        records = self.store.get_records()
        filtered = []

        q_lower = query.strip().lower() if query else None
        scanner_lower = scanner.strip().lower() if scanner else None
        rule_lower = rule_id.strip().lower() if rule_id else None
        sev_norm = Severity.normalize(severity) if severity else None

        for r in records:
            if scanner_lower and r.scanner_name.lower() != scanner_lower:
                continue
            if rule_lower and rule_lower not in r.rule_id.lower():
                continue
            if sev_norm and r.severity != sev_norm:
                continue
            if q_lower:
                in_title = q_lower in r.title.lower()
                in_root = q_lower in r.root_cause.lower()
                in_rem = q_lower in r.remediation.lower()
                in_rule = q_lower in r.rule_id.lower()
                if not (in_title or in_root or in_rem or in_rule):
                    continue

            filtered.append(r)

        return sorted(filtered, key=lambda r: (r.match_count, r.created_at), reverse=True)

    def get_stats(self) -> Dict[str, Any]:
        """
        Generates usage statistics across all stored records.
        """
        records = self.store.get_records()

        by_scanner: Dict[str, int] = {}
        by_severity: Dict[str, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        total_matches = 0

        for r in records:
            s_name = r.scanner_name.lower()
            by_scanner[s_name] = by_scanner.get(s_name, 0) + 1

            sev = r.severity
            if sev in by_severity:
                by_severity[sev] += 1
            else:
                by_severity[sev] = 1

            total_matches += r.match_count

        most_matched = sorted([r for r in records if r.match_count > 0],
                              key=lambda r: r.match_count, reverse=True)[:5]

        recently_used = sorted([r for r in records if r.last_used_at],
                               key=lambda r: r.last_used_at or "", reverse=True)[:5]

        return {
            "total_records": len(records),
            "total_matches": total_matches,
            "by_scanner": by_scanner,
            "by_severity": by_severity,
            "most_matched": [r.to_dict() for r in most_matched],
            "recently_used": [r.to_dict() for r in recently_used],
        }
