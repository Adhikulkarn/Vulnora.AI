"""
Data models for the Vulnora AI Local Issue Memory System.
Defines MemoryRecord, MatchConfidence, and MemoryMatchResult.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from vulnora.scanners.data_structures import Severity, mask_secret


class MatchConfidence:
    """Confidence levels for memory resolution matching."""
    EXACT = "EXACT"          # Exact signature match (rule + language + code pattern hash)
    RULE_MATCH = "RULE_MATCH"  # Scanner + Rule ID + Language match
    PARTIAL = "PARTIAL"      # Scanner + Rule ID match across different file types
    NONE = "NONE"            # No match found

    SCORE_MAP = {
        EXACT: 1.0,
        RULE_MATCH: 0.85,
        PARTIAL: 0.60,
        NONE: 0.0,
    }


@dataclass
class MemoryRecord:
    """
    Structured record of a previously resolved and verified security vulnerability.
    Stored inside `.vulnora/memory.json`.
    """
    id: str
    title: str
    scanner_name: str
    rule_id: str
    severity: str
    vulnerability_signature: str
    file_type: str = "generic"
    root_cause: str = ""
    remediation: str = ""
    code_fingerprint: str = ""
    fix_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_used_at: Optional[str] = None
    match_count: int = 0

    def __post_init__(self):
        self.severity = Severity.normalize(self.severity)
        self.scanner_name = self.scanner_name.strip().lower()
        self.rule_id = self.rule_id.strip()

        # Sanitize any accidental secrets from remediation, root_cause, and title
        self.title = mask_secret(self.title) if len(self.title) > 80 and " " not in self.title else self.title
        if self.scanner_name == "gitleaks":
            self.remediation = mask_secret(self.remediation) if "secret" in self.remediation.lower() else self.remediation
            self.root_cause = mask_secret(self.root_cause) if "secret" in self.root_cause.lower() else self.root_cause

    def record_match(self) -> None:
        """Increments match count and updates last_used_at timestamp."""
        self.match_count += 1
        self.last_used_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the memory record to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "scanner_name": self.scanner_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "vulnerability_signature": self.vulnerability_signature,
            "file_type": self.file_type,
            "root_cause": self.root_cause,
            "remediation": self.remediation,
            "code_fingerprint": self.code_fingerprint,
            "fix_metadata": self.fix_metadata,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "match_count": self.match_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryRecord":
        """Deserializes a dictionary into a MemoryRecord instance."""
        return cls(
            id=data.get("id", ""),
            title=data.get("title", "Untitled Vulnerability"),
            scanner_name=data.get("scanner_name", "unknown"),
            rule_id=data.get("rule_id", "unknown"),
            severity=data.get("severity", Severity.INFO),
            vulnerability_signature=data.get("vulnerability_signature", ""),
            file_type=data.get("file_type", "generic"),
            root_cause=data.get("root_cause", ""),
            remediation=data.get("remediation", ""),
            code_fingerprint=data.get("code_fingerprint", ""),
            fix_metadata=data.get("fix_metadata", {}),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            last_used_at=data.get("last_used_at"),
            match_count=data.get("match_count", 0),
        )


@dataclass
class MemoryMatchResult:
    """
    Represents the result of querying local memory for a discovered vulnerability finding.
    """
    finding_fingerprint: str
    finding_title: str
    scanner_name: str
    rule_id: str
    confidence: str = MatchConfidence.NONE
    confidence_score: float = 0.0
    record: Optional[MemoryRecord] = None
    match_reason: str = "No matching resolution in local memory"

    @property
    def has_match(self) -> bool:
        return self.record is not None and self.confidence != MatchConfidence.NONE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.has_match,
            "finding_fingerprint": self.finding_fingerprint,
            "finding_title": self.finding_title,
            "scanner_name": self.scanner_name,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "match_reason": self.match_reason,
            "memory_id": self.record.id if self.record else None,
            "verified_remediation": self.record.remediation if self.record else None,
            "root_cause": self.record.root_cause if self.record else None,
        }
