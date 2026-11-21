"""
Data contracts and models for Vulnora AI.

Defines unified representations of security findings, scanner executions,
Git push ref updates, repository status, configuration contracts, and
the multi-scanner orchestrator results.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class Severity(str, Enum):
    """
    Standardized vulnerability severity levels with total ordering.
    Ordered from lowest severity (INFO) to highest severity (CRITICAL).
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparison: higher rank = more severe."""
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks.get(self, 0)

    def _get_other_rank(self, other: Any) -> int:
        if isinstance(other, Severity):
            return other.rank
        if isinstance(other, str):
            try:
                return Severity.from_string(other).rank
            except ValueError:
                raise TypeError(f"Cannot compare Severity with {other!r}")
        raise TypeError(f"Cannot compare Severity with {type(other).__name__}")

    def __lt__(self, other: Any) -> bool:
        try:
            return self.rank < self._get_other_rank(other)
        except TypeError:
            return NotImplemented

    def __le__(self, other: Any) -> bool:
        try:
            return self.rank <= self._get_other_rank(other)
        except TypeError:
            return NotImplemented

    def __gt__(self, other: Any) -> bool:
        try:
            return self.rank > self._get_other_rank(other)
        except TypeError:
            return NotImplemented

    def __ge__(self, other: Any) -> bool:
        try:
            return self.rank >= self._get_other_rank(other)
        except TypeError:
            return NotImplemented

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.upper()
        return False

    def __hash__(self) -> int:
        return hash(self.value)

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """
        Parses a case-insensitive severity string into a Severity enum.
        Raises ValueError if unrecognized.
        """
        if not value:
            return cls.INFO
        normalized = value.strip().upper()
        # Common aliases from various scanners
        alias_map = {
            "ERROR": cls.HIGH,
            "WARN": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "NOTE": cls.LOW,
            "NOTICE": cls.INFO,
            "MODERATE": cls.MEDIUM,
        }
        if normalized in alias_map:
            return alias_map[normalized]
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown severity level: {value!r}")

    # Backward and forward compatibility alias
    from_str = from_string


class ScanStatus(str, Enum):
    """Execution status of an individual security scanner."""
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    NOT_INSTALLED = "NOT_INSTALLED"
    SKIPPED = "SKIPPED"

    @classmethod
    def from_string(cls, value: str) -> ScanStatus:
        if not value:
            return cls.FAILED
        normalized = value.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.FAILED


# Alias ScannerStatus to ScanStatus for backward and forward compatibility
ScannerStatus = ScanStatus


@dataclass
class Finding:
    """
    Unified representation of a vulnerability, secret leak, or misconfiguration
    identified by any security scanner (Gitleaks, Semgrep, Bandit, OSV-Scanner, Trivy, etc.).
    """
    title: str
    description: str
    scanner_name: str
    rule_id: str
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    end_line_number: Optional[int] = None
    snippet: Optional[str] = None
    remediation: str = ""
    reference_urls: List[str] = field(default_factory=list)
    fingerprint: str = ""
    raw_details: Dict[str, Any] = field(default_factory=dict)
    is_secret: bool = False

    def __post_init__(self) -> None:
        # Normalize severity if string was passed
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            self.severity = Severity.from_string(self.severity)

        # Ensure reference_urls is a list
        if not isinstance(self.reference_urls, list):
            self.reference_urls = list(self.reference_urls) if self.reference_urls else []

        # Auto-compute deterministic SHA-256 fingerprint if missing
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """
        Computes a deterministic 32-character SHA-256 hex digest for deduplication.
        Combines scanner name, rule ID, file path, and line number.
        """
        raw = f"{self.scanner_name}:{self.rule_id}:{self.file_path}:{self.line_number or 0}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding to a clean dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "scanner_name": self.scanner_name,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "end_line_number": self.end_line_number,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "reference_urls": list(self.reference_urls),
            "fingerprint": self.fingerprint,
            "raw_details": dict(self.raw_details),
            "is_secret": self.is_secret,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Constructs a Finding instance from a dictionary."""
        data_copy = dict(data)
        sev = data_copy.get("severity", Severity.INFO)
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        data_copy["severity"] = sev
        return cls(**data_copy)


@dataclass
class ScannerResult:
    """
    Tracks the execution status, metrics, and findings from an individual scanner run.
    """
    scanner_name: str
    status: ScanStatus
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None
    raw_output: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.status, str) and not isinstance(self.status, ScanStatus):
            self.status = ScanStatus.from_string(self.status)

        # Normalize findings list elements to Finding instances
        normalized_findings: List[Finding] = []
        for f in self.findings:
            if isinstance(f, dict):
                normalized_findings.append(Finding.from_dict(f))
            elif isinstance(f, Finding):
                normalized_findings.append(f)
        self.findings = normalized_findings

    @property
    def has_findings(self) -> bool:
        """Returns True if any security findings were detected."""
        return len(self.findings) > 0

    @property
    def critical_findings(self) -> List[Finding]:
        """Returns only findings with CRITICAL severity."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        """Returns only findings with HIGH severity."""
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes scanner execution result to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "status": self.status.value,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
            "raw_output": self.raw_output,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScannerResult:
        """Constructs a ScannerResult instance from a dictionary."""
        data_copy = dict(data)
        data_copy["status"] = ScanStatus.from_string(data_copy.get("status", "FAILED"))
        raw_findings = data_copy.get("findings", [])
        data_copy["findings"] = [
            Finding.from_dict(f) if isinstance(f, dict) else f
            for f in raw_findings
        ]
        # Remove computed field if present
        data_copy.pop("findings_count", None)
        return cls(**data_copy)


@dataclass
class OrchestratorResult:
    """
    Unified result of running the multi-scanner detection pipeline.
    Aggregates findings, deduplicates overlapping reports, and summarizes scanner metrics.
    """
    target_path: str
    duration_seconds: float = 0.0
    scanner_results: List[ScannerResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scanners_run: List[str] = field(default_factory=list)
    scanners_skipped: List[str] = field(default_factory=list)
    scanners_failed: List[str] = field(default_factory=list)
    target_url: Optional[str] = None
    is_full_scan: bool = False

    def __post_init__(self) -> None:
        normalized_results: List[ScannerResult] = []
        for r in self.scanner_results:
            if isinstance(r, dict):
                normalized_results.append(ScannerResult.from_dict(r))
            elif isinstance(r, ScannerResult):
                normalized_results.append(r)
        self.scanner_results = normalized_results

        normalized_findings: List[Finding] = []
        for f in self.findings:
            if isinstance(f, dict):
                normalized_findings.append(Finding.from_dict(f))
            elif isinstance(f, Finding):
                normalized_findings.append(f)
        self.findings = normalized_findings

    @property
    def total_findings(self) -> int:
        """Total number of deduplicated findings detected across all scanners."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[Finding]:
        """Filtered list of findings with CRITICAL severity."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        """Filtered list of findings with HIGH severity."""
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> List[Finding]:
        """Filtered list of findings with MEDIUM severity."""
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> List[Finding]:
        """Filtered list of findings with LOW severity."""
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def info_findings(self) -> List[Finding]:
        """Filtered list of findings with INFO severity."""
        return [f for f in self.findings if f.severity == Severity.INFO]

    @property
    def has_critical_or_high(self) -> bool:
        """Returns True if any CRITICAL or HIGH findings were identified."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes orchestrator result to dictionary."""
        return {
            "target_path": self.target_path,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_findings": self.total_findings,
            "critical_count": len(self.critical_findings),
            "high_count": len(self.high_findings),
            "medium_count": len(self.medium_findings),
            "low_count": len(self.low_findings),
            "info_count": len(self.info_findings),
            "scanners_run": list(self.scanners_run),
            "scanners_skipped": list(self.scanners_skipped),
            "scanners_failed": list(self.scanners_failed),
            "scanner_results": [r.to_dict() for r in self.scanner_results],
            "findings": [f.to_dict() for f in self.findings],
            "target_url": self.target_url,
            "is_full_scan": self.is_full_scan,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> OrchestratorResult:
        """Constructs an OrchestratorResult from a dictionary."""
        data_copy = dict(data)
        for k in ["total_findings", "critical_count", "high_count", "medium_count", "low_count", "info_count"]:
            data_copy.pop(k, None)
        raw_sr = data_copy.get("scanner_results", [])
        data_copy["scanner_results"] = [
            ScannerResult.from_dict(r) if isinstance(r, dict) else r
            for r in raw_sr
        ]
        raw_f = data_copy.get("findings", [])
        data_copy["findings"] = [
            Finding.from_dict(f) if isinstance(f, dict) else f
            for f in raw_f
        ]
        return cls(**data_copy)


@dataclass
class PushRefUpdate:
    """
    Represents a single ref update provided by Git to the pre-push hook.
    Git passes lines to stdin formatted as:
      <local_ref> SP <local_sha> SP <remote_ref> SP <remote_sha> LF
    """
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str
    branch_name: Optional[str] = None
    is_branch: bool = False
    is_deletion: bool = False
    is_tag: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serializes PushRefUpdate to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PushRefUpdate:
        """Constructs PushRefUpdate from a dictionary."""
        return cls(**data)


@dataclass
class GitRepoStatus:
    """
    Diagnostic status of a Git repository inspected by the GitEngine.
    """
    is_git: bool
    root_path: Optional[str] = None
    current_branch: Optional[str] = None
    current_commit: Optional[str] = None
    is_detached: bool = False
    is_dirty: bool = False
    protected_branches: List[str] = field(default_factory=list)
    is_current_branch_protected: bool = False
    hooks_dir: Optional[str] = None
    hook_installed: bool = False
    detected_languages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes GitRepoStatus to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GitRepoStatus:
        """Constructs GitRepoStatus from a dictionary."""
        return cls(**data)


@dataclass
class RepoLanguage:
    """
    Language detection result for a repository, enabling language-agnostic analysis.
    """
    primary_language: str
    detected_languages: List[str] = field(default_factory=list)
    manifest_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes RepoLanguage to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RepoLanguage:
        """Constructs RepoLanguage from a dictionary."""
        return cls(**data)


class ImmunityTier(str, Enum):
    """
    Lookup tiers for local AST immune memory.
    - TIER_1_EXACT: Exact hash match (sub-1ms).
    - TIER_2_STRUCTURAL: Normalized AST structural similarity >= 85% (renamed variable variant, sub-10ms).
    - TIER_3_PARTIAL: Partial AST match (50% - 84%).
    - NO_MATCH: Similarity < 50%.
    """
    TIER_1_EXACT = "TIER_1_EXACT"
    TIER_2_STRUCTURAL = "TIER_2_STRUCTURAL"
    TIER_3_PARTIAL = "TIER_3_PARTIAL"
    NO_MATCH = "NO_MATCH"


@dataclass
class ImmuneRecord:
    """
    A single antibody record stored in local immune memory (.vulnora/memory.json).
    Contains normalized AST signatures and anonymized templates—never raw proprietary business logic.
    """
    id: str
    rule_id: str
    scanner_name: str
    severity: Severity
    language: str
    exact_hash: str
    ast_signature: str
    anonymized_template: str
    resolution: str  # e.g. "ACCEPTED_RISK", "FALSE_POSITIVE", "REMEDIATED", "PREVENTED"
    remediation_patch: Optional[str] = None
    agents_rule: str = ""
    created_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            self.severity = Severity.from_string(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes ImmuneRecord to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "scanner_name": self.scanner_name,
            "severity": self.severity.value,
            "language": self.language,
            "exact_hash": self.exact_hash,
            "ast_signature": self.ast_signature,
            "anonymized_template": self.anonymized_template,
            "resolution": self.resolution,
            "remediation_patch": self.remediation_patch,
            "agents_rule": self.agents_rule,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ImmuneRecord:
        """Constructs ImmuneRecord from a dictionary."""
        data_copy = dict(data)
        sev = data_copy.get("severity", Severity.INFO)
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        data_copy["severity"] = sev
        return cls(**data_copy)


@dataclass
class ImmuneMatch:
    """
    Result of evaluating a code finding against immune memory.
    """
    matched: bool
    tier: ImmunityTier
    similarity_score: float = 0.0
    record: Optional[ImmuneRecord] = None
    lookup_duration_ms: float = 0.0
    explanation: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.tier, str) and not isinstance(self.tier, ImmunityTier):
            self.tier = ImmunityTier(self.tier)
        if isinstance(self.record, dict):
            self.record = ImmuneRecord.from_dict(self.record)

    @property
    def is_exact(self) -> bool:
        return self.tier == ImmunityTier.TIER_1_EXACT

    @property
    def is_variant(self) -> bool:
        return self.tier == ImmunityTier.TIER_2_STRUCTURAL

    @property
    def is_partial(self) -> bool:
        return self.tier == ImmunityTier.TIER_3_PARTIAL

    def to_dict(self) -> Dict[str, Any]:
        """Serializes ImmuneMatch to dictionary."""
        return {
            "matched": self.matched,
            "tier": self.tier.value,
            "similarity_score": round(self.similarity_score, 4),
            "record": self.record.to_dict() if self.record else None,
            "lookup_duration_ms": round(self.lookup_duration_ms, 3),
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ImmuneMatch:
        """Constructs ImmuneMatch from a dictionary."""
        data_copy = dict(data)
        data_copy["tier"] = ImmunityTier(data_copy.get("tier", ImmunityTier.NO_MATCH.value))
        rec = data_copy.get("record")
        if isinstance(rec, dict):
            data_copy["record"] = ImmuneRecord.from_dict(rec)
        return cls(**data_copy)


@dataclass
class ImmunityMetrics:
    """
    Operational metrics for local immune memory.
    """
    total_records: int = 0
    records_by_language: Dict[str, int] = field(default_factory=dict)
    records_by_resolution: Dict[str, int] = field(default_factory=dict)
    records_by_severity: Dict[str, int] = field(default_factory=dict)
    tier1_hits: int = 0
    tier2_hits: int = 0
    tier3_hits: int = 0
    misses: int = 0
    avg_lookup_ms: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Percentage of lookups that resulted in antibody hits."""
        total_hits = self.tier1_hits + self.tier2_hits + self.tier3_hits
        total_lookups = total_hits + self.misses
        if total_lookups == 0:
            return 100.0
        return (total_hits / total_lookups) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes ImmunityMetrics to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ImmunityMetrics:
        """Constructs ImmunityMetrics from a dictionary."""
        return cls(**data)


@dataclass
class RedactionResult:
    """
    Result of pre-egress secret scrubbing on a text string.
    Guarantees zero-secret leakage while preserving code syntax and line integrity.
    """
    redacted_text: str
    secrets_found_count: int = 0
    detected_types: List[str] = field(default_factory=list)

    @property
    def has_redactions(self) -> bool:
        """Returns True if any secret was identified and redacted."""
        return self.secrets_found_count > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes RedactionResult to dictionary."""
        return {
            "redacted_text": self.redacted_text,
            "secrets_found_count": self.secrets_found_count,
            "detected_types": list(self.detected_types),
            "has_redactions": self.has_redactions,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RedactionResult:
        """Constructs RedactionResult from a dictionary."""
        data_copy = dict(data)
        data_copy.pop("has_redactions", None)
        return cls(**data_copy)


@dataclass
class SurgicalPrompt:
    """
    Targeted, copy-ready Markdown remediation prompt compiled for AI coding agents.
    Contains secret-scrubbed enclosing AST block, line context, and immune memory guidance.
    """
    finding_id: str
    rule_id: str
    scanner_name: str
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    enclosing_symbol: Optional[str] = None
    vulnerable_code_block: str = ""
    compiled_markdown: str = ""
    immune_hint: Optional[str] = None
    redaction_summary: Optional[RedactionResult] = None

    def __post_init__(self) -> None:
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            self.severity = Severity.from_string(self.severity)
        if isinstance(self.redaction_summary, dict):
            self.redaction_summary = RedactionResult.from_dict(self.redaction_summary)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes SurgicalPrompt to dictionary."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "scanner_name": self.scanner_name,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "enclosing_symbol": self.enclosing_symbol,
            "vulnerable_code_block": self.vulnerable_code_block,
            "compiled_markdown": self.compiled_markdown,
            "immune_hint": self.immune_hint,
            "redaction_summary": self.redaction_summary.to_dict() if self.redaction_summary else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SurgicalPrompt:
        """Constructs SurgicalPrompt from a dictionary."""
        data_copy = dict(data)
        sev = data_copy.get("severity", Severity.INFO)
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        data_copy["severity"] = sev
        red_sum = data_copy.get("redaction_summary")
        if isinstance(red_sum, dict):
            data_copy["redaction_summary"] = RedactionResult.from_dict(red_sum)
        return cls(**data_copy)


@dataclass
class RemediationProposal:
    """
    Surgical code remediation proposed by Cloud AI for a security finding.
    Contains root cause diagnosis, fix explanation, and drop-in replacement code.
    """
    finding_id: str
    rule_id: str
    file_path: str
    root_cause: str
    explanation: str
    replacement_code: str
    original_code: str = ""
    line_number: Optional[int] = None
    agents_rule: str = ""
    confidence: float = 1.0
    provider: str = ""
    model: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes RemediationProposal to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RemediationProposal:
        """Constructs RemediationProposal from dictionary."""
        return cls(**data)


@dataclass
class VerificationResult:
    """
    Outcome of verifying an applied patch by re-running the flagging security scanner.
    Captures scanner status, unified diff, immune memory recording, and AGENTS.md rule state.
    """
    success: bool
    file_path: str
    scanner_name: str
    rule_id: str
    remaining_findings_count: int = 0
    diff_unified: str = ""
    verified_patch: str = ""
    antibody_id: Optional[str] = None
    agents_rule_added: bool = False
    message: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes VerificationResult to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerificationResult:
        """Constructs VerificationResult from dictionary."""
        return cls(**data)


@dataclass
class AgentRule:
    """
    A distilled, actionable preventative rule appended to AGENTS.md.
    Teaches coding agents to avoid known vulnerability variants.
    """
    rule_id: str
    language: str
    rule_text: str
    severity: str = "HIGH"
    source: str = "vulnora"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes AgentRule to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentRule:
        """Constructs AgentRule from dictionary."""
        return cls(**data)
