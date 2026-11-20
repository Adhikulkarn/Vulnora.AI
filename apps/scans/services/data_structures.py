import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedFinding:
    """
    Unified representation of a vulnerability or secret finding identified
    by any security scanner (Gitleaks, Semgrep, Bandit, OSV-Scanner).
    """
    title: str
    description: str
    scanner_name: str
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str
    line_number: Optional[int] = None
    end_line_number: Optional[int] = None
    remediation: str = ""
    reference_urls: List[str] = field(default_factory=list)
    fingerprint: str = ""
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.fingerprint:
            # Deterministic hash to identify duplicate findings
            raw_fp = f"{self.scanner_name}:{self.rule_id}:{self.file_path}:{self.line_number or 0}"
            self.fingerprint = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "scanner_name": self.scanner_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "end_line_number": self.end_line_number,
            "remediation": self.remediation,
            "reference_urls": self.reference_urls,
            "fingerprint": self.fingerprint,
            "raw_details": self.raw_details,
        }


@dataclass
class ScannerExecutionResult:
    """
    Tracks the execution status and findings output from an individual scanner run.
    """
    scanner_name: str
    status: str  # COMPLETED, FAILED, TIMED_OUT, NOT_INSTALLED
    duration_seconds: float = 0.0
    findings: List[NormalizedFinding] = field(default_factory=list)
    error_message: Optional[str] = None
    raw_output: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings_count": len(self.findings),
            "error_message": self.error_message,
        }

