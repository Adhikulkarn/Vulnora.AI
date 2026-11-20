"""
Unified vulnerability and execution data structures for Vulnora AI.
Provides normalized finding definitions, severity constants, and secret redaction.
"""

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    @classmethod
    def normalize(cls, val: Optional[str]) -> str:
        if not val:
            return cls.INFO
        clean = val.strip().upper()
        if clean in cls.ORDER:
            return clean
        if "CRIT" in clean:
            return cls.CRITICAL
        if "HIGH" in clean or "ERROR" in clean:
            return cls.HIGH
        if "MED" in clean or "WARN" in clean:
            return cls.MEDIUM
        if "LOW" in clean:
            return cls.LOW
        return cls.INFO


class ScanStatus:
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    TIMED_OUT = "TIMED_OUT"
    NOT_INSTALLED = "NOT_INSTALLED"


def mask_secret(value: str) -> str:
    """Masks secret values to prevent exposure in logs or terminal output."""
    if not value or len(value) <= 6:
        return "******"
    return f"{value[:3]}...{value[-3:]}"


@dataclass
class NormalizedFinding:
    """
    Unified representation of a vulnerability, misconfiguration, or secret finding
    discovered across any security scanner.
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
        self.severity = Severity.normalize(self.severity)

        # Deterministic fingerprint to deduplicate across runs and overlapping tools
        if not self.fingerprint:
            raw_fp = f"{self.scanner_name.lower()}:{self.rule_id}:{self.file_path}:{self.line_number or 0}"
            self.fingerprint = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:32]

        # Redact any unmasked secrets from description or remediation
        if self.scanner_name.lower() == "gitleaks":
            self.description = re.sub(r"(token|secret|key|password|credential)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
                                      r"\1: [REDACTED]", self.description, flags=re.IGNORECASE)
            self.remediation = re.sub(r"(token|secret|key|password|credential)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
                                      r"\1: [REDACTED]", self.remediation, flags=re.IGNORECASE)

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
    Tracks the execution status and normalized findings of an individual scanner run.
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
            "duration_seconds": round(self.duration_seconds, 2),
            "findings_count": len(self.findings),
            "error_message": self.error_message,
        }

