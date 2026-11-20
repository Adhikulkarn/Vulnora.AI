"""
Vulnora AI Local Issue Memory System.
Stores previously resolved and verified vulnerabilities, provides deterministic
signature matching, and integrates with the multi-scanner orchestrator.
"""

from .engine import MemoryLookupEngine
from .models import MatchConfidence, MemoryMatchResult, MemoryRecord
from .service import MemoryService
from .signatures import (
    detect_file_type,
    generate_code_fingerprint,
    generate_rule_signature,
    generate_vulnerability_signature,
    normalize_code_pattern,
)
from .store import DEFAULT_MEMORY_TEMPLATE, MemoryStore

__all__ = [
    "DEFAULT_MEMORY_TEMPLATE",
    "MatchConfidence",
    "MemoryLookupEngine",
    "MemoryMatchResult",
    "MemoryRecord",
    "MemoryService",
    "MemoryStore",
    "detect_file_type",
    "generate_code_fingerprint",
    "generate_rule_signature",
    "generate_vulnerability_signature",
    "normalize_code_pattern",
]
