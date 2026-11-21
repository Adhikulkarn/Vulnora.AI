"""
6-Scanner Detection Orchestrator for Vulnora AI.

Provides multi-scanner adapters and concurrent orchestration:
- Gitleaks (Secrets)
- Semgrep (Multi-language SAST)
- Bandit (Python AST)
- OSV-Scanner (Open-source Dependency Auditing)
- Trivy (Container, IaC, and CVE Scanning)
- OWASP ZAP (Dynamic Application Security Testing)
"""

from vulnora.scanners.bandit import BanditScanner
from vulnora.scanners.base import BaseScanner, ScanContext
from vulnora.scanners.gitleaks import GitleaksScanner
from vulnora.scanners.osv_scanner import OSVScanner
from vulnora.scanners.runner import SCANNER_REGISTRY, ScannerOrchestrator
from vulnora.scanners.semgrep import SemgrepScanner
from vulnora.scanners.trivy import TrivyScanner
from vulnora.scanners.zap import ZAPScanner

__all__ = [
    "BaseScanner",
    "ScanContext",
    "ScannerOrchestrator",
    "SCANNER_REGISTRY",
    "GitleaksScanner",
    "SemgrepScanner",
    "BanditScanner",
    "OSVScanner",
    "TrivyScanner",
    "ZAPScanner",
]
