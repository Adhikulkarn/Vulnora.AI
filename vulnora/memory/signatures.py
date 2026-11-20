"""
Deterministic signature generator for the Vulnora AI Local Issue Memory System.
Ensures recurring vulnerabilities are reliably matched across files and projects
without depending solely on brittle file paths or vulnerability titles.
"""

import hashlib
from pathlib import Path
import re
from typing import Optional

# Standard mapping of file extensions to canonical language/file types
EXTENSION_MAP = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".cs": "csharp",
    ".rs": "rust",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".html": "html",
    ".htm": "html",
    ".xml": "xml",
    ".env": "env",
}


def detect_file_type(file_path: Optional[str]) -> str:
    """
    Infers canonical language or file type from a file path or name.
    """
    if not file_path:
        return "generic"

    name_lower = Path(file_path).name.lower()
    if name_lower in ("dockerfile", "containerfile"):
        return "dockerfile"
    if name_lower.startswith(".env") or name_lower.endswith(".env"):
        return "env"
    if name_lower in ("requirements.txt", "pipfile", "pyproject.toml", "setup.py"):
        return "python-dependency"
    if name_lower in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return "node-dependency"
    if name_lower in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "jvm-dependency"

    suffix = Path(file_path).suffix.lower()
    return EXTENSION_MAP.get(suffix, "generic")


def normalize_code_pattern(code_snippet: Optional[str]) -> str:
    """
    Normalizes a code snippet or vulnerability pattern:
    - Strips leading/trailing whitespace.
    - Replaces internal multi-spaces and newlines with a single space.
    - Strips quotes and comments to focus on abstract syntax tokens.
    """
    if not code_snippet:
        return ""

    # Normalize whitespace
    cleaned = re.sub(r"\s+", " ", code_snippet.strip())
    # Remove sensitive token-like sequences (alphanumeric sequences >= 16 chars)
    cleaned = re.sub(r"['\"][a-zA-Z0-9_\-\.]{16,}['\"]", "'[REDACTED]'", cleaned)
    return cleaned.strip()


def generate_code_fingerprint(code_snippet: Optional[str]) -> str:
    """
    Generates a deterministic 16-character SHA-256 hash of a normalized code snippet.
    """
    normalized = normalize_code_pattern(code_snippet)
    if not normalized:
        return "none"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def generate_vulnerability_signature(
    scanner_name: str,
    rule_id: str,
    file_path_or_type: Optional[str] = None,
    code_snippet: Optional[str] = None,
) -> str:
    """
    Generates a deterministic, collision-resistant vulnerability signature.
    Signature components:
      - Normalized scanner name (e.g. 'bandit', 'semgrep', 'osv-scanner')
      - Normalized rule ID or CVE ID (e.g. 'b605', 'ghsa-82r6-8w77-94w6')
      - Inferred file/language type (e.g. 'python', 'dockerfile', 'env')
      - Normalized code fingerprint
    Format:
      sig_<24-char SHA256 hex digest>
    """
    scanner_norm = (scanner_name or "unknown").strip().lower()
    rule_norm = (rule_id or "unknown").strip().lower()

    # Determine file type: if already canonical file type, keep it; else detect from path
    if file_path_or_type and file_path_or_type in EXTENSION_MAP.values():
        file_type = file_path_or_type
    else:
        file_type = detect_file_type(file_path_or_type)

    code_fp = generate_code_fingerprint(code_snippet)

    raw_signature_payload = f"vulnora:v1:{scanner_norm}:{rule_norm}:{file_type}:{code_fp}"
    sig_hash = hashlib.sha256(raw_signature_payload.encode("utf-8")).hexdigest()[:24]
    return f"sig_{sig_hash}"


def generate_rule_signature(
    scanner_name: str,
    rule_id: str,
    file_path_or_type: Optional[str] = None,
) -> str:
    """
    Generates a broader rule-level signature (without code snippet) for fallback matching.
    """
    scanner_norm = (scanner_name or "unknown").strip().lower()
    rule_norm = (rule_id or "unknown").strip().lower()

    if file_path_or_type and file_path_or_type in EXTENSION_MAP.values():
        file_type = file_path_or_type
    else:
        file_type = detect_file_type(file_path_or_type)

    return f"rule:{scanner_norm}:{rule_norm}:{file_type}"
