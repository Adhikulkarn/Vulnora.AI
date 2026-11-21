"""
Pre-egress secret scrubbing engine for Vulnora AI.

Guarantees Zero-Secret Egress across all outbound AI prompts, Cloud payloads,
memory records, and logs. Replaces detected secrets with `***REDACTED***` while
preserving surrounding code syntax, structure, and line numbers.
"""

from __future__ import annotations

import math
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple, Union

from vulnora.core.models import RedactionResult

REDACTION_MARKER = "***REDACTED***"


class SecretRedactor:
    """
    Multi-pattern and entropy-based secret detection and scrubbing engine.
    """

    def __init__(self):
        self._custom_secrets: Set[str] = set()
        # Specific known secret regex patterns
        self._patterns: List[Tuple[str, Pattern[str]]] = [
            (
                "PEM_PRIVATE_KEY",
                re.compile(
                    r"-----BEGIN (?:[A-Z\s]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z\s]+)?PRIVATE KEY-----"
                ),
            ),
            (
                "AWS_ACCESS_KEY",
                re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
            ),
            (
                "AWS_SECRET_KEY",
                re.compile(
                    r"(?i)\b(aws_secret_access_key|aws_secret_key|secret_key|aws_secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})\b"
                ),
            ),
            (
                "GITHUB_TOKEN",
                re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b"),
            ),
            (
                "GOOGLE_API_KEY",
                re.compile(r"\b((?:AIza[0-9A-Za-z_-]{30,45})|(?:AQ[\.-][0-9A-Za-z_-]{20,65}))\b"),
            ),
            (
                "SLACK_TOKEN",
                re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,250})\b"),
            ),
            (
                "STRIPE_KEY",
                re.compile(r"\b((?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
            ),
            (
                "JWT_TOKEN",
                re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
            ),
            (
                "BEARER_AUTH",
                re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9_\-\.~+/]+=*)"),
            ),
            (
                "DB_CONNECTION_URL",
                re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]+://[^:\s/@]+:)([^@\s/]+)(@[^\s/]+)"),
            ),
            (
                "GENERIC_CREDENTIAL_ASSIGNMENT",
                re.compile(
                    r"(?i)\b([a-z0-9_\-]*(?:password|passwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key|token)[a-z0-9_\-]*)[\"']?\s*[:=]\s*(['\"])(.*?)\2"
                ),
            ),
        ]

    def add_custom_secret(self, secret: str) -> None:
        """
        Registers a runtime secret string to be scrubbed before any egress or display.
        """
        if secret and len(secret.strip()) >= 6:
            self._custom_secrets.add(secret.strip())

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not text:
            return 0.0
        entropy = 0.0
        text_len = len(text)
        char_counts: Dict[str, int] = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / text_len
            entropy -= p * math.log2(p)
        return entropy

    def redact(self, text: str) -> RedactionResult:
        """
        Scans and redacts all secrets in text with `***REDACTED***`.
        Preserves indentation, line count, and surrounding code syntax.
        """
        if not text:
            return RedactionResult(redacted_text="", secrets_found_count=0, detected_types=[])

        redacted = text
        detected_types: List[str] = []
        secrets_count = 0

        # 0. Custom registered secrets (e.g. active session API keys)
        for custom_secret in self._custom_secrets:
            if custom_secret in redacted:
                secrets_count += redacted.count(custom_secret)
                if "CUSTOM_SECRET" not in detected_types:
                    detected_types.append("CUSTOM_SECRET")
                redacted = redacted.replace(custom_secret, REDACTION_MARKER)

        # 1. PEM Private Keys (multiline block)
        pem_matches = list(self._patterns[0][1].finditer(redacted))
        if pem_matches:
            for m in pem_matches:
                secrets_count += 1
                if "PEM_PRIVATE_KEY" not in detected_types:
                    detected_types.append("PEM_PRIVATE_KEY")
                # Maintain same number of lines so line numbers are not shifted
                line_count = m.group(0).count("\n")
                if line_count >= 2:
                    interior_newlines = "\n" * (line_count - 2)
                    replacement = f"-----BEGIN PRIVATE KEY-----\n# {REDACTION_MARKER}\n{interior_newlines}-----END PRIVATE KEY-----"
                else:
                    replacement = f"-----BEGIN PRIVATE KEY-----\n# {REDACTION_MARKER} -----END PRIVATE KEY-----"
                redacted = redacted.replace(m.group(0), replacement)

        # 2. Database Connection Strings (mask password only)
        db_pat = [p for p in self._patterns if p[0] == "DB_CONNECTION_URL"][0][1]
        for m in db_pat.finditer(redacted):
            raw_url = m.group(0)
            prefix = m.group(1)
            pwd = m.group(2)
            suffix = m.group(3)
            if pwd and pwd != REDACTION_MARKER:
                secrets_count += 1
                if "DB_CONNECTION_URL" not in detected_types:
                    detected_types.append("DB_CONNECTION_URL")
                clean_url = f"{prefix}{REDACTION_MARKER}{suffix}"
                redacted = redacted.replace(raw_url, clean_url)

        # 3. AWS Secret Access Key assignment
        aws_sec_pat = [p for p in self._patterns if p[0] == "AWS_SECRET_KEY"][0][1]
        for m in aws_sec_pat.finditer(redacted):
            key_name = m.group(1)
            raw_val = m.group(2)
            if raw_val != REDACTION_MARKER:
                secrets_count += 1
                if "AWS_SECRET_KEY" not in detected_types:
                    detected_types.append("AWS_SECRET_KEY")
                redacted = redacted.replace(raw_val, REDACTION_MARKER)

        # 4. Bearer Token Headers
        bearer_pat = [p for p in self._patterns if p[0] == "BEARER_AUTH"][0][1]
        for m in bearer_pat.finditer(redacted):
            prefix = m.group(1)
            token = m.group(2)
            if token != REDACTION_MARKER:
                secrets_count += 1
                if "BEARER_AUTH" not in detected_types:
                    detected_types.append("BEARER_AUTH")
                redacted = redacted.replace(m.group(0), f"{prefix}{REDACTION_MARKER}")

        # 5. Direct token matches (AWS Access Key, GitHub, Google, Slack, Stripe, JWT)
        direct_patterns = [
            p for p in self._patterns
            if p[0] in ("AWS_ACCESS_KEY", "GITHUB_TOKEN", "GOOGLE_API_KEY", "SLACK_TOKEN", "STRIPE_KEY", "JWT_TOKEN")
        ]
        for name, pat in direct_patterns:
            for m in pat.finditer(redacted):
                token = m.group(1)
                if token != REDACTION_MARKER:
                    secrets_count += 1
                    if name not in detected_types:
                        detected_types.append(name)
                    redacted = redacted.replace(token, REDACTION_MARKER)

        # 6. Generic Credential Assignment (password = "...", api_key = "...")
        gen_pat = [p for p in self._patterns if p[0] == "GENERIC_CREDENTIAL_ASSIGNMENT"][0][1]
        for m in gen_pat.finditer(redacted):
            var_name = m.group(1)
            quote = m.group(2)
            val = m.group(3)
            # Avoid redacting empty strings or already redacted markers
            if val and val != REDACTION_MARKER and len(val) >= 4:
                # Do not redact common test placeholders like "REDACTED", "test", "todo"
                if val.lower() not in ("redacted", "todo", "none", "null", "false", "true", "password"):
                    secrets_count += 1
                    if "GENERIC_CREDENTIAL" not in detected_types:
                        detected_types.append("GENERIC_CREDENTIAL")
                    redacted = redacted.replace(f"{quote}{val}{quote}", f"{quote}{REDACTION_MARKER}{quote}")

        # 7. High-Entropy Value Detection
        entropy_regex = re.compile(r'''(?i)\b([a-zA-Z0-9_\-]{2,40})\s*[:=]\s*(['"])([^'"\s\r\n]{16,})\2''')
        for m in entropy_regex.finditer(redacted):
            var_key = m.group(1)
            quote = m.group(2)
            token_val = m.group(3)
            if token_val != REDACTION_MARKER:
                entropy = self.calculate_entropy(token_val)
                if entropy > 3.6:
                    secrets_count += 1
                    if "HIGH_ENTROPY_TOKEN" not in detected_types:
                        detected_types.append("HIGH_ENTROPY_TOKEN")
                    redacted = redacted.replace(f"{quote}{token_val}{quote}", f"{quote}{REDACTION_MARKER}{quote}")

        return RedactionResult(
            redacted_text=redacted,
            secrets_found_count=secrets_count,
            detected_types=detected_types,
        )

    def redact_file(self, file_path: Union[str, Path]) -> RedactionResult:
        """Reads file, redacts secrets, and returns RedactionResult."""
        p = Path(file_path).resolve()
        if not p.is_file():
            return RedactionResult(redacted_text="", secrets_found_count=0, detected_types=[])
        content = p.read_text(encoding="utf-8", errors="replace")
        return self.redact(content)

    def is_secret(self, text: str) -> bool:
        """Returns True if text contains any recognized secret pattern or high entropy."""
        res = self.redact(text)
        return res.has_redactions
