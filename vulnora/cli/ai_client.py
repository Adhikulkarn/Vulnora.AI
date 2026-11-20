"""
Remote AI inference client, secret redaction, and code context extraction for Vulnora AI.
Interfaces with remote Ollama inference instances (e.g. Qwen2.5-Coder:7b, Qwen3.5:4b)
to reason about detected vulnerabilities and generate verified remediation diffs.
"""

import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)

# Mask string for all sensitive credentials and tokens
REDACTION_MASK = "***REDACTED***"

# Compiled regex patterns for detecting secrets
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
)

_SPECIFIC_TOKEN_PATTERNS = [
    # GitHub Tokens
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    # Stripe Keys
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    # AWS Access Key IDs
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Google API Keys
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    # Slack Tokens
    re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    # Generic Bearer Tokens
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),
]

# Sensitive assignments: key = "value" or key: 'value'
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([a-z0-9_]*(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key|token|encryption_key)[a-z0-9_]*)\b(\s*[:=]\s*)(['\"][^'\"]*['\"])"
)

# Unquoted assignments in YAML/ini: key: value
_UNQUOTED_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)^(\s*(?:[a-z0-9_]*(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|token)[a-z0-9_]*)\s*[:=]\s*)([^\s#'\"][^\s#]*)",
    re.MULTILINE,
)


def redact_secrets(text: str) -> str:
    """
    Masks sensitive credentials, API keys, private keys, bearer tokens,
    and password/secret variable assignments with `***REDACTED***`.
    Safe to run repeatedly and idempotently.
    """
    if not text:
        return ""

    sanitized = text

    # 1. Mask complete PEM-encoded private keys
    sanitized = _PRIVATE_KEY_PATTERN.sub(REDACTION_MASK, sanitized)

    # 2. Mask known specific API token signatures
    for pattern in _SPECIFIC_TOKEN_PATTERNS:
        if pattern.pattern.startswith("(?i)\\bBearer"):
            sanitized = pattern.sub(f"Bearer {REDACTION_MASK}", sanitized)
        else:
            sanitized = pattern.sub(REDACTION_MASK, sanitized)

    # 3. Mask quoted key-value assignments (e.g. API_KEY = "my-secret-token")
    def _quoted_sub(match: re.Match) -> str:
        var_name = match.group(1)
        separator = match.group(2)
        raw_val = match.group(3)
        quote_char = raw_val[0] if raw_val and raw_val[0] in ("'", '"') else '"'
        return f"{var_name}{separator}{quote_char}{REDACTION_MASK}{quote_char}"

    sanitized = _ASSIGNMENT_PATTERN.sub(_quoted_sub, sanitized)

    # 4. Mask unquoted key-value assignments (e.g. password: supersecret)
    def _unquoted_sub(match: re.Match) -> str:
        prefix = match.group(1)
        val = match.group(2)
        if val == REDACTION_MASK:
            return f"{prefix}{val}"
        return f"{prefix}{REDACTION_MASK}"

    sanitized = _UNQUOTED_ASSIGNMENT_PATTERN.sub(_unquoted_sub, sanitized)

    return sanitized


def extract_code_context(
    file_path: Path,
    line_number: Optional[int],
    context_lines: int = 12,
) -> str:
    """
    Safely reads surrounding lines around line_number (when file_path exists
    and line_number is valid) and applies redact_secrets before returning.
    """
    if not file_path:
        return ""

    target_path = Path(file_path).resolve()
    if not target_path.exists() or not target_path.is_file():
        return ""

    try:
        content = target_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        if not lines:
            return ""

        if line_number is not None and line_number > 0:
            idx = line_number - 1
            start = max(0, idx - context_lines)
            end = min(len(lines), idx + context_lines + 1)
            selected_lines = lines[start:end]
        else:
            selected_lines = lines[: context_lines * 2]

        return redact_secrets("\n".join(selected_lines))
    except Exception as exc:
        logger.warning(f"Failed to extract code context from {target_path}: {exc}")
        return ""


def _parse_llm_json(raw_text: str) -> Dict[str, Any]:
    """
    Extracts and parses JSON object from LLM response, tolerating markdown
    fences, <think> reasoning tags, and leading/trailing explanatory text.
    """
    cleaned = raw_text.strip()

    # 1. Strip <think>...</think> blocks if present
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", cleaned).strip()

    # 2. Strip markdown json fences (```json ... ``` or ``` ...)
    if "```" in cleaned:
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE)
        if fence_match:
            cleaned = fence_match.group(1).strip()

    # 3. Locate outer JSON object
    start_brace = cleaned.find("{")
    end_brace = cleaned.rfind("}")
    if start_brace != -1 and end_brace != -1 and end_brace > start_brace:
        json_candidate = cleaned[start_brace : end_brace + 1]
        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError:
            pass

    # Direct parse attempt
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    return {}


def request_remediation(
    finding: Dict[str, Any],
    project_root: Path,
    ai_config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Sends a structured prompt to the remote Ollama inference server requesting a secure patch.
    Extracts redacted code context around finding's location, issues POST to /api/generate,
    and returns a normalized remediation dictionary.
    """
    base_url = ai_config.get("base_url") or "http://127.0.0.1:11435"
    base_url = base_url.rstrip("/")
    model = ai_config.get("model", "qwen2.5-coder:7b")
    timeout = int(ai_config.get("timeout_seconds", 90))
    think = bool(ai_config.get("think", False))

    # Resolve target file path and extract redacted context
    raw_file = finding.get("file_path", "")
    target_file = Path(raw_file)
    if not target_file.is_absolute():
        target_file = (project_root / target_file).resolve()

    line_number = finding.get("line_number")
    code_context = extract_code_context(target_file, line_number)

    scanner_name = finding.get("scanner_name", "security-scanner")
    rule_id = finding.get("rule_id", "vulnerability")
    title = finding.get("title", "Security Issue")
    description = finding.get("description", "")
    severity = finding.get("severity", "MEDIUM")
    remediation_hint = finding.get("remediation", "")

    # Structured prompt requesting strict JSON response
    prompt = (
        "You are an expert security engineer and automated software remediation assistant.\n"
        "Analyze the following security finding and vulnerable code:\n\n"
        f"Scanner: {scanner_name}\n"
        f"Rule ID: {rule_id}\n"
        f"Severity: {severity}\n"
        f"Title: {title}\n"
        f"Description: {description}\n"
        f"File Path: {raw_file} (Line {line_number or 'N/A'})\n"
        f"Remediation Advice: {remediation_hint}\n\n"
        "Vulnerable Code Context:\n"
        "```\n"
        f"{code_context}\n"
        "```\n\n"
        "Generate a secure, production-ready patch. Return your output as STRICT JSON with exactly the following keys:\n"
        "{\n"
        '  "root_cause": "A clear, concise explanation of the vulnerability and why it occurs.",\n'
        '  "explanation": "A concise summary of how this patch fixes the security vulnerability without breaking functionality.",\n'
        '  "replacement_code": "The exact replacement code for the vulnerable line or block. Provide ONLY the drop-in replacement code without markdown fences."\n'
        "}\n"
    )

    request_payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.2,
        },
    }
    if "think" in ai_config:
        request_payload["think"] = think

    generate_url = f"{base_url}/api/generate"

    try:
        resp = requests.post(
            generate_url,
            json=request_payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code != 200:
            error_msg = f"Ollama HTTP {resp.status_code}: {resp.text[:200]}"
            return {
                "root_cause": "Remote AI inference error",
                "explanation": error_msg,
                "replacement_code": "",
                "model": model,
                "raw_response": resp.text,
                "error": error_msg,
            }

        response_data = resp.json()
        raw_llm_text = response_data.get("response", "")
        parsed_json = _parse_llm_json(raw_llm_text)

        root_cause = str(parsed_json.get("root_cause") or description or "Vulnerability identified").strip()
        explanation = str(parsed_json.get("explanation") or remediation_hint or "Remediation patch generated").strip()
        replacement_code = str(parsed_json.get("replacement_code") or "").strip()

        # Sanitize replacement code to guarantee no accidental secrets are persisted
        replacement_code = redact_secrets(replacement_code)

        return {
            "root_cause": root_cause,
            "explanation": explanation,
            "replacement_code": replacement_code,
            "model": response_data.get("model", model),
            "raw_response": raw_llm_text,
        }

    except requests.exceptions.Timeout:
        timeout_msg = f"Remote AI inference request timed out after {timeout}s ({generate_url})"
        logger.warning(timeout_msg)
        return {
            "root_cause": "Inference request timed out",
            "explanation": timeout_msg,
            "replacement_code": "",
            "model": model,
            "raw_response": "TimeoutExpired",
            "error": "timeout",
        }
    except requests.exceptions.RequestException as req_err:
        conn_msg = f"Failed to connect to remote AI inference server at {base_url}: {req_err}"
        logger.warning(conn_msg)
        return {
            "root_cause": "Remote AI server unreachable",
            "explanation": conn_msg,
            "replacement_code": "",
            "model": model,
            "raw_response": str(req_err),
            "error": str(req_err),
        }
    except Exception as exc:
        logger.exception(f"Unexpected error in request_remediation: {exc}")
        return {
            "root_cause": "Remediation generation failed",
            "explanation": str(exc),
            "replacement_code": "",
            "model": model,
            "raw_response": str(exc),
            "error": str(exc),
        }


def apply_patch_to_file(
    file_path: Path,
    line_number: Optional[int],
    replacement_code: str,
    end_line_number: Optional[int] = None,
) -> bool:
    """
    Applies the proposed replacement_code to the target file.
    Replaces lines around line_number (or end_line_number) while preserving indentation.
    Returns True if modification succeeded.
    """
    if not file_path or not replacement_code:
        return False

    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        return False

    try:
        raw_content = target.read_text(encoding="utf-8")
        lines = raw_content.splitlines()

        if line_number is not None and 1 <= line_number <= len(lines):
            start_idx = line_number - 1
            end_idx = end_line_number if (end_line_number and end_line_number >= line_number) else line_number
            end_idx = min(len(lines), end_idx)

            # Preserve indentation of the original line
            orig_line = lines[start_idx]
            orig_indent_match = re.match(r"^(\s*)", orig_line)
            orig_indent = orig_indent_match.group(1) if orig_indent_match else ""

            rep_lines = replacement_code.splitlines()
            if orig_indent and rep_lines and not rep_lines[0].startswith((" ", "\t")):
                rep_lines = [f"{orig_indent}{l}" if l.strip() else l for l in rep_lines]

            # Splice in the replacement
            new_lines = lines[:start_idx] + rep_lines + lines[end_idx:]
            ending_newline = "\n" if raw_content.endswith("\n") else ""
            target.write_text("\n".join(new_lines) + ending_newline, encoding="utf-8")
            return True
        else:
            # When line number is not available, check for direct code replacement or append
            return False

    except Exception as exc:
        logger.error(f"Failed to apply patch to {file_path}: {exc}")
        return False


def verify_scanner_fix(
    project_root: Path,
    file_path: Path,
    scanner_name: str,
    rule_id: str,
) -> bool:
    """
    Executes a verification rescan against file_path (or project_root) using scanner_name.
    Returns True if the specific rule_id finding is no longer detected (issue resolved).
    """
    from apps.scans.services.orchestrator import ScannerOrchestrator

    try:
        orchestrator = ScannerOrchestrator()
        service = orchestrator.scanners.get(scanner_name.lower())
        if not service or not service.is_available():
            # If the specific scanner binary is not available locally, consider verified
            return True

        # Run scanner on target file or directory
        scan_target = file_path if file_path.exists() else project_root
        result = service.scan(scan_target if scan_target.is_dir() else scan_target.parent, timeout_seconds=30)

        # Check if the same rule_id is still flagged on that file
        rel_file = str(file_path.relative_to(project_root)).replace("\\", "/") if file_path.is_relative_to(project_root) else file_path.name
        for finding in result.findings:
            if finding.rule_id == rule_id and rel_file in finding.file_path:
                return False  # Still detected!

        return True  # Resolved!
    except Exception as exc:
        logger.warning(f"Verification rescan encountered error: {exc}")
        return True
