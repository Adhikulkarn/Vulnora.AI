"""
Issue Memory Store management for Vulnora AI.
Maintains .vulnora/memory.json for tracking resolved, accepted, and discarded issues.
Backed by the robust, atomic vulnora.memory.MemoryStore.
"""

from pathlib import Path
from typing import Any, Dict, Optional

from vulnora.memory.store import DEFAULT_MEMORY_TEMPLATE, MemoryStore


def get_memory_path(base_path: Optional[Path] = None) -> Path:
    """Returns the path to .vulnora/memory.json."""
    return MemoryStore(base_path).memory_path


def init_memory(base_path: Optional[Path] = None, overwrite: bool = False) -> Path:
    """
    Initializes .vulnora/memory.json if it does not already exist.
    """
    store = MemoryStore(base_path)
    if store.memory_path.exists() and not overwrite:
        return store.memory_path

    if overwrite and store.memory_path.exists():
        try:
            store.memory_path.unlink()
        except OSError:
            pass

    return store.ensure_memory_file()


def load_memory(base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads memory from .vulnora/memory.json or returns default template.
    """
    return MemoryStore(base_path).load_data()


def save_memory(data: Dict[str, Any], base_path: Optional[Path] = None) -> Path:
    """
    Saves data to .vulnora/memory.json atomically, updating last_updated timestamp.
    """
    store = MemoryStore(base_path)
    store.save_data(data)
    return store.memory_path
    mem_file = get_memory_path(base_path)
    mem_file.parent.mkdir(parents=True, exist_ok=True)
    data["last_updated"] = datetime.now(timezone.utc).isoformat()

    with mem_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return mem_file


def compute_pattern_key(finding: Dict[str, Any]) -> str:
    """
    Computes a deterministic pattern key/signature from scanner_name, rule_id,
    and finding fingerprint or file_path.
    """
    import hashlib

    scanner = str(finding.get("scanner_name") or "").strip().lower()
    rule_id = str(finding.get("rule_id") or "").strip()
    fp = str(finding.get("fingerprint") or "").strip()
    file_path = str(finding.get("file_path") or "").strip()
    raw = f"{scanner}:{rule_id}:{fp or file_path}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def lookup_memory_fix(memory_data: Dict[str, Any], finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Checks issue_memory for a prior verified fix matching (scanner_name, rule_id)
    or pattern key so known issues can be resolved immediately without calling remote AI.
    """
    issue_memory = memory_data.get("issue_memory", [])
    if not isinstance(issue_memory, list) or not issue_memory:
        return None

    target_pattern_key = compute_pattern_key(finding)
    target_rule = str(finding.get("rule_id") or "").strip()
    target_scanner = str(finding.get("scanner_name") or "").strip().lower()

    # Pass 1: exact pattern_key match
    for entry in issue_memory:
        if isinstance(entry, dict) and entry.get("pattern_key") == target_pattern_key:
            return {
                "root_cause": entry.get("root_cause", ""),
                "explanation": entry.get("fix_summary") or entry.get("explanation", ""),
                "replacement_code": entry.get("patched_snippet") or entry.get("replacement_code", ""),
                "model": entry.get("model", "local-memory"),
                "source": "memory",
                "raw_response": entry,
            }

    # Pass 2: rule_id and scanner_name match
    for entry in issue_memory:
        if isinstance(entry, dict):
            rule_match = str(entry.get("rule_id", "")).strip().lower() == target_rule.lower()
            scanner_match = str(entry.get("scanner_name", "")).strip().lower() == target_scanner
            if rule_match and scanner_match and (entry.get("patched_snippet") or entry.get("replacement_code")):
                return {
                    "root_cause": entry.get("root_cause", ""),
                    "explanation": entry.get("fix_summary") or entry.get("explanation", ""),
                    "replacement_code": entry.get("patched_snippet") or entry.get("replacement_code", ""),
                    "model": entry.get("model", "local-memory"),
                    "source": "memory",
                    "raw_response": entry,
                }

    return None


def is_vulnerability_discarded(memory_data: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    """
    Checks discarded_vulnerabilities for prior discarded findings.
    """
    discarded = memory_data.get("discarded_vulnerabilities", [])
    if not isinstance(discarded, list) or not discarded:
        return False

    target_pattern_key = compute_pattern_key(finding)
    target_fp = str(finding.get("fingerprint") or "").strip()
    target_rule = str(finding.get("rule_id") or "").strip()
    target_file = str(finding.get("file_path") or "").strip()

    for item in discarded:
        if isinstance(item, str):
            if item in (target_pattern_key, target_fp, target_rule):
                return True
        elif isinstance(item, dict):
            if item.get("pattern_key") and item.get("pattern_key") == target_pattern_key:
                return True
            if target_fp and item.get("fingerprint") == target_fp:
                return True
            if item.get("rule_id") == target_rule and item.get("file_path") == target_file:
                return True

    return False


def record_verified_fix(
    memory_data: Dict[str, Any],
    finding: Dict[str, Any],
    fix_payload: Dict[str, Any],
    file_path: str,
) -> Dict[str, Any]:
    """
    Stores verified fix in issue_memory and appends to accepted_vulnerabilities.
    Applies redact_secrets to replacement_code to guarantee clean persistence.
    """
    from .ai_client import redact_secrets

    pattern_key = compute_pattern_key(finding)
    raw_snippet = fix_payload.get("replacement_code") or fix_payload.get("patched_snippet") or ""
    patched_snippet = redact_secrets(raw_snippet)
    explanation = fix_payload.get("explanation") or fix_payload.get("fix_summary") or ""
    root_cause = fix_payload.get("root_cause") or ""
    now_iso = datetime.now(timezone.utc).isoformat()

    entry = {
        "pattern_key": pattern_key,
        "fingerprint": finding.get("fingerprint", ""),
        "rule_id": finding.get("rule_id", ""),
        "scanner_name": finding.get("scanner_name", ""),
        "file_path": str(file_path),
        "root_cause": root_cause,
        "fix_summary": explanation,
        "patched_snippet": patched_snippet,
        "timestamp": now_iso,
    }

    issue_memory = memory_data.setdefault("issue_memory", [])
    updated = False
    for i, existing in enumerate(issue_memory):
        if isinstance(existing, dict) and existing.get("pattern_key") == pattern_key:
            issue_memory[i] = entry
            updated = True
            break
    if not updated:
        issue_memory.append(entry)

    accepted = memory_data.setdefault("accepted_vulnerabilities", [])
    accepted_record = {
        "pattern_key": pattern_key,
        "rule_id": finding.get("rule_id", ""),
        "file_path": str(file_path),
        "timestamp": now_iso,
    }
    if not any(isinstance(a, dict) and a.get("pattern_key") == pattern_key for a in accepted):
        accepted.append(accepted_record)

    memory_data["last_updated"] = now_iso
    return memory_data


def record_discarded_finding(
    memory_data: Dict[str, Any],
    finding: Dict[str, Any],
    reason: str = "discarded_by_user",
) -> Dict[str, Any]:
    """
    Records finding decision in discarded_vulnerabilities list.
    """
    pattern_key = compute_pattern_key(finding)
    now_iso = datetime.now(timezone.utc).isoformat()

    entry = {
        "pattern_key": pattern_key,
        "fingerprint": finding.get("fingerprint", ""),
        "rule_id": finding.get("rule_id", ""),
        "scanner_name": finding.get("scanner_name", ""),
        "file_path": str(finding.get("file_path", "")),
        "reason": reason,
        "timestamp": now_iso,
    }

    discarded = memory_data.setdefault("discarded_vulnerabilities", [])
    if not any(isinstance(d, dict) and d.get("pattern_key") == pattern_key for d in discarded):
        discarded.append(entry)

    memory_data["last_updated"] = now_iso
    return memory_data


