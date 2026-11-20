"""
Issue Memory Store management for Vulnora AI.
Maintains .vulnora/memory.json for tracking resolved, accepted, and discarded issues.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Optional

from .config import get_vulnora_dir

DEFAULT_MEMORY_TEMPLATE: Dict[str, Any] = {
    "version": "1.0",
    "created_at": "",
    "last_updated": "",
    "accepted_vulnerabilities": [],
    "discarded_vulnerabilities": [],
    "issue_memory": [],
    "scan_history": [],
}


def get_memory_path(base_path: Optional[Path] = None) -> Path:
    """Returns the path to .vulnora/memory.json."""
    return get_vulnora_dir(base_path) / "memory.json"


def init_memory(base_path: Optional[Path] = None, overwrite: bool = False) -> Path:
    """
    Initializes .vulnora/memory.json if it does not already exist.
    """
    mem_file = get_memory_path(base_path)
    if mem_file.exists() and not overwrite:
        return mem_file

    mem_file.parent.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    data = dict(DEFAULT_MEMORY_TEMPLATE)
    data["created_at"] = now_iso
    data["last_updated"] = now_iso

    with mem_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return mem_file


def load_memory(base_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads memory from .vulnora/memory.json or returns default template.
    """
    mem_file = get_memory_path(base_path)
    if not mem_file.exists():
        return dict(DEFAULT_MEMORY_TEMPLATE)

    try:
        with mem_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dict(DEFAULT_MEMORY_TEMPLATE)


def save_memory(data: Dict[str, Any], base_path: Optional[Path] = None) -> Path:
    """
    Saves data to .vulnora/memory.json, updating last_updated timestamp.
    """
    mem_file = get_memory_path(base_path)
    mem_file.parent.mkdir(parents=True, exist_ok=True)
    data["last_updated"] = datetime.now(timezone.utc).isoformat()

    with mem_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return mem_file

