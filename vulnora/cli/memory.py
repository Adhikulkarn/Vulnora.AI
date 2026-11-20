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
