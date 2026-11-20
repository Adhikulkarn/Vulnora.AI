"""
Persistent storage management for Vulnora AI Issue Memory (`.vulnora/memory.json`).
Features:
- Atomic file writes using temporary files to prevent corruption.
- Automatic creation and schema validation.
- Corrupted JSON recovery (automated timestamped backup).
- Thread-safe access.
- Secret sanitization before serialization.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional

from vulnora.cli.config import get_vulnora_dir
from vulnora.scanners.data_structures import mask_secret
from .models import MemoryRecord

logger = logging.getLogger(__name__)

DEFAULT_MEMORY_TEMPLATE: Dict[str, Any] = {
    "version": "1.0",
    "created_at": "",
    "last_updated": "",
    "accepted_vulnerabilities": [],
    "discarded_vulnerabilities": [],
    "issue_memory": [],
    "scan_history": [],
}


class MemoryStore:
    """
    Manages reading and writing `.vulnora/memory.json` with atomicity,
    corruption resilience, and duplicate prevention.
    """

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = Path(base_path).resolve() if base_path else Path.cwd()
        self.vulnora_dir = get_vulnora_dir(self.base_path)
        self.memory_path = self.vulnora_dir / "memory.json"
        self._lock = threading.RLock()

    def ensure_memory_file(self) -> Path:
        """
        Creates `.vulnora/` directory and `.vulnora/memory.json` if missing.
        """
        if self.memory_path.exists():
            return self.memory_path

        self.vulnora_dir.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.now(timezone.utc).isoformat()
        initial_data = dict(DEFAULT_MEMORY_TEMPLATE)
        initial_data["created_at"] = now_iso
        initial_data["last_updated"] = now_iso

        self._atomic_write(initial_data)
        return self.memory_path

    def load_data(self) -> Dict[str, Any]:
        """
        Loads memory data from `.vulnora/memory.json`.
        Recovers safely if JSON is missing, empty, or corrupted.
        """
        with self._lock:
            if not self.memory_path.exists():
                self.ensure_memory_file()

            try:
                content = self.memory_path.read_text(encoding="utf-8").strip()
                if not content:
                    return self._reset_to_default("Memory file was empty.")

                data = json.loads(content)
                if not isinstance(data, dict):
                    return self._reset_to_default("Root JSON structure must be an object.")

                # Ensure required keys exist
                if "issue_memory" not in data or not isinstance(data["issue_memory"], list):
                    data["issue_memory"] = []

                return data

            except (json.JSONDecodeError, OSError) as err:
                return self._recover_corrupted_file(str(err))

    def _reset_to_default(self, reason: str) -> Dict[str, Any]:
        """Resets the store to default template without backup if empty."""
        logger.warning(f"Resetting memory.json: {reason}")
        now_iso = datetime.now(timezone.utc).isoformat()
        data = dict(DEFAULT_MEMORY_TEMPLATE)
        data["created_at"] = now_iso
        data["last_updated"] = now_iso
        self._atomic_write(data)
        return data

    def _recover_corrupted_file(self, error_message: str) -> Dict[str, Any]:
        """
        Safely backs up corrupted file and initializes a clean memory store.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.memory_path.with_name(f"memory.json.corrupted.{ts}")
        try:
            if self.memory_path.exists():
                self.memory_path.rename(backup_path)
                logger.warning(f"Corrupted memory.json backed up to '{backup_path.name}'. Reason: {error_message}")
        except Exception as e:
            logger.error(f"Failed to backup corrupted memory file: {e}")

        return self._reset_to_default(f"Recovered from corrupted state: {error_message}")

    def _atomic_write(self, data: Dict[str, Any]) -> None:
        """
        Writes JSON payload atomically using a temporary file in the same directory.
        """
        self.vulnora_dir.mkdir(parents=True, exist_ok=True)
        temp_file = self.vulnora_dir / f".memory.json.tmp.{os.getpid()}"
        data["last_updated"] = datetime.now(timezone.utc).isoformat()

        # Sanitize records to ensure no raw secret tokens are accidentally stored in title
        if "issue_memory" in data and isinstance(data["issue_memory"], list):
            for item in data["issue_memory"]:
                if isinstance(item, dict):
                    title_val = item.get("title", "")
                    if len(title_val) > 60 and " " not in title_val:
                        item["title"] = mask_secret(title_val)

        try:
            with temp_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_file.replace(self.memory_path)
        except Exception:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise

    def save_data(self, data: Dict[str, Any]) -> None:
        """Saves entire memory payload atomically under thread lock."""
        with self._lock:
            self._atomic_write(data)

    def get_records(self) -> List[MemoryRecord]:
        """Returns all MemoryRecord items stored in `.vulnora/memory.json`."""
        data = self.load_data()
        records_raw = data.get("issue_memory", [])
        records = []
        for r in records_raw:
            if isinstance(r, dict):
                try:
                    records.append(MemoryRecord.from_dict(r))
                except Exception as e:
                    logger.warning(f"Skipping malformed memory record: {e}")
        return records

    def get_record(self, record_id: str) -> Optional[MemoryRecord]:
        """Finds a memory record by unique ID."""
        clean_id = record_id.strip()
        for r in self.get_records():
            if r.id == clean_id:
                return r
        return None

    def save_record(self, record: MemoryRecord) -> MemoryRecord:
        """
        Saves or updates a MemoryRecord.
        Prevents duplicate entries by matching vulnerability_signature.
        """
        with self._lock:
            data = self.load_data()
            records_raw = data.get("issue_memory", [])

            # Check for existing record by signature or ID
            existing_idx = None
            for idx, r in enumerate(records_raw):
                if isinstance(r, dict):
                    if r.get("id") == record.id or r.get("vulnerability_signature") == record.vulnerability_signature:
                        existing_idx = idx
                        break

            rec_dict = record.to_dict()

            if existing_idx is not None:
                # Update existing record while preserving creation date and existing match count
                existing = records_raw[existing_idx]
                rec_dict["created_at"] = existing.get("created_at", record.created_at)
                rec_dict["match_count"] = max(existing.get("match_count", 0), record.match_count)
                if not rec_dict.get("last_used_at"):
                    rec_dict["last_used_at"] = existing.get("last_used_at")
                records_raw[existing_idx] = rec_dict
            else:
                records_raw.append(rec_dict)

            data["issue_memory"] = records_raw
            self._atomic_write(data)
            return MemoryRecord.from_dict(rec_dict)

    def increment_match(self, record_id: str) -> Optional[MemoryRecord]:
        """
        Increments match count and updates last_used_at for the given record ID.
        """
        with self._lock:
            data = self.load_data()
            records_raw = data.get("issue_memory", [])

            updated_record = None
            for idx, r in enumerate(records_raw):
                if isinstance(r, dict) and r.get("id") == record_id:
                    r["match_count"] = r.get("match_count", 0) + 1
                    r["last_used_at"] = datetime.now(timezone.utc).isoformat()
                    updated_record = MemoryRecord.from_dict(r)
                    records_raw[idx] = r
                    break

            if updated_record:
                data["issue_memory"] = records_raw
                self._atomic_write(data)

            return updated_record

    def delete_record(self, record_id: str) -> bool:
        """Deletes a record by ID."""
        with self._lock:
            data = self.load_data()
            records_raw = data.get("issue_memory", [])
            initial_len = len(records_raw)
            data["issue_memory"] = [r for r in records_raw if isinstance(r, dict) and r.get("id") != record_id]

            if len(data["issue_memory"]) < initial_len:
                self._atomic_write(data)
                return True
            return False
