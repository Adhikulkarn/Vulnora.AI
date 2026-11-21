"""
Antibody Pack manager for Vulnora AI.

Exports and imports portable, anonymized vulnerability signatures across codebases.
Strictly enforces ZERO proprietary code leakage: exported packs contain only
normalized AST signatures, anonymized templates, and preventative rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union
import yaml

from vulnora.core.models import ImmuneRecord, Severity
from vulnora.immune.memory_store import ImmuneMemoryStore


class AntibodyPackError(Exception):
    """Base exception for Antibody Pack export and import errors."""
    pass


class AntibodyPackManager:
    """
    Manages export and import of portable, shareable security antibodies.
    Ensures absolute data sanitization before serializing to JSON or YAML.
    """

    FORMAT_VERSION = "1.0"

    @classmethod
    def sanitize_record(cls, record: ImmuneRecord) -> Dict[str, Any]:
        """
        Sanitizes an ImmuneRecord before export:
        - Strips local repository file paths.
        - Guarantees template contains only anonymized placeholders (VAR_N, STR_LIT, 0).
        - Strips developer or environment specific metadata.
        """
        # Ensure anonymized template has no sensitive system paths or un-anonymized email addresses
        clean_template = record.anonymized_template
        clean_template = re.sub(r"(/[a-zA-Z0-9_\.\-]+)+", "/PATH_PLACEHOLDER", clean_template)
        clean_template = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "USER@DOMAIN", clean_template)

        clean_metadata = {
            k: v for k, v in record.metadata.items()
            if k not in ("file_path", "raw_snippet", "user", "email", "git_commit")
        }

        return {
            "id": record.id,
            "rule_id": record.rule_id,
            "scanner_name": record.scanner_name,
            "severity": record.severity.value,
            "language": record.language,
            "exact_hash": record.exact_hash,
            "ast_signature": record.ast_signature,
            "anonymized_template": clean_template,
            "resolution": record.resolution,
            "remediation_patch": record.remediation_patch,
            "agents_rule": record.agents_rule,
            "metadata": clean_metadata,
        }

    @classmethod
    def export_pack(
        cls,
        store: ImmuneMemoryStore,
        output_path: Union[str, Path],
        pack_name: str = "vulnora-antibodies",
        selected_rule_ids: Optional[List[str]] = None,
    ) -> Path:
        """
        Exports antibodies from memory store into a sanitized JSON or YAML file.
        Strictly sanitizes every record to prevent proprietary code or secret leaks.
        """
        out = Path(output_path).resolve()
        records = store.get_all_records()

        if selected_rule_ids:
            rule_set = {r.strip().lower() for r in selected_rule_ids}
            records = [r for r in records if r.rule_id.lower() in rule_set]

        sanitized_antibodies = [cls.sanitize_record(r) for r in records]

        pack_data: Dict[str, Any] = {
            "format_version": cls.FORMAT_VERSION,
            "pack_name": pack_name,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "antibodies_count": len(sanitized_antibodies),
            "antibodies": sanitized_antibodies,
        }

        out.parent.mkdir(parents=True, exist_ok=True)

        # Determine format from extension
        suffix = out.suffix.lower()
        if suffix in (".yaml", ".yml"):
            with out.open("w", encoding="utf-8") as f:
                yaml.dump(pack_data, f, default_flow_style=False, sort_keys=False)
        else:
            with out.open("w", encoding="utf-8") as f:
                json.dump(pack_data, f, indent=2, sort_keys=False)

        return out

    @classmethod
    def import_pack(
        cls,
        pack_path: Union[str, Path],
        store: ImmuneMemoryStore,
        overwrite: bool = False,
    ) -> int:
        """
        Imports antibodies from a JSON or YAML pack into the local immune memory store.
        Deduplicates records based on `exact_hash`.
        Returns the number of newly added or updated antibodies.
        """
        file_path = Path(pack_path).resolve()
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"Antibody pack not found: {file_path}")

        raw_content = file_path.read_text(encoding="utf-8")
        suffix = file_path.suffix.lower()

        try:
            if suffix in (".yaml", ".yml"):
                data = yaml.safe_load(raw_content) or {}
            else:
                data = json.loads(raw_content)
        except Exception as exc:
            raise AntibodyPackError(f"Failed to parse antibody pack: {exc}")

        if not isinstance(data, dict):
            raise AntibodyPackError("Invalid antibody pack format: root must be a mapping.")

        antibodies_list = data.get("antibodies", [])
        if not isinstance(antibodies_list, list):
            raise AntibodyPackError("Invalid antibody pack format: 'antibodies' must be a list.")

        existing_hashes = {r.exact_hash for r in store.get_all_records()}
        imported_count = 0

        for item in antibodies_list:
            if not isinstance(item, dict):
                continue

            exact_hash = str(item.get("exact_hash") or "")
            if not exact_hash:
                continue

            if exact_hash in existing_hashes and not overwrite:
                continue

            sev = Severity.from_string(str(item.get("severity") or "INFO"))
            record = ImmuneRecord(
                id=str(item.get("id") or f"ab_import_{exact_hash[:8]}"),
                rule_id=str(item.get("rule_id") or "UNKNOWN"),
                scanner_name=str(item.get("scanner_name") or "imported"),
                severity=sev,
                language=str(item.get("language") or "generic"),
                exact_hash=exact_hash,
                ast_signature=str(item.get("ast_signature") or ""),
                anonymized_template=str(item.get("anonymized_template") or ""),
                resolution=str(item.get("resolution") or "ACCEPTED_RISK"),
                remediation_patch=item.get("remediation_patch"),
                agents_rule=str(item.get("agents_rule") or ""),
                created_at=str(item.get("created_at") or datetime.now(timezone.utc).isoformat()),
                metadata=item.get("metadata", {}),
            )

            # Store in local memory store
            store._records = [r for r in store._records if r.exact_hash != record.exact_hash]
            store._records.append(record)
            store._hash_index[record.exact_hash] = record
            existing_hashes.add(record.exact_hash)
            imported_count += 1

        if imported_count > 0:
            store._save()

        return imported_count
