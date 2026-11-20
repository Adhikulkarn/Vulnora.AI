"""
Optional synchronization utility with the Vulnora Django Backend REST API.
Synchronizes local CLI scan results to the central server when online,
and fails gracefully with local-only storage when the backend is offline.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests

from .data_structures import NormalizedFinding

logger = logging.getLogger(__name__)


def is_backend_available(backend_url: str, timeout_seconds: float = 1.0) -> bool:
    """Checks if the Django backend is reachable via health probe."""
    try:
        health_endpoint = f"{backend_url.rstrip('/')}/api/v1/health/"
        res = requests.get(health_endpoint, timeout=timeout_seconds)
        return res.status_code == 200
    except Exception:
        return False


def sync_scan_to_backend(
    project_path: Optional[Path],
    target_url: Optional[str],
    scanners: List[str],
    findings: List[NormalizedFinding],
    base_path: Optional[Path] = None,
) -> Tuple[bool, str]:
    """
    Attempts to trigger / record scan with the central Django backend REST API.
    Returns:
        (success: bool, status_message: str)
    """
    from vulnora.cli.config import load_config

    config = load_config(base_path)
    backend_cfg = config.get("backend", {})
    if not backend_cfg.get("sync_history", True):
        return False, "Backend sync disabled in configuration."

    backend_url = backend_cfg.get("url", "http://127.0.0.1:8000").rstrip("/")

    if not is_backend_available(backend_url):
        return False, f"Backend at {backend_url} is offline. Findings saved locally only."

    try:
        scan_endpoint = f"{backend_url}/api/v1/scans/"
        payload = {
            "project_path": str(project_path) if project_path else None,
            "target_url": target_url,
            "scanners": scanners,
        }
        res = requests.post(scan_endpoint, json=payload, timeout=10.0)
        if res.status_code in (200, 201):
            scan_id = res.json().get("id", "registered")
            return True, f"Successfully synchronized scan session ({scan_id}) to backend."
        else:
            return False, f"Backend returned status {res.status_code} during sync."
    except Exception as exc:
        logger.debug(f"Backend sync failed: {exc}")
        return False, f"Backend synchronization error: {exc}"

