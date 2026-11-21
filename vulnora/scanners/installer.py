"""
Cross-platform binary bootstrapper and scanner installer for Vulnora AI.

Manages automatic discovery and standalone installation of security scanners:
- Bundled Python tools (bandit, semgrep)
- Standalone binaries (gitleaks, osv-scanner, trivy) into ~/.vulnora/bin/
- Optional DAST scanner (OWASP ZAP)

Features:
- Auto-detects OS (Linux, Darwin, Windows) and CPU architecture (amd64, arm64).
- Safe archive extraction preventing path traversal.
- 0o755 execution permissions on Unix.
- Streams live progress via optional on_log callback.
- Graceful offline/network failure handling (never crashes on network drop).
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import zipfile

# Pinned stable release versions for standalone scanner binaries
GITLEAKS_VERSION = "8.21.2"
OSV_SCANNER_VERSION = "1.9.2"
TRIVY_VERSION = "0.58.2"

STATIC_SCANNERS: List[str] = ["bandit", "semgrep", "gitleaks", "osv-scanner", "trivy"]
STANDALONE_SCANNERS: List[str] = ["gitleaks", "osv-scanner", "trivy"]


def get_vulnora_bin_dir() -> Path:
    """
    Returns the resolved directory path where standalone scanner binaries are placed.
    Defaults to ~/.vulnora/bin/ and respects the VULNORA_BIN_DIR environment override.
    Falls back to .vulnora/bin/ in cwd if the user home directory is read-only.
    """
    override = os.environ.get("VULNORA_BIN_DIR")
    if override and override.strip():
        return Path(override).expanduser().resolve()

    home_bin = (Path.home() / ".vulnora" / "bin").resolve()
    try:
        # Check if writable or create directory
        home_bin.mkdir(parents=True, exist_ok=True)
        return home_bin
    except OSError:
        # Fall back to local .vulnora/bin in current workspace if home is read-only
        local_bin = (Path.cwd() / ".vulnora" / "bin").resolve()
        try:
            local_bin.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        return local_bin


def get_extended_path() -> str:
    """
    Returns the system PATH prepended with ~/.vulnora/bin/ and the active
    Python environment's bin/ directory.
    """
    vulnora_bin = str(get_vulnora_bin_dir())
    py_bin = str(Path(sys.executable).parent.resolve())
    current_path = os.environ.get("PATH", "")
    parts = [p for p in current_path.split(os.pathsep) if p]
    prepend: List[str] = []
    if vulnora_bin not in parts:
        prepend.append(vulnora_bin)
    if py_bin not in parts:
        prepend.append(py_bin)
    return os.pathsep.join(prepend + parts) if prepend else current_path


def detect_platform() -> Tuple[str, str]:
    """
    Auto-detects the host OS ('linux', 'darwin', 'windows') and CPU architecture ('amd64', 'arm64').
    """
    os_name = sys.platform.lower()
    if os_name.startswith("linux"):
        system = "linux"
    elif os_name == "darwin":
        system = "darwin"
    elif os_name in ("win32", "cygwin", "msys") or platform.system().lower() == "windows":
        system = "windows"
    else:
        system = "linux"

    arch_raw = platform.machine().lower()
    if arch_raw in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    elif arch_raw in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = "amd64"

    return system, arch


def is_binary_installed(binary_name: str) -> bool:
    """
    Checks whether a scanner binary is present in system PATH, the active Python bin/,
    or ~/.vulnora/bin/.
    """
    ext_path = get_extended_path()
    exe_name = f"{binary_name}.exe" if sys.platform == "win32" and not binary_name.endswith(".exe") else binary_name

    if shutil.which(exe_name, path=ext_path) or shutil.which(binary_name, path=ext_path):
        return True

    bin_dir = get_vulnora_bin_dir()
    if (bin_dir / exe_name).is_file() or (bin_dir / binary_name).is_file():
        return True

    return False


def get_missing_scanners() -> List[str]:
    """
    Returns list of all required static scanners (Python + standalone) currently missing.
    OWASP ZAP is strictly excluded as it is optional DAST.
    """
    return [s for s in STATIC_SCANNERS if not is_binary_installed(s)]


def get_missing_standalone_scanners() -> List[str]:
    """
    Returns list of missing standalone binary scanners (gitleaks, osv-scanner, trivy).
    """
    return [s for s in STANDALONE_SCANNERS if not is_binary_installed(s)]


def _resolve_download_url(name: str, system: str, arch: str) -> Optional[Tuple[str, str]]:
    """
    Resolves the official GitHub Release asset URL and archive/binary format for a scanner.
    Returns (url, file_format) where file_format is 'tar.gz', 'zip', or 'binary'.
    """
    if name == "gitleaks":
        arch_str = "x64" if arch == "amd64" else "arm64"
        ext = "zip" if system == "windows" else "tar.gz"
        asset = f"gitleaks_{GITLEAKS_VERSION}_{system}_{arch_str}.{ext}"
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{asset}"
        return url, ext

    elif name == "osv-scanner":
        exe_ext = ".exe" if system == "windows" else ""
        asset = f"osv-scanner_{system}_{arch}{exe_ext}"
        url = f"https://github.com/google/osv-scanner/releases/download/v{OSV_SCANNER_VERSION}/{asset}"
        return url, "binary"

    elif name == "trivy":
        os_str = "Linux" if system == "linux" else ("macOS" if system == "darwin" else "Windows")
        arch_str = "64bit" if arch == "amd64" else "ARM64"
        ext = "zip" if system == "windows" else "tar.gz"
        asset = f"trivy_{TRIVY_VERSION}_{os_str}-{arch_str}.{ext}"
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{asset}"
        return url, ext

    return None


def _download_url(url: str, dest_path: Path, timeout: int = 30) -> None:
    """Downloads a remote file with a standard User-Agent header."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Vulnora-AI/0.1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        with open(dest_path, "wb") as f:
            shutil.copyfileobj(resp, f)


def _safe_extract_tar_binary(tar_path: Path, dest_dir: Path, binary_name: str) -> Optional[Path]:
    """
    Safely extracts only the target executable from a tar.gz archive, preventing path traversal.
    """
    dest_dir = dest_dir.resolve()
    dest_file = dest_dir / (f"{binary_name}.exe" if sys.platform == "win32" else binary_name)

    with tarfile.open(tar_path, "r:*") as tar:
        for member in tar.getmembers():
            normalized_name = Path(member.name).name
            if normalized_name in (binary_name, f"{binary_name}.exe"):
                extracted_f = tar.extractfile(member)
                if extracted_f:
                    with open(dest_file, "wb") as out:
                        shutil.copyfileobj(extracted_f, out)
                    if os.name != "nt":
                        dest_file.chmod(0o755)
                    return dest_file
    return None


def _safe_extract_zip_binary(zip_path: Path, dest_dir: Path, binary_name: str) -> Optional[Path]:
    """
    Safely extracts only the target executable from a zip archive, preventing path traversal.
    """
    dest_dir = dest_dir.resolve()
    dest_file = dest_dir / (f"{binary_name}.exe" if sys.platform == "win32" else binary_name)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            normalized_name = Path(info.filename).name
            if normalized_name in (binary_name, f"{binary_name}.exe"):
                with zf.open(info) as src, open(dest_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                if os.name != "nt":
                    dest_file.chmod(0o755)
                return dest_file
    return None


def install_scanner(
    name: str,
    on_log: Optional[Callable[[str], None]] = None,
    force: bool = False,
) -> bool:
    """
    Downloads and installs a standalone scanner binary into ~/.vulnora/bin/.
    Skips if already present in system PATH or bin dir (unless force=True).
    Handles network errors gracefully.
    """
    name_clean = name.strip().lower()

    if not force and is_binary_installed(name_clean):
        if on_log:
            on_log(f"Scanner '{name_clean}' is already available. Skipping download.")
        return True

    if name_clean in ("bandit", "semgrep"):
        if on_log:
            on_log(f"Python scanner '{name_clean}' must be installed via pip (bundled in pyproject.toml).")
        return is_binary_installed(name_clean)

    if name_clean not in STANDALONE_SCANNERS:
        if on_log:
            on_log(f"Scanner '{name_clean}' is not a recognized standalone binary.")
        return False

    system, arch = detect_platform()
    resolved = _resolve_download_url(name_clean, system, arch)
    if not resolved:
        if on_log:
            on_log(f"[!] Warning: No download target available for {name_clean} on {system}/{arch}.")
        return False

    url, fmt = resolved

    try:
        bin_dir = get_vulnora_bin_dir()
        try:
            bin_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            bin_dir = (Path.cwd() / ".vulnora" / "bin").resolve()
            bin_dir.mkdir(parents=True, exist_ok=True)

        target_exe = bin_dir / (f"{name_clean}.exe" if system == "windows" else name_clean)

        if on_log:
            on_log(f"[*] Downloading {name_clean} for {system}/{arch} from GitHub Releases...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_download = Path(tmp_dir) / f"{name_clean}_dl"
            _download_url(url, tmp_download)

            if fmt == "binary":
                shutil.copyfile(tmp_download, target_exe)
                if os.name != "nt":
                    target_exe.chmod(0o755)
            elif fmt == "tar.gz":
                extracted = _safe_extract_tar_binary(tmp_download, bin_dir, name_clean)
                if not extracted or not target_exe.is_file():
                    raise RuntimeError(f"Could not find {name_clean} executable inside archive.")
            elif fmt == "zip":
                extracted = _safe_extract_zip_binary(tmp_download, bin_dir, name_clean)
                if not extracted or not target_exe.is_file():
                    raise RuntimeError(f"Could not find {name_clean} executable inside archive.")

        if on_log:
            on_log(f"[✔] Successfully installed {name_clean} to {target_exe}")
        return True

    except Exception as exc:
        msg = f"[!] Warning: Failed to download {name_clean} ({exc}). Continuing without crashing."
        if on_log:
            on_log(msg)
        return False


def install_missing_scanners(
    on_log: Optional[Callable[[str], None]] = None,
    force: bool = False,
) -> Dict[str, bool]:
    """
    Installs any missing standalone scanner binaries into ~/.vulnora/bin/.
    Checks Python scanners (bandit, semgrep) and logs informational status.
    Returns dictionary mapping scanner names to installation success.
    """
    results: Dict[str, bool] = {}

    # 1. Inform regarding Python scanners
    for py_tool in ("bandit", "semgrep"):
        present = is_binary_installed(py_tool)
        results[py_tool] = present
        if not present and on_log:
            on_log(f"[*] Notice: Python scanner '{py_tool}' not found in PATH or environment.")

    # 2. Bootstrap standalone binaries
    for standalone in STANDALONE_SCANNERS:
        if force or not is_binary_installed(standalone):
            success = install_scanner(standalone, on_log=on_log, force=force)
            results[standalone] = success
        else:
            results[standalone] = True
            if on_log:
                on_log(f"[✔] Scanner '{standalone}' is already installed.")

    return results


def verify_all_scanners() -> Dict[str, Dict[str, Any]]:
    """
    Returns diagnostic verification status for all security scanners.
    """
    scanners = {
        "bandit": {"type": "Python SAST", "required": True},
        "semgrep": {"type": "Multi-language SAST", "required": True},
        "gitleaks": {"type": "Secret Scanner", "required": True},
        "osv-scanner": {"type": "SCA Dependency Scanner", "required": True},
        "trivy": {"type": "IaC & Container Scanner", "required": True},
        "zap": {"type": "DAST Web Scanner (Optional)", "required": False, "binary": "zap-baseline.py"},
    }

    statuses: Dict[str, Dict[str, Any]] = {}
    ext_path = get_extended_path()
    bin_dir = get_vulnora_bin_dir()

    for name, info in scanners.items():
        binary_to_check = info.get("binary", name)
        installed = is_binary_installed(binary_to_check)
        resolved_path = shutil.which(binary_to_check, path=ext_path)

        if not resolved_path:
            candidate = bin_dir / (f"{binary_to_check}.exe" if sys.platform == "win32" else binary_to_check)
            if candidate.is_file():
                resolved_path = str(candidate)

        statuses[name] = {
            "name": name,
            "type": info["type"],
            "required": info["required"],
            "installed": installed,
            "path": resolved_path,
        }

    return statuses
