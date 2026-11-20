import logging
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Optional

from .data_structures import NormalizedFinding, ScannerExecutionResult

logger = logging.getLogger(__name__)


class BaseScannerService(ABC):
    """
    Abstract base service providing safe subprocess execution, binary discovery,
    timeout handling, and finding normalization for a specific security scanner.
    """

    name: str = "base"
    executable_name: str = ""

    def __init__(self, custom_executable_path: Optional[str] = None):
        self.custom_executable_path = custom_executable_path
        self._cached_executable: Optional[str] = None

    def find_executable(self) -> Optional[str]:
        """
        Locates the scanner binary across virtual environments, package managers, and PATH.
        """
        if self.custom_executable_path and Path(self.custom_executable_path).exists():
            return self.custom_executable_path

        if self._cached_executable and Path(self._cached_executable).exists():
            return self._cached_executable

        candidates: List[Path] = []

        # 1. Virtual Environment Scripts / bin directory
        venv_scripts = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
        candidates.append(venv_scripts / self.executable_name)
        if os.name == "nt":
            candidates.append(venv_scripts / f"{self.executable_name}.exe")

        # 2. Windows WinGet Links directory
        if os.name == "nt":
            local_appdata = os.getenv("LOCALAPPDATA")
            if local_appdata:
                winget_links = Path(local_appdata) / "Microsoft" / "WinGet" / "Links"
                candidates.append(winget_links / f"{self.executable_name}.exe")
                candidates.append(winget_links / self.executable_name)

        # Check explicit candidate paths
        for cand in candidates:
            if cand.is_file():
                self._cached_executable = str(cand)
                return self._cached_executable

        # 3. System PATH lookup
        found = shutil.which(self.executable_name)
        if found:
            self._cached_executable = found
            return self._cached_executable

        return None

    def is_available(self) -> bool:
        """Returns True if the scanner binary is installed and executable."""
        return self.find_executable() is not None

    def get_version(self) -> Optional[str]:
        """Returns the version string of the installed scanner binary."""
        exe = self.find_executable()
        if not exe:
            return None
        try:
            res = self._run_subprocess([exe, "--version"], timeout_seconds=10)
            if res.returncode == 0:
                return res.stdout.strip().splitlines()[0]
        except Exception:
            pass
        return None

    def _run_subprocess(
        self,
        args: List[str],
        timeout_seconds: int = 60,
        cwd: Optional[Path] = None,
    ) -> subprocess.CompletedProcess:
        """
        Safely executes a scanner subprocess.
        Enforces subprocess argument lists, never shell=True.
        """
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        logger.info(f"Executing scanner command: {args[:4]}... (timeout: {timeout_seconds}s)")
        return subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,  # Enforce strict argument list safety
            creationflags=creationflags,
        )

    def to_relative_path(self, file_path_str: str, project_root: Path) -> str:
        """Converts an absolute file path to a project-relative path."""
        try:
            p = Path(file_path_str)
            if p.is_absolute():
                return str(p.relative_to(project_root)).replace("\\", "/")
            return file_path_str.replace("\\", "/")
        except Exception:
            return file_path_str.replace("\\", "/")

    @abstractmethod
    def scan(self, project_path: Path, timeout_seconds: int = 60) -> ScannerExecutionResult:
        """Executes the scanner against project_path and returns normalized results."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw_data: Any, project_path: Path) -> List[NormalizedFinding]:
        """Normalizes scanner-specific output into standard NormalizedFinding objects."""
        raise NotImplementedError

