"""
Base scanner interfaces, context abstractions, and subprocess runner for Vulnora AI.

Provides `BaseScanner` ABC with safe subprocess execution (`shell=False`),
binary discovery via `shutil.which`, explicit timeout boundaries, and `ScanContext`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from vulnora.core.models import Finding, ScannerResult, ScanStatus, Severity


@dataclass
class ScanContext:
    """
    Execution context passed to each scanner adapter.
    Encapsulates target path, diff-scoped file boundaries, target URLs, and timeouts.
    """
    target_path: Path
    is_full_scan: bool = False
    changed_files: List[Path] = field(default_factory=list)
    target_url: Optional[str] = None
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        self.target_path = Path(self.target_path).resolve()
        self.changed_files = [Path(p).resolve() for p in self.changed_files]

    def get_target_files(self) -> List[Path]:
        """
        Returns relevant target files.
        If diff-scoped and changed_files is non-empty, returns changed_files.
        Otherwise, returns all files within target_path.
        """
        if not self.is_full_scan and self.changed_files:
            return [f for f in self.changed_files if f.is_file()]
        
        # Traverse target_path (skipping hidden git/vulnora directories)
        files: List[Path] = []
        for root, dirs, filenames in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__")]
            for name in filenames:
                files.append(Path(root) / name)
        return files

    def get_files_by_extension(self, extensions: Sequence[str]) -> List[Path]:
        """Filters target files by specific extensions (e.g. ['.py', '.pyi'])."""
        norm_exts = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions}
        candidates = self.get_target_files()
        return [f for f in candidates if f.suffix.lower() in norm_exts]

    def has_extension(self, extensions: Sequence[str]) -> bool:
        """Returns True if any target file possesses one of the specified extensions."""
        return len(self.get_files_by_extension(extensions)) > 0

    def has_matching_filenames(self, filenames: Sequence[str]) -> bool:
        """
        Checks whether any target file matches one of the filenames or glob patterns
        (e.g., ['Dockerfile', 'Cargo.lock', 'package.json']).
        """
        norm_names = {name.lower() for name in filenames}
        candidates = self.get_target_files()
        for f in candidates:
            if f.name.lower() in norm_names:
                return True
            for pattern in norm_names:
                if pattern.startswith("*") and f.name.lower().endswith(pattern[1:]):
                    return True
                if f.name.lower().startswith(pattern.rstrip("*")):
                    return True
        return False

    def get_matching_files(self, filenames: Sequence[str]) -> List[Path]:
        """Returns files matching any of the specified filenames or patterns."""
        norm_names = {name.lower() for name in filenames}
        matches: List[Path] = []
        candidates = self.get_target_files()
        for f in candidates:
            name_lower = f.name.lower()
            if name_lower in norm_names:
                matches.append(f)
            else:
                for pattern in norm_names:
                    if pattern.startswith("*") and name_lower.endswith(pattern[1:]):
                        matches.append(f)
                        break
                    elif pattern.endswith("*") and name_lower.startswith(pattern[:-1]):
                        matches.append(f)
                        break
        return matches


class BaseScanner(ABC):
    """
    Abstract base class for all security scanner adapters.
    Provides safe subprocess execution, binary discovery, auto-gating, and error handling.
    """

    scanner_name: str = "base"
    binary_name: str = ""

    def __init__(self, binary_override: Optional[str] = None):
        self.binary_override = binary_override

    @property
    def executable(self) -> str:
        """Returns the binary name or override to search in PATH."""
        return self.binary_override or self.binary_name

    def is_available(self) -> bool:
        """Checks if the scanner binary is installed and executable in PATH."""
        if not self.executable:
            return False
        return shutil.which(self.executable) is not None

    def should_run(self, context: ScanContext) -> bool:
        """
        Auto-gating rule: Evaluates whether this scanner should run given the context.
        Subclasses override this to restrict execution to relevant files or targets.
        """
        return True

    def run_subprocess(
        self,
        cmd: Sequence[str],
        cwd: Optional[Path] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Safe subprocess runner strictly enforcing:
        - shell=False
        - Sequence[str] arguments (strings/shell interpolation rejected)
        - Explicit timeout
        - Clean stderr/stdout capture
        - Environment isolation
        """
        if not isinstance(cmd, (list, tuple)):
            raise TypeError(f"Command arguments must be a sequence of strings, got {type(cmd).__name__}")

        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        effective_cwd = cwd or Path.cwd()

        return subprocess.run(
            list(cmd),
            shell=False,
            timeout=timeout,
            capture_output=True,
            text=True,
            cwd=effective_cwd,
            env=run_env,
        )

    def get_gated_message(self, context: ScanContext) -> str:
        """Returns descriptive reason why scanner execution was skipped."""
        return f"Gated: No applicable target files or configuration found for {self.scanner_name}."

    def scan(self, context: ScanContext) -> ScannerResult:
        """
        Template method orchestrating binary checks, auto-gating, timeout boundaries,
        and exception capture.
        """
        # 1. Binary availability check
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.NOT_INSTALLED,
                duration_seconds=0.0,
                error_message=f"Scanner binary '{self.executable}' not found in system PATH. Install it to enable {self.scanner_name} scans.",
            )

        # 2. Auto-gating evaluation
        if not self.should_run(context):
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.SKIPPED,
                duration_seconds=0.0,
                error_message=self.get_gated_message(context),
            )

        # 3. Execution with duration tracking and timeout safety
        start_time = time.perf_counter()
        try:
            result = self._execute_scan(context)
            duration = time.perf_counter() - start_time
            result.duration_seconds = duration
            return result
        except subprocess.TimeoutExpired:
            duration = time.perf_counter() - start_time
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.TIMED_OUT,
                duration_seconds=duration,
                error_message=f"Scanner '{self.scanner_name}' timed out after {context.timeout_seconds}s.",
            )
        except Exception as exc:
            duration = time.perf_counter() - start_time
            return ScannerResult(
                scanner_name=self.scanner_name,
                status=ScanStatus.FAILED,
                duration_seconds=duration,
                error_message=f"Scanner execution failed: {exc}",
            )

    @abstractmethod
    def _execute_scan(self, context: ScanContext) -> ScannerResult:
        """Subclass implementation of the scanner execution and output parsing."""
        pass
