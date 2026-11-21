"""
Concurrent multi-scanner detection orchestrator for Vulnora AI.

Runs configured security scanner adapters in parallel using ThreadPoolExecutor,
evaluates auto-gating rules, handles missing binaries and timeouts gracefully,
and normalizes & deduplicates findings into an `OrchestratorResult`.
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
import time
from typing import Callable, Dict, List, Optional, Sequence, Type

from vulnora.core.config import VulnoraConfig, load_config
from vulnora.core.models import Finding, OrchestratorResult, ScannerResult, ScanStatus
from vulnora.scanners.bandit import BanditScanner
from vulnora.scanners.base import BaseScanner, ScanContext
from vulnora.scanners.gitleaks import GitleaksScanner
from vulnora.scanners.osv_scanner import OSVScanner
from vulnora.scanners.semgrep import SemgrepScanner
from vulnora.scanners.trivy import TrivyScanner
from vulnora.scanners.zap import ZAPScanner

# Default registry mapping scanner names to adapter classes
SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
    "gitleaks": GitleaksScanner,
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "osv-scanner": OSVScanner,
    "trivy": TrivyScanner,
    "zap": ZAPScanner,
}


class ScannerOrchestrator:
    """
    Orchestrates concurrent multi-scanner detection across source code,
    dependencies, container configs, and live DAST targets.
    """

    def __init__(
        self,
        config: Optional[VulnoraConfig] = None,
        custom_scanners: Optional[Dict[str, BaseScanner]] = None,
        max_workers: int = 6,
    ):
        self.config = config or load_config()
        self.max_workers = max_workers
        self.scanners: Dict[str, BaseScanner] = {}

        if custom_scanners:
            self.scanners.update(custom_scanners)
        else:
            # Instantiate scanners based on registry
            for name, cls in SCANNER_REGISTRY.items():
                self.scanners[name] = cls()

    def get_enabled_scanners(self, requested: Optional[Sequence[str]] = None) -> List[BaseScanner]:
        """
        Determines which scanners to execute.
        If `requested` is provided, filters strictly to those.
        Otherwise, consults `self.config.scanners.enabled`.
        """
        if requested:
            selected_names = [s.strip().lower() for s in requested if s.strip()]
        else:
            selected_names = [s.strip().lower() for s in self.config.scanners.enabled]

        active: List[BaseScanner] = []
        for name in selected_names:
            if name in self.scanners:
                active.append(self.scanners[name])
        return active

    def run_scanners(
        self,
        target_path: Optional[Path] = None,
        is_full_scan: bool = False,
        changed_files: Optional[List[Path]] = None,
        target_url: Optional[str] = None,
        requested_scanners: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[int] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> OrchestratorResult:
        """
        Executes all active scanners concurrently within a ThreadPoolExecutor.
        Aggregates outputs, tolerates individual scanner failures or missing tools,
        and deduplicates findings.
        """
        path = Path(target_path or Path.cwd()).resolve()
        timeout = timeout_seconds or self.config.scanners.timeout_seconds

        context = ScanContext(
            target_path=path,
            is_full_scan=is_full_scan,
            changed_files=changed_files or [],
            target_url=target_url,
            timeout_seconds=timeout,
        )

        active_scanners = self.get_enabled_scanners(requested=requested_scanners)
        if not active_scanners:
            if on_log:
                on_log("[dim][SCAN][/dim] No active scanners configured or enabled. Scan complete.")
            return OrchestratorResult(
                target_path=str(path),
                duration_seconds=0.0,
                target_url=target_url,
                is_full_scan=is_full_scan,
            )

        target_files = context.get_target_files()
        if on_log:
            mode_desc = "full repository scan" if is_full_scan else f"diff-scoped ({len(changed_files or [])} changed file(s))"
            on_log(f"[bold cyan][SCAN][/bold cyan] Starting detection pipeline on [bold]{path.name}[/bold] ({mode_desc}).")
            on_log(f"[cyan][SCAN][/cyan] Targeted {len(target_files)} eligible file(s) across {len(active_scanners)} scanner(s).")

        start_time = time.perf_counter()
        results: List[ScannerResult] = []

        def _execute_scanner(scanner: BaseScanner) -> ScannerResult:
            if on_log:
                on_log(f"[bold yellow][START][/bold yellow] Scanner [bold]{scanner.scanner_name}[/bold] executing...")
            res = scanner.scan(context)
            if on_log:
                if res.status == ScanStatus.COMPLETED:
                    on_log(
                        f"[bold green][DONE][/bold green] Scanner [bold]{res.scanner_name}[/bold] finished in "
                        f"{res.duration_seconds:.2f}s ({len(res.findings)} finding(s))."
                    )
                elif res.status in (ScanStatus.SKIPPED, ScanStatus.NOT_INSTALLED):
                    on_log(
                        f"[dim][SKIP][/dim] Scanner [bold]{res.scanner_name}[/bold] skipped: "
                        f"{res.error_message or res.status.value}"
                    )
                else:
                    on_log(
                        f"[bold red][ERROR][/bold red] Scanner [bold]{res.scanner_name}[/bold] "
                        f"{res.status.value}: {res.error_message or 'Failure'}"
                    )
            return res

        # Execute scanners concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(active_scanners), self.max_workers)) as executor:
            future_to_scanner = {
                executor.submit(_execute_scanner, scanner): scanner
                for scanner in active_scanners
            }

            for future in concurrent.futures.as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    res = future.result()
                    results.append(res)
                except Exception as exc:
                    if on_log:
                        on_log(f"[bold red][ERROR][/bold red] Scanner [bold]{scanner.scanner_name}[/bold] worker exception: {exc}")
                    # Defensive fallback: worker crash should never crash orchestrator
                    results.append(
                        ScannerResult(
                            scanner_name=scanner.scanner_name,
                            status=ScanStatus.FAILED,
                            duration_seconds=0.0,
                            error_message=f"Orchestrator worker exception: {exc}",
                        )
                    )

        total_duration = time.perf_counter() - start_time

        # Categorize scanners
        scanners_run: List[str] = []
        scanners_skipped: List[str] = []
        scanners_failed: List[str] = []

        for r in results:
            if r.status == ScanStatus.COMPLETED:
                scanners_run.append(r.scanner_name)
            elif r.status in (ScanStatus.SKIPPED, ScanStatus.NOT_INSTALLED):
                scanners_skipped.append(r.scanner_name)
            else:
                scanners_failed.append(r.scanner_name)

        # Deduplicate findings across overlapping scanners
        deduplicated_findings = self._deduplicate_findings(results)

        if on_log:
            on_log(
                f"[bold cyan][DEDUP][/bold cyan] Deduplication complete: {len(deduplicated_findings)} unique finding(s) "
                f"retained across {len(scanners_run)} completed scanner(s) ({total_duration:.2f}s total)."
            )

        return OrchestratorResult(
            target_path=str(path),
            duration_seconds=total_duration,
            scanner_results=results,
            findings=deduplicated_findings,
            scanners_run=sorted(scanners_run),
            scanners_skipped=sorted(scanners_skipped),
            scanners_failed=sorted(scanners_failed),
            target_url=target_url,
            is_full_scan=is_full_scan,
        )

    def _deduplicate_findings(self, results: List[ScannerResult]) -> List[Finding]:
        """
        Deduplicates security findings using deterministic SHA-256 fingerprints.
        If multiple scanners detect the same vulnerability, the earliest is retained.
        """
        seen_fingerprints: set[str] = set()
        deduped: List[Finding] = []

        for r in results:
            for finding in r.findings:
                fp = finding.fingerprint or finding.compute_fingerprint()
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    deduped.append(finding)

        # Sort findings by severity (CRITICAL first)
        deduped.sort(key=lambda f: f.severity.rank, reverse=True)
        return deduped
