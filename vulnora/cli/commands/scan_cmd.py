"""
Implementation of `vulnora scan` command.
Executes local security scanners (Gitleaks, Semgrep, Bandit, OSV-Scanner, Trivy, and OWASP ZAP),
normalizes findings, displays rich terminal output, and optionally exports or syncs results.
"""

import json
from pathlib import Path
import sys
from typing import Any, List, Optional
import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from vulnora.cli.config import load_config
from vulnora.cli.git_utils import get_git_root
from vulnora.cli.ui import console, print_banner, render_split_pane
from vulnora.memory import MatchConfidence, MemoryService
from vulnora.scanners import (
    NormalizedFinding,
    ScannerOrchestrator,
    ScanStatus,
    Severity,
    sync_scan_to_backend,
)


def scan_command(
    project_path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
    zap_target: Optional[str] = typer.Option(
        None,
        "--zap-target",
        "-u",
        help="Target running web application URL for OWASP ZAP DAST scanning (e.g. http://127.0.0.1:8000).",
    ),
    target_url: Optional[str] = typer.Option(
        None,
        "--target-url",
        hidden=True,
        help="Alias for --zap-target.",
    ),
    scanners: Optional[List[str]] = typer.Option(
        None,
        "--scanner",
        "-s",
        help="Specific scanner(s) to execute (gitleaks, semgrep, bandit, osv-scanner, trivy, zap).",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to export normalized scan results as JSON.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print raw JSON findings to standard output.",
    ),
    sync: bool = typer.Option(
        False,
        "--sync",
        help="Attempt synchronization with central Django backend REST API.",
    ),
    timeout: int = typer.Option(
        60,
        "--timeout",
        help="Timeout in seconds per scanner.",
    ),
):
    """
    Execute security scanning across source code, dependencies, containers, and web targets.
    Coordinates Gitleaks, Semgrep, Bandit, OSV-Scanner, Trivy, and OWASP ZAP.
    """
    dast_url = zap_target or target_url
    target_dir = Path(project_path).resolve() if project_path else Path.cwd().resolve()

    orchestrator = ScannerOrchestrator()

    # Path & URL Validation
    try:
        validated_dir = orchestrator.validate_project_path(target_dir) if target_dir else None
    except Exception as exc:
        console.print(f"[bold red]✖ Path Error:[/bold red] [red]{exc}[/red]")
        raise typer.Exit(code=1)

    if dast_url:
        try:
            dast_url = orchestrator.validate_target_url(dast_url)
        except Exception as exc:
            console.print(f"[bold red]✖ Target URL Error:[/bold red] [red]{exc}[/red]")
            raise typer.Exit(code=1)

    # Load configuration
    config = load_config(validated_dir)
    configured_scanners = scanners or config.get("scanners", {}).get("enabled", [
        "gitleaks", "semgrep", "bandit", "osv-scanner", "trivy"
    ])
    if dast_url and "zap" not in configured_scanners:
        configured_scanners.append("zap")

    if not json_output:
        print_banner()

    # Run scanners with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description=f"Running security scanners across {validated_dir.name}...", total=None)
        overall_status, scanner_statuses, unified_findings, duration = orchestrator.run_scan(
            project_path=validated_dir,
            target_url=dast_url,
            scanners_to_run=configured_scanners,
            timeout_seconds=timeout,
        )

        # Memory Lookup: Compare findings against local issue memory (.vulnora/memory.json)
        mem_service = MemoryService(validated_dir)
        memory_matches = mem_service.lookup_findings(unified_findings, update_usage=True)
        match_by_fp = {m.finding_fingerprint: m for m in memory_matches}

    # 1. Output raw JSON if requested
    if json_output:
        result_payload = {
            "status": overall_status,
            "duration_seconds": round(duration, 3),
            "project_path": str(validated_dir) if validated_dir else None,
            "target_url": dast_url,
            "total_findings": len(unified_findings),
            "severity_counts": orchestrator.calculate_severity_counts(unified_findings),
            "scanner_statuses": scanner_statuses,
            "memory_matches_count": sum(1 for m in memory_matches if m.has_match),
            "findings": [
                {
                    **f.to_dict(),
                    "memory_match": match_by_fp[f.fingerprint].to_dict() if f.fingerprint in match_by_fp else None,
                }
                for f in unified_findings
            ],
        }
        print(json.dumps(result_payload, indent=2))
        return

    # 2. Rich Terminal Presentation
    _display_scan_results(
        target_dir=validated_dir,
        dast_url=dast_url,
        duration=duration,
        overall_status=overall_status,
        scanner_statuses=scanner_statuses,
        findings=unified_findings,
        orchestrator=orchestrator,
        memory_matches=memory_matches,
    )

    # 3. Export to JSON file if requested
    if output_file:
        out_path = Path(output_file).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        export_payload = {
            "status": overall_status,
            "duration_seconds": round(duration, 3),
            "project_path": str(validated_dir) if validated_dir else None,
            "target_url": dast_url,
            "total_findings": len(unified_findings),
            "severity_counts": orchestrator.calculate_severity_counts(unified_findings),
            "scanner_statuses": scanner_statuses,
            "memory_matches_count": sum(1 for m in memory_matches if m.has_match),
            "findings": [
                {
                    **f.to_dict(),
                    "memory_match": match_by_fp[f.fingerprint].to_dict() if f.fingerprint in match_by_fp else None,
                }
                for f in unified_findings
            ],
        }
        out_path.write_text(json.dumps(export_payload, indent=2), encoding="utf-8")
        console.print(f"[bold green]✔[/bold green] [white]Exported findings to:[/white] [cyan]{out_path}[/cyan]")

    # 4. Optional Backend Synchronization
    if sync:
        synced, sync_msg = sync_scan_to_backend(
            project_path=validated_dir,
            target_url=dast_url,
            scanners=configured_scanners,
            findings=unified_findings,
            base_path=validated_dir,
        )
        if synced:
            console.print(f"[bold green]✔[/bold green] [dim]{sync_msg}[/dim]")
        else:
            console.print(f"[yellow]ℹ Backend Sync:[/yellow] [dim]{sync_msg}[/dim]")


def _display_scan_results(
    target_dir: Path,
    dast_url: Optional[str],
    duration: float,
    overall_status: str,
    scanner_statuses: dict,
    findings: List[NormalizedFinding],
    orchestrator: ScannerOrchestrator,
    memory_matches: Optional[List[Any]] = None,
):
    """Renders formatted tables, severity breakdowns, and Mascot panel."""
    # Summary of Scanner Executions
    status_table = Table(title="Security Scanner Execution Summary", header_style="bold cyan", border_style="dim")
    status_table.add_column("Scanner", style="bold white", width=14)
    status_table.add_column("Status", width=14)
    status_table.add_column("Duration", justify="right", width=10)
    status_table.add_column("Findings", justify="right", width=10)
    status_table.add_column("Notes / Message", style="dim")

    for name, st in scanner_statuses.items():
        state = st.get("status", "UNKNOWN")
        if state == ScanStatus.COMPLETED:
            styled_state = "[bold green]COMPLETED[/bold green]"
        elif state == ScanStatus.NOT_INSTALLED:
            styled_state = "[yellow]NOT INSTALLED[/yellow]"
        elif state == ScanStatus.TIMED_OUT:
            styled_state = "[bold yellow]TIMED OUT[/bold yellow]"
        else:
            styled_state = "[bold red]FAILED[/bold red]"

        dur = f"{st.get('duration_seconds', 0.0):.2f}s"
        count = str(st.get("findings_count", 0))
        msg = st.get("error_message") or ("No issues detected" if st.get("findings_count", 0) == 0 else "Analysis complete")

        status_table.add_row(name.upper(), styled_state, dur, count, msg)

    console.print(status_table)
    console.print()

    # Severity Breakdown
    sev_counts = orchestrator.calculate_severity_counts(findings)
    sev_table = Table(title="Vulnerabilities by Severity", header_style="bold magenta", border_style="dim")
    sev_table.add_column("CRITICAL", justify="center", style="bold red")
    sev_table.add_column("HIGH", justify="center", style="red")
    sev_table.add_column("MEDIUM", justify="center", style="yellow")
    sev_table.add_column("LOW", justify="center", style="blue")
    sev_table.add_column("INFO", justify="center", style="cyan")
    sev_table.add_column("TOTAL FINDINGS", justify="center", style="bold white")

    sev_table.add_row(
        str(sev_counts[Severity.CRITICAL]),
        str(sev_counts[Severity.HIGH]),
        str(sev_counts[Severity.MEDIUM]),
        str(sev_counts[Severity.LOW]),
        str(sev_counts[Severity.INFO]),
        f"[bold]{sev_counts['total']}[/bold]",
    )
    console.print(sev_table)
    console.print()

    # Detailed Findings List (Top 15 if many)
    match_by_fp = {m.finding_fingerprint: m for m in memory_matches} if memory_matches else {}
    if findings:
        console.print(f"[bold yellow]Identified Vulnerabilities ({min(len(findings), 15)} of {len(findings)} shown):[/bold yellow]")
        for idx, f in enumerate(findings[:15], 1):
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "cyan",
            }.get(f.severity, "white")

            loc = f"{Path(f.file_path).name}:{f.line_number}" if f.line_number else (Path(f.file_path).name if f.file_path else f.target_url)
            console.print(f"  {idx}. [{sev_color}][{f.severity}][/{sev_color}] [bold]{f.title}[/bold] ({f.rule_id})")
            console.print(f"     [dim]Scanner:[/dim] {f.scanner_name.upper()} | [dim]Location:[/dim] {loc}")
            
            # Show local memory hit if available
            mem_hit = match_by_fp.get(f.fingerprint)
            if mem_hit and mem_hit.has_match and mem_hit.record:
                console.print(f"     [bold green]🧠 MEMORY MATCH ({mem_hit.confidence}):[/bold green] [cyan]{mem_hit.record.id}[/cyan] [dim]– Verified fix available[/dim]")
                if mem_hit.record.remediation:
                    console.print(f"     [dim]Verified Fix:[/dim] {mem_hit.record.remediation[:110]}...")
            elif f.remediation:
                console.print(f"     [dim]Remediation:[/dim] {f.remediation[:110]}...")
            console.print()

    # Split-Pane Mascot Summary
    mascot_state = "ready" if len(findings) == 0 else "alert"
    border_color = "green" if len(findings) == 0 else "red"

    total_mem_hits = sum(1 for m in memory_matches if m.has_match) if memory_matches else 0

    log_lines = []
    log_lines.append(f"[bold cyan]Scan Target:[/bold cyan]    [white]{target_dir.name}[/white]")
    if dast_url:
        log_lines.append(f"[bold cyan]DAST URL:[/bold cyan]       [white]{dast_url}[/white]")
    log_lines.append(f"[bold cyan]Scan Status:[/bold cyan]    [bold {border_color}]{overall_status}[/bold {border_color}] (in {duration:.2f}s)")
    log_lines.append(f"[bold cyan]Findings:[/bold cyan]       [white]{len(findings)} unique issues detected[/white]")
    if total_mem_hits > 0:
        log_lines.append(f"[bold cyan]Memory Matches:[/bold cyan] [bold green]{total_mem_hits} verified solutions available[/bold green]")
    log_lines.append("")

    if len(findings) == 0:
        log_lines.append("[bold green]✔ CLEAN CODEBASE[/bold green]")
        log_lines.append("[dim]Zero security vulnerabilities or hardcoded secrets detected.[/dim]")
    else:
        log_lines.append(f"[bold red]⚠ SECURITY POSTURE ALERT[/bold red]")
        log_lines.append(f"[white]Critical: {sev_counts['CRITICAL']} | High: {sev_counts['HIGH']} | Medium: {sev_counts['MEDIUM']}[/white]")
        log_lines.append("[dim]Review the findings above or export with '--output results.json'.[/dim]")

    layout = render_split_pane(
        mascot_state=mascot_state,
        log_title="Vulnora Security Posture Summary",
        log_lines=log_lines,
        mascot_subtitle="Status: " + ("CLEAN" if len(findings) == 0 else "ACTION REQUIRED"),
        border_style=border_color,
    )
    console.print(layout)
