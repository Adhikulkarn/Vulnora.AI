"""
Implementation of `vulnora scan` command.
Prepares the scanner execution interface and displays modular scan pipeline status.
"""

from pathlib import Path
from typing import List, Optional
import typer

from ..config import load_config
from ..ui import console, print_banner, render_split_pane


def scan_command(
    project_path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
    target_url: Optional[str] = typer.Option(
        None,
        "--target-url",
        "-u",
        help="Target web application URL for dynamic security testing (DAST).",
    ),
    scanners: Optional[List[str]] = typer.Option(
        None,
        "--scanner",
        "-s",
        help="Individual scanners to run (defaults to all enabled in config).",
    ),
):
    """
    Execute security scanning across source code, dependencies, containers, and web targets.
    Displays the split-pane Sentinel mascot and modular scanner status log.
    """
    target = Path(project_path).resolve() if project_path else Path.cwd().resolve()
    print_banner()

    config = load_config(target)
    configured_scanners = scanners or config.get("scanners", {}).get("enabled", [
        "gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"
    ])

    log_lines = []
    log_lines.append(f"[bold cyan]Scanning Target:[/bold cyan] [white]{target}[/white]")
    if target_url:
        log_lines.append(f"[bold cyan]Target Web URL:[/bold cyan]  [white]{target_url}[/white]")

    log_lines.append(f"[dim]Timeout:[/dim] [cyan]{config.get('scanners', {}).get('timeout_seconds', 60)}s[/cyan]")
    log_lines.append("")
    log_lines.append("[bold yellow]Modular Scanner Pipeline:[/bold yellow]")

    for s in configured_scanners:
        log_lines.append(f"  [cyan]•[/cyan] [white]{s.upper():<14}[/white] [dim]───>[/dim] [yellow]READY / QUEUED[/yellow]")

    log_lines.append("")
    log_lines.append("[bold green]✔ CLI Scanner Foundation Initialized[/bold green]")
    log_lines.append("[dim]Orchestrator integration hooks ready for security engine execution.[/dim]")
    log_lines.append("[dim]Use 'vulnora guard' to verify branch protection status.[/dim]")

    layout = render_split_pane(
        mascot_state="scanning",
        log_title="Vulnora Multi-Scanner Execution",
        log_lines=log_lines,
        mascot_subtitle="Scanner Module: Active",
        border_style="yellow",
    )
    console.print(layout)
