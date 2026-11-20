"""
Implementation of `vulnora guard` command.
Performs branch-aware protection checks and displays the Sentinel guard interface.
"""

from pathlib import Path
from typing import Optional
import typer

from ..config import get_protected_branches, load_config
from ..git_utils import get_current_branch, get_git_root, is_git_repository, is_protected_branch
from ..ui import console, print_banner, render_split_pane


def guard_command(
    project_path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
    branch_override: Optional[str] = typer.Option(
        None,
        "--branch",
        "-b",
        help="Explicitly evaluate a specific branch name rather than detecting HEAD.",
    ),
):
    """
    Check branch-aware security guard status and enforcement policy.
    Detects if the current Git branch is protected (e.g. main, production).
    """
    target = Path(project_path).resolve() if project_path else Path.cwd().resolve()
    print_banner()

    log_lines = []
    log_lines.append(f"[bold cyan]Target Repository:[/bold cyan] [white]{target}[/white]")

    # Check Git Repository
    is_git = is_git_repository(target)
    if not is_git and not branch_override:
        log_lines.append("[bold red]✖ Error:[/bold red] [red]Target directory is not a Git repository.[/red]")
        log_lines.append("[dim]Please initialize git ('git init') or pass --branch to evaluate policy.[/dim]")
        layout = render_split_pane(
            mascot_state="alert",
            log_title="Branch Guard - Error",
            log_lines=log_lines,
            mascot_subtitle="Repository Missing",
            border_style="red",
        )
        console.print(layout)
        raise typer.Exit(code=1)

    if not is_git and branch_override:
        log_lines.append("[yellow]ℹ Non-Git Directory:[/yellow] [dim]Evaluating policy using provided --branch override[/dim]")

    # Resolve Branch
    current_branch = branch_override or get_current_branch(target)
    if not current_branch:
        current_branch = "unknown"

    # Load Configuration & Protected Branches
    config = load_config(target)
    protected_branches = get_protected_branches(target)
    protected = is_protected_branch(current_branch, protected_branches)

    log_lines.append(f"[bold]Active Branch:[/bold] [bold yellow]{current_branch}[/bold yellow]")
    log_lines.append(f"[dim]Protected Branches:[/dim] [cyan]{', '.join(protected_branches)}[/cyan]")
    log_lines.append("")

    if protected:
        mascot_state = "alert"
        border_color = "red"
        log_lines.append("[bold red]⚠ HIGH-SECURITY GUARD ACTIVE[/bold red]")
        log_lines.append(f"[red]Direct push or merge targeting protected branch '[bold]{current_branch}[/bold]'.[/red]")
        log_lines.append("[white]Policy Enforced:[/white] [bold red]ZERO CRITICAL / ZERO HIGH VULNERABILITIES[/bold red]")
        log_lines.append("[dim]Automated push guards will block any changes introducing new issues.[/dim]")
    else:
        mascot_state = "guarding"
        border_color = "cyan"
        log_lines.append("[bold green]✔ FEATURE BRANCH DETECTED[/bold green]")
        log_lines.append(f"[cyan]Active development branch '[bold]{current_branch}[/bold]'.[/cyan]")
        log_lines.append("[white]Policy Enforced:[/white] [green]STANDARD FEATURE GUARD[/green]")
        log_lines.append("[dim]Changes will be validated and issue-memory diffed prior to upstream PR.[/dim]")

    log_lines.append("")
    log_lines.append("[dim]Next Step: Run 'vulnora scan' to evaluate security posture.[/dim]")

    layout = render_split_pane(
        mascot_state=mascot_state,
        log_title=f"Branch Guard Policy ({current_branch})",
        log_lines=log_lines,
        mascot_subtitle="Guard Status: " + ("PROTECTED" if protected else "ACTIVE"),
        border_style=border_color,
    )
    console.print(layout)
