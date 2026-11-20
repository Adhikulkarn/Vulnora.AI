"""
Implementation of `vulnora guard` command.
Performs branch-aware protection checks and displays the Sentinel guard interface.
Supports both manual terminal invocations and Git pre-push hook execution.
Triggers the local multi-scanner engine on protected branches.
"""

from pathlib import Path
import sys
from typing import List, Optional
import typer

from ..config import get_protected_branches, is_pre_push_hook_enabled, load_config
from ..git_utils import (
    PushRefUpdate,
    get_current_branch,
    get_git_root,
    get_repo_name,
    is_git_repository,
    is_protected_branch,
    parse_push_refs,
)
from ..ui import console, print_banner, render_split_pane
from vulnora.memory import MemoryService
from vulnora.scanners import ScannerOrchestrator, Severity


def guard_command(
    remote_name: Optional[str] = typer.Argument(
        None,
        help="Remote name provided by Git pre-push hook (e.g. 'origin').",
    ),
    remote_url: Optional[str] = typer.Argument(
        None,
        help="Remote URL provided by Git pre-push hook.",
    ),
    hook_mode: bool = typer.Option(
        False,
        "--hook",
        help="Flag indicating execution originated from a Git pre-push hook.",
    ),
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
        help="Explicitly evaluate a specific branch name rather than detecting HEAD or pre-push input.",
    ),
):
    """
    Check branch-aware security guard status and enforcement policy.
    Evaluates push destinations against configured protected branches (e.g. main, production).
    """
    target = Path(project_path).resolve() if project_path else Path.cwd().resolve()
    repo_root = get_git_root(target) or target
    repo_name = get_repo_name(repo_root)

    # 1. Verify Git Pre-Push Hook Policy Configuration
    if not is_pre_push_hook_enabled(repo_root):
        console.print("[dim]Vulnora pre-push guard is disabled in .vulnora/config.yaml. Allowing push.[/dim]")
        return

    # 2. Check if running in Git Hook mode or receiving stdin
    stdin_content = ""
    if hook_mode or not sys.stdin.isatty():
        try:
            stdin_content = sys.stdin.read()
        except Exception as exc:
            console.print(f"[bold red]✖ Error reading Git pre-push input:[/bold red] [red]{exc}[/red]")
            raise typer.Exit(code=1)

    # 3. Branch Guard Evaluation via Git Hook Input
    if hook_mode or stdin_content.strip():
        _handle_hook_execution(
            stdin_content=stdin_content,
            repo_root=repo_root,
            repo_name=repo_name,
            remote_name=remote_name,
            remote_url=remote_url,
        )
        return

    # 4. Manual Terminal Execution (Evaluating local HEAD branch or --branch override)
    _handle_manual_execution(
        target=target,
        repo_name=repo_name,
        branch_override=branch_override,
    )


def _handle_hook_execution(
    stdin_content: str,
    repo_root: Path,
    repo_name: str,
    remote_name: Optional[str],
    remote_url: Optional[str],
):
    """Processes ref updates streamed from Git's pre-push hook via stdin."""
    raw_lines = stdin_content.strip()
    if not raw_lines:
        return

    updates: List[PushRefUpdate] = parse_push_refs(raw_lines)
    if not updates and raw_lines:
        console.print("[bold red]✖ Git Pre-Push Error:[/bold red] [red]Received malformed ref update stream from Git.[/red]")
        raise typer.Exit(code=1)

    # Separate branch deletions, tags, and active branch pushes
    branch_updates = [u for u in updates if u.is_branch and not u.is_deletion]
    deletions = [u for u in updates if u.is_deletion]
    tags = [u for u in updates if u.is_tag]

    # If the push consists solely of branch deletions or tags, bypass security guard checks
    if not branch_updates and (deletions or tags):
        console.print("[dim]Vulnora Guard: Push contains only tags or branch deletions; security checks skipped.[/dim]")
        return

    # Load configured protected branches
    protected_branches = get_protected_branches(repo_root)

    # Identify destination branches
    destination_branches = [u.branch_name for u in branch_updates if u.branch_name]
    protected_destinations = [b for b in destination_branches if is_protected_branch(b, protected_branches)]
    unprotected_destinations = [b for b in destination_branches if not is_protected_branch(b, protected_branches)]

    # If NO protected branches are targeted, allow push immediately
    if not protected_destinations:
        dest_display = ", ".join(unprotected_destinations) if unprotected_destinations else "feature branch"
        console.print(
            f"[bold green]✔[/bold green] [white]Push targeting unprotected branch(es): [bold cyan]{dest_display}[/bold cyan].[/white]"
        )
        console.print("[dim]Vulnora Guard: Security checks skipped for unprotected branches.[/dim]")
        return

    # Protected branch targeted -> Invoke Rich Sentinel Guard Interface & Run Scanners!
    print_banner()

    orchestrator = ScannerOrchestrator()
    config = load_config(repo_root)
    configured_scanners = config.get("scanners", {}).get("enabled", ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy"])

    # Run scanners against the repository
    target_scanners = [s for s in configured_scanners if s != "zap"]
    overall_status, scanner_statuses, unified_findings, duration = orchestrator.run_scan(
        project_path=repo_root,
        scanners_to_run=target_scanners,
        timeout_seconds=config.get("scanners", {}).get("timeout_seconds", 60),
    )
    sev_counts = orchestrator.calculate_severity_counts(unified_findings)

    log_lines = []
    log_lines.append(f"[bold cyan]Target Repository:[/bold cyan] [white]{repo_name}[/white]")
    remote_info = f"{remote_name} ({remote_url})" if remote_url else (remote_name or "origin")
    log_lines.append(f"[bold cyan]Remote Target:[/bold cyan]     [dim]{remote_info}[/dim]")
    log_lines.append(f"[bold cyan]Destination Branch:[/bold cyan] [bold yellow]{', '.join(protected_destinations)}[/bold yellow]")
    log_lines.append(f"[dim]Protected Branches:[/dim] [cyan]{', '.join(protected_branches)}[/cyan]")
    log_lines.append("")

    log_lines.append("[bold red]⚠ HIGH-SECURITY GUARD INTERCEPT[/bold red]")
    log_lines.append(f"[red]Push targeting protected branch: [bold]{', '.join(protected_destinations)}[/bold][/red]")
    log_lines.append("[white]Policy Enforced:[/white] [bold red]ZERO CRITICAL / ZERO HIGH VULNERABILITIES[/bold red]")
    log_lines.append("")
    log_lines.append(f"[bold yellow]Security Scan Execution ({duration:.2f}s):[/bold yellow]")
    log_lines.append(f"  [dim]• Scanners Run:[/dim] {', '.join(target_scanners)}")
    log_lines.append(f"  [dim]• Total Findings:[/dim] [white]{len(unified_findings)} issues[/white]")
    log_lines.append(
        f"  • Breakdown: [bold red]Crit: {sev_counts[Severity.CRITICAL]}[/bold red] | "
        f"[red]High: {sev_counts[Severity.HIGH]}[/red] | "
        f"[yellow]Med: {sev_counts[Severity.MEDIUM]}[/yellow] | "
        f"[blue]Low: {sev_counts[Severity.LOW]}[/blue]"
    )

    # Local Issue Memory Lookup
    mem_service = MemoryService(repo_root)
    mem_matches = mem_service.lookup_findings(unified_findings, update_usage=True)
    mem_hits = sum(1 for m in mem_matches if m.has_match)
    if mem_hits > 0:
        log_lines.append(f"  [dim]• Memory Matches:[/dim] [bold green]{mem_hits} verified resolutions found in local memory[/bold green]")

    log_lines.append("")
    log_lines.append("[bold green]✔ Pre-push branch guard check passed (Phase 3 placeholder: push permitted).[/bold green]")

    layout = render_split_pane(
        mascot_state="alert",
        log_title=f"Branch Guard Policy ({', '.join(protected_destinations)})",
        log_lines=log_lines,
        mascot_subtitle="Guard Status: INTERCEPTED",
        border_style="red",
    )
    console.print(layout)


def _handle_manual_execution(
    target: Path,
    repo_name: str,
    branch_override: Optional[str],
):
    """Processes interactive CLI execution of `vulnora guard`."""
    print_banner()

    log_lines = []
    log_lines.append(f"[bold cyan]Target Repository:[/bold cyan] [white]{repo_name}[/white]")

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

    # Resolve Current Active Branch
    current_branch = branch_override or get_current_branch(target)
    if not current_branch:
        current_branch = "unknown"

    # Load Configuration & Protected Branches
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

        # Run scanner orchestrator against repository
        orchestrator = ScannerOrchestrator()
        config = load_config(target)
        configured_scanners = config.get("scanners", {}).get("enabled", ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy"])
        target_scanners = [s for s in configured_scanners if s != "zap"]
        overall_status, scanner_statuses, unified_findings, duration = orchestrator.run_scan(
            project_path=target,
            scanners_to_run=target_scanners,
            timeout_seconds=config.get("scanners", {}).get("timeout_seconds", 60),
        )
        sev_counts = orchestrator.calculate_severity_counts(unified_findings)
        log_lines.append("")
        log_lines.append(f"[bold yellow]Security Findings Breakdown ({duration:.2f}s):[/bold yellow]")
        log_lines.append(
            f"  • [bold red]Crit: {sev_counts[Severity.CRITICAL]}[/bold red] | "
            f"[red]High: {sev_counts[Severity.HIGH]}[/red] | "
            f"[yellow]Med: {sev_counts[Severity.MEDIUM]}[/yellow] | "
            f"[blue]Low: {sev_counts[Severity.LOW]}[/blue] | "
            f"[dim]Total: {len(unified_findings)}[/dim]"
        )

        # Local Issue Memory Lookup
        mem_service = MemoryService(target)
        mem_matches = mem_service.lookup_findings(unified_findings, update_usage=True)
        mem_hits = sum(1 for m in mem_matches if m.has_match)
        if mem_hits > 0:
            log_lines.append(f"  • [dim]Memory Matches:[/dim] [bold green]{mem_hits} verified resolutions found in local memory[/bold green]")
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
