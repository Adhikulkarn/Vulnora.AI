"""
CLI commands for the Vulnora AI Local Issue Memory System.
Provides:
  - vulnora memory list
  - vulnora memory show <id>
  - vulnora memory search
  - vulnora memory stats
  - vulnora memory record (controlled workflow to store verified fixes)
"""

from pathlib import Path
from typing import Optional
import typer
from rich.panel import Panel
from rich.table import Table

from vulnora.cli.ui import console, print_banner
from vulnora.memory import MemoryService
from vulnora.scanners.data_structures import Severity

memory_app = typer.Typer(
    name="memory",
    help="Manage and query previously resolved vulnerabilities and verified fixes.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@memory_app.command(name="list", help="Display all stored vulnerability memory records.")
def list_records(
    path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
):
    """Lists all stored vulnerability resolutions from .vulnora/memory.json."""
    base_dir = Path(path).resolve() if path else Path.cwd()
    service = MemoryService(base_dir)
    records = service.list_records()

    print_banner()

    if not records:
        console.print("[yellow]ℹ No memory records found.[/yellow] [dim]Store verified resolutions using 'vulnora memory record'.[/dim]")
        return

    table = Table(
        title=f"Vulnora Local Issue Memory ({len(records)} verified records)",
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Memory ID", style="bold white", no_wrap=True)
    table.add_column("Scanner", style="bold cyan", no_wrap=True)
    table.add_column("Rule ID", style="magenta", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Matches", justify="right", no_wrap=True)
    table.add_column("Title", style="white")

    for r in records:
        sev = r.severity.upper()
        if sev == Severity.CRITICAL:
            sev_style = "[bold red]CRITICAL[/bold red]"
        elif sev == Severity.HIGH:
            sev_style = "[red]HIGH[/red]"
        elif sev == Severity.MEDIUM:
            sev_style = "[yellow]MEDIUM[/yellow]"
        elif sev == Severity.LOW:
            sev_style = "[blue]LOW[/blue]"
        else:
            sev_style = "[cyan]INFO[/cyan]"

        last_used = r.last_used_at[:10] if r.last_used_at else "Never"
        table.add_row(
            r.id,
            r.scanner_name.upper(),
            r.rule_id,
            sev_style,
            str(r.match_count),
            r.title[:45] + ("..." if len(r.title) > 45 else ""),
        )

    console.print(table)


@memory_app.command(name="show", help="Display the complete details of a specific memory record.")
def show_record(
    record_id: str = typer.Argument(..., help="Unique ID of the memory record (e.g. mem_a1b2c3d4)."),
    path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
):
    """Displays comprehensive root cause, remediation, and signature details for a memory record."""
    base_dir = Path(path).resolve() if path else Path.cwd()
    service = MemoryService(base_dir)
    record = service.get_record(record_id)

    if not record:
        console.print(f"[bold red]✖ Error:[/bold red] Memory record '{record_id}' not found in [cyan].vulnora/memory.json[/cyan].")
        raise typer.Exit(code=1)

    print_banner()

    details = []
    details.append(f"[bold cyan]Memory Record ID:[/bold cyan]  [bold white]{record.id}[/bold white]")
    details.append(f"[bold cyan]Vulnerability:[/bold cyan]     [white]{record.title}[/white]")
    details.append(f"[bold cyan]Scanner / Rule:[/bold cyan]    [cyan]{record.scanner_name.upper()}[/cyan] | [magenta]{record.rule_id}[/magenta]")
    details.append(f"[bold cyan]Severity:[/bold cyan]          [bold]{record.severity}[/bold]")
    details.append(f"[bold cyan]File / Language:[/bold cyan]   [yellow]{record.file_type}[/yellow]")
    details.append(f"[bold cyan]Signature:[/bold cyan]        [dim]{record.vulnerability_signature}[/dim]")
    details.append(f"[bold cyan]Usage Statistics:[/bold cyan] [green]{record.match_count} successful matches[/green] (Last used: {record.last_used_at or 'Never'})")
    details.append(f"[bold cyan]Created Timestamp:[/bold cyan][dim]{record.created_at}[/dim]")
    details.append("")
    details.append("[bold yellow]Root Cause:[/bold yellow]")
    details.append(f"  {record.root_cause or 'No root cause documented.'}")
    details.append("")
    details.append("[bold green]Verified Remediation:[/bold green]")
    details.append(f"  {record.remediation or 'No remediation guidance documented.'}")

    if record.fix_metadata:
        details.append("")
        details.append("[bold magenta]Fix Metadata:[/bold magenta]")
        for k, v in record.fix_metadata.items():
            details.append(f"  [dim]• {k}:[/dim] {v}")

    panel = Panel(
        "\n".join(details),
        title=f"[bold]Memory Record: {record.id}[/bold]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


@memory_app.command(name="search", help="Search memory records by scanner, rule ID, severity, or keywords.")
def search_records(
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Search keywords in title, root cause, or remediation."),
    scanner: Optional[str] = typer.Option(None, "--scanner", "-s", help="Filter by scanner name (e.g. bandit, semgrep)."),
    rule_id: Optional[str] = typer.Option(None, "--rule-id", "-r", help="Filter by rule ID or CVE (e.g. B605)."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity level (CRITICAL, HIGH, etc.)."),
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Target project directory path."),
):
    """Searches memory records matching specific criteria."""
    base_dir = Path(path).resolve() if path else Path.cwd()
    service = MemoryService(base_dir)
    results = service.search_records(
        query=query,
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
    )

    print_banner()

    filter_desc = []
    if query:
        filter_desc.append(f"query='{query}'")
    if scanner:
        filter_desc.append(f"scanner='{scanner}'")
    if rule_id:
        filter_desc.append(f"rule='{rule_id}'")
    if severity:
        filter_desc.append(f"severity='{severity}'")

    filters_str = f" ({', '.join(filter_desc)})" if filter_desc else ""

    if not results:
        console.print(f"[yellow]ℹ No records matching search criteria{filters_str}.[/yellow]")
        return

    table = Table(
        title=f"Memory Search Results: {len(results)} matches{filters_str}",
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Memory ID", style="bold white", no_wrap=True)
    table.add_column("Scanner", style="bold cyan", no_wrap=True)
    table.add_column("Rule ID", style="magenta", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Matches", justify="right", no_wrap=True)
    table.add_column("Title", style="white")

    for r in results:
        table.add_row(
            r.id,
            r.scanner_name.upper(),
            r.rule_id,
            r.severity,
            str(r.match_count),
            r.title[:45] + ("..." if len(r.title) > 45 else ""),
        )

    console.print(table)


@memory_app.command(name="stats", help="Display memory statistics and usage analytics.")
def memory_stats(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Target project directory path."),
):
    """Displays total memory records, scanner distributions, and match frequencies."""
    base_dir = Path(path).resolve() if path else Path.cwd()
    service = MemoryService(base_dir)
    stats = service.get_stats()

    print_banner()

    summary_text = [
        f"[bold cyan]Total Verified Records:[/bold cyan] [bold white]{stats['total_records']}[/bold white]",
        f"[bold cyan]Total Successful Matches:[/bold cyan] [bold green]{stats['total_matches']}[/bold green]",
    ]

    console.print(Panel("\n".join(summary_text), title="[bold]Vulnora Issue Memory Overview[/bold]", border_style="cyan"))
    console.print()

    # Scanner Breakdown Table
    s_table = Table(title="Records by Scanner", header_style="bold cyan", border_style="dim")
    s_table.add_column("Scanner", style="bold white")
    s_table.add_column("Record Count", justify="right", style="cyan")
    for s_name, count in stats["by_scanner"].items():
        s_table.add_row(s_name.upper(), str(count))

    if not stats["by_scanner"]:
        s_table.add_row("NONE", "0")

    # Severity Breakdown Table
    sev_table = Table(title="Records by Severity", header_style="bold magenta", border_style="dim")
    sev_table.add_column("Severity", style="bold white")
    sev_table.add_column("Record Count", justify="right")
    for sev, count in stats["by_severity"].items():
        if sev == Severity.CRITICAL:
            color = "bold red"
        elif sev == Severity.HIGH:
            color = "red"
        elif sev == Severity.MEDIUM:
            color = "yellow"
        elif sev == Severity.LOW:
            color = "blue"
        else:
            color = "cyan"
        sev_table.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{count}[/{color}]")

    console.print(s_table)
    console.print()
    console.print(sev_table)


@memory_app.command(name="record", help="Record a verified vulnerability resolution into local memory.")
def record_resolution(
    title: str = typer.Option(..., "--title", "-t", help="Vulnerability title (e.g. 'Insecure MD5 Hash')."),
    scanner: str = typer.Option(..., "--scanner", "-s", help="Scanner name (e.g. bandit, semgrep, gitleaks)."),
    rule_id: str = typer.Option(..., "--rule-id", "-r", help="Rule ID or CVE ID (e.g. B303, GHSA-xxxx)."),
    severity: str = typer.Option("HIGH", "--severity", help="Vulnerability severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)."),
    root_cause: str = typer.Option(..., "--root-cause", help="Explanation of why the vulnerability occurred."),
    remediation: str = typer.Option(..., "--remediation", help="Verified resolution steps / code fix guidance."),
    file_path: Optional[str] = typer.Option(None, "--file-path", help="Affected file path or type (e.g. app.py)."),
    code_pattern: Optional[str] = typer.Option(None, "--code-pattern", help="Abstract code snippet or pattern."),
    verified: bool = typer.Option(True, "--verified/--unverified", help="Confirm the resolution was verified via rescan."),
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Target project directory path."),
):
    """
    Saves a verified vulnerability resolution to .vulnora/memory.json.
    Ensures duplicate signatures are updated rather than duplicated.
    """
    base_dir = Path(path).resolve() if path else Path.cwd()
    service = MemoryService(base_dir)

    try:
        record = service.save_verified_resolution(
            title=title,
            scanner_name=scanner,
            rule_id=rule_id,
            severity=severity,
            root_cause=root_cause,
            remediation=remediation,
            file_path_or_type=file_path,
            code_snippet=code_pattern,
            verified=verified,
        )
        print_banner()
        console.print(f"[bold green]✔ Verified Resolution Recorded in Local Memory![/bold green]")
        console.print(f"  [bold cyan]Memory ID:[/bold cyan]  [bold white]{record.id}[/bold white]")
        console.print(f"  [bold cyan]Signature:[/bold cyan]  [dim]{record.vulnerability_signature}[/dim]")
        console.print(f"  [bold cyan]Rule / Tool:[/bold cyan][magenta]{record.rule_id}[/magenta] ([cyan]{record.scanner_name.upper()}[/cyan])")
    except Exception as exc:
        console.print(f"[bold red]✖ Error saving memory record:[/bold red] {exc}")
        raise typer.Exit(code=1)
