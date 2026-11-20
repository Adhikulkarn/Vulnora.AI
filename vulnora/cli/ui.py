"""
Rich terminal UI utilities and split-pane interface for Vulnora AI.
Features the Vulnora Sentinel Mascot pane and real-time security log panel.
"""

from typing import List, Optional
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# Vulnora Mascot ASCII Art States
MASCOT_READY = """
      [bold cyan]/\\_/\\ [/bold cyan]
     [bold cyan]( o.o )[/bold cyan]   [bold yellow]VULNORA[/bold yellow]
      [bold cyan]> ^ <[/bold cyan]    [dim]Sentinel v1.0[/dim]
   [bold blue]/|     |\\ [/bold blue]
  [bold blue]/_|_____|_/[/bold blue]  [green]● SYSTEM READY[/green]
"""

MASCOT_SCANNING = """
      [bold yellow]/\\_/\\ [/bold yellow]
     [bold yellow]( •.• )[/bold yellow]   [bold yellow]VULNORA[/bold yellow]
      [bold yellow]> ^ <[/bold yellow]    [cyan]Scanning...[/cyan]
   [bold magenta]/| === |\\ [/bold magenta]
  [bold magenta]/_|_____|_/[/bold magenta]  [yellow]● RUNNING CHECKS[/yellow]
"""

MASCOT_GUARDING = """
      [bold green]/\\_/\\ [/bold green]
     [bold green]( ◉.◉ )[/bold green]   [bold yellow]VULNORA[/bold yellow]
      [bold green]> ^ <[/bold green]    [green]Branch Guard[/green]
   [bold cyan]/| SHIELD |\\ [/bold cyan]
  [bold cyan]/_|________|_/[/bold cyan] [cyan]● SHIELD ACTIVE[/cyan]
"""

MASCOT_ALERT = """
      [bold red]/\\_/\\ [/bold red]
     [bold red]( ×.× )[/bold red]   [bold yellow]VULNORA[/bold yellow]
      [bold red]> ! <[/bold red]    [bold red]ALERT[/bold red]
   [bold red]/|  WARN  |\\ [/bold red]
  [bold red]/_|________|_/[/bold red] [bold red]● SECURITY BLOCK[/bold red]
"""


def get_mascot_panel(state: str = "ready", subtitle: Optional[str] = None) -> Panel:
    """Generates the mascot panel based on state ('ready', 'scanning', 'guarding', 'alert')."""
    if state == "scanning":
        content = MASCOT_SCANNING
        border_style = "yellow"
        title = "[bold yellow]Vulnora Sentinel[/bold yellow]"
    elif state == "guarding":
        content = MASCOT_GUARDING
        border_style = "cyan"
        title = "[bold cyan]Branch Guard Sentinel[/bold cyan]"
    elif state == "alert":
        content = MASCOT_ALERT
        border_style = "red"
        title = "[bold red]Sentinel Alert[/bold red]"
    else:
        content = MASCOT_READY
        border_style = "green"
        title = "[bold green]Vulnora AI Assistant[/bold green]"

    return Panel(
        Text.from_markup(content.strip()),
        title=title,
        subtitle=subtitle or "[dim]Vulnora Security Engine[/dim]",
        border_style=border_style,
        padding=(1, 2),
    )


def render_split_pane(
    mascot_state: str,
    log_title: str,
    log_lines: List[str],
    mascot_subtitle: Optional[str] = None,
    border_style: str = "blue",
) -> Layout:
    """
    Renders a two-column split-pane layout:
      - Left column: Sentinel Mascot
      - Right column: Execution logs / security status
    """
    layout = Layout(name="root")
    layout.split_row(
        Layout(name="left", ratio=1, minimum_size=32),
        Layout(name="right", ratio=2),
    )

    left_panel = get_mascot_panel(state=mascot_state, subtitle=mascot_subtitle)

    log_text = Text()
    for line in log_lines:
        log_text.append_text(Text.from_markup(f"{line}\n"))

    right_panel = Panel(
        log_text,
        title=f"[bold {border_style}]{log_title}[/bold {border_style}]",
        border_style=border_style,
        padding=(1, 2),
    )

    layout["left"].update(left_panel)
    layout["right"].update(right_panel)
    return layout


def print_banner():
    """Prints the official Vulnora AI banner in terminal."""
    banner_text = Text(
        "█░█ █░█ █░░ █▄░█ █▀█ █▀█ ▄▀█      ▄▀█ █\n"
        "▀▄▀ █▄█ █▄▄ █░▀█ █▄█ █▀▄ █▀█ ▄▄   █▀█ █\n"
        "Branch-Aware Autonomous Security Guard & Remediation",
        style="bold cyan",
    )
    console.print(Panel(banner_text, border_style="cyan", padding=(0, 2)))


def print_success(message: str):
    """Prints a styled success message."""
    console.print(f"[bold green]✔[/bold green] [white]{message}[/white]")


def print_warning(message: str):
    """Prints a styled warning message."""
    console.print(f"[bold yellow]▲[/bold yellow] [yellow]{message}[/yellow]")


def print_error(message: str, detail: Optional[str] = None):
    """Prints a styled error message with optional detail."""
    console.print(f"[bold red]✖ Error:[/bold red] [red]{message}[/red]")
    if detail:
        console.print(f"  [dim]{detail}[/dim]")


def print_info(message: str):
    """Prints a styled informational message."""
    console.print(f"[bold blue]ℹ[/bold blue] [dim]{message}[/dim]")


def display_remediation_card(finding: dict, fix_payload: dict, source: str = "Remote AI"):
    """
    Renders a styled Rich panel showing the vulnerability finding,
    root cause, explanation, and proposed replacement code.
    """
    title = finding.get("title", "Security Finding")
    rule_id = finding.get("rule_id", "")
    severity = str(finding.get("severity", "MEDIUM")).upper()
    file_path = finding.get("file_path", "")
    line_num = finding.get("line_number")
    loc = f"{file_path}:{line_num}" if line_num else file_path

    sev_color = "red" if severity in ("CRITICAL", "HIGH") else ("yellow" if severity == "MEDIUM" else "cyan")

    content = Text()
    content.append("Finding: ", style="bold white")
    content.append(f"{title} ", style=f"bold {sev_color}")
    content.append(f"[{severity}]\n", style=f"bold {sev_color}")
    content.append(f"Location: {loc}  |  Rule: {rule_id}\n\n", style="dim")

    content.append("Root Cause:\n", style="bold cyan")
    content.append(f"{fix_payload.get('root_cause', 'Vulnerability detected.')}\n\n", style="white")

    content.append("Remediation Explanation:\n", style="bold green")
    content.append(f"{fix_payload.get('explanation', '')}\n\n", style="white")

    replacement_code = fix_payload.get("replacement_code") or fix_payload.get("patched_snippet") or ""
    if replacement_code:
        content.append("Proposed Replacement Code:\n", style="bold yellow")
        content.append(f"{replacement_code}\n", style="bold green")

    panel = Panel(
        content,
        title=f"[bold {sev_color}]Remediation Proposal ({source})[/bold {sev_color}]",
        subtitle=f"[dim]Source: {source}[/dim]",
        border_style=sev_color,
        padding=(1, 2),
    )
    console.print(panel)

