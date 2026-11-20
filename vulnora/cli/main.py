"""
Main Typer CLI entrypoint for Vulnora AI.
Provides `vulnora init`, `vulnora scan`, and `vulnora guard`.
"""

from typing import Optional
import typer

from .commands.guard_cmd import guard_command
from .commands.init_cmd import init_command
from .commands.memory_cmd import memory_app
from .commands.scan_cmd import scan_command
from .ui import console

__version__ = "1.0.0"

app = typer.Typer(
    name="vulnora",
    help="[bold cyan]Vulnora AI[/bold cyan]: Branch-Aware Autonomous Security Guard & Remediation Engine.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]Vulnora AI[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Display the current Vulnora version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """
    Vulnora AI CLI commands for repository security management.
    """
    pass


# Register Core CLI Commands
app.command(name="init", help="Initialize Vulnora configuration, issue memory, and .gitignore settings.")(init_command)
app.command(name="scan", help="Run multi-scanner security analysis across files, dependencies, and URLs.")(scan_command)
app.command(name="guard", help="Evaluate branch-aware protection status for protected branches (main, production).")(guard_command)
app.add_typer(memory_app, name="memory", help="Manage and query previously resolved vulnerabilities and verified fixes.")


if __name__ == "__main__":
    app()

