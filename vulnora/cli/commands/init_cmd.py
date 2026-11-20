"""
Implementation of `vulnora init` command.
Initializes Vulnora configuration, issue memory store, and gitignore safety entries.
"""

from pathlib import Path
from typing import Optional
import typer

from ..config import DEFAULT_CONFIG_TEMPLATE, get_config_path, get_vulnora_dir, save_config
from ..git_utils import get_git_root, is_git_repository, update_gitignore
from ..memory import get_memory_path, init_memory
from ..ui import console, print_banner, print_error, print_info, print_success, print_warning, render_split_pane


def init_command(
    project_path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target project directory path (defaults to current working directory).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing .vulnora/config.yaml and memory.json if already present.",
    ),
):
    """
    Initialize Vulnora AI in the current project or repository.
    Creates .vulnora/ configuration, memory store, and updates .gitignore.
    """
    target = Path(project_path).resolve() if project_path else Path.cwd().resolve()
    print_banner()

    log_lines = []
    log_lines.append(f"[bold cyan]Initializing Vulnora AI at:[/bold cyan] [white]{target}[/white]")

    # 1. Check Git Repository
    is_git = is_git_repository(target)
    git_root = get_git_root(target)

    if not is_git:
        log_lines.append("[bold yellow]▲ Warning:[/bold yellow] [yellow]Directory is not a Git repository.[/yellow]")
        log_lines.append("[dim]Vulnora guard and pre-push hooks require a Git repository.[/dim]")
        log_lines.append("[dim]Run 'git init' to enable full branch-aware protection.[/dim]")
    else:
        log_lines.append(f"[green]✔ Git Repository Detected:[/green] [dim]{git_root}[/dim]")

    # 2. Create .vulnora directory
    vulnora_dir = get_vulnora_dir(target)
    vulnora_dir.mkdir(parents=True, exist_ok=True)
    log_lines.append(f"[green]✔ Workspace Directory:[/green] [white]{vulnora_dir.name}/[/white]")

    # 3. Generate .vulnora/config.yaml
    config_file = get_config_path(target)
    config_created = False
    if not config_file.exists() or force:
        cfg_data = dict(DEFAULT_CONFIG_TEMPLATE)
        cfg_data["project"]["name"] = target.name
        save_config(cfg_data, target)
        config_created = True
        log_lines.append(f"[green]✔ Generated Config:[/green] [white]{config_file.name}[/white]")
    else:
        log_lines.append(f"[cyan]ℹ Existing Config Found:[/cyan] [dim]{config_file.name} (preserved)[/dim]")

    # 4. Generate .vulnora/memory.json
    memory_file = get_memory_path(target)
    init_memory(target, overwrite=force)
    log_lines.append(f"[green]✔ Initialized Issue Memory:[/green] [white]{memory_file.name}[/white]")

    # 5. Update .gitignore
    if git_root:
        patterns = [
            ".vulnora/memory.json",
            ".vulnora/cache/",
            ".vulnora/logs/",
            ".vulnora/*.local.yaml",
        ]
        added = update_gitignore(git_root, patterns)
        if added:
            log_lines.append(f"[green]✔ Updated .gitignore:[/green] [dim]Protected {len(added)} cache/memory entries[/dim]")
        else:
            log_lines.append("[cyan]ℹ .gitignore already up to date.[/cyan]")

    log_lines.append("")
    log_lines.append("[bold green]Vulnora AI initialization complete![/bold green]")
    log_lines.append("[dim]Run 'vulnora guard' to inspect branch protection status.[/dim]")
    log_lines.append("[dim]Run 'vulnora scan' to start security analysis.[/dim]")

    # Display Rich Split Pane UI
    layout = render_split_pane(
        mascot_state="ready",
        log_title="Project Initialization Logs",
        log_lines=log_lines,
        mascot_subtitle="Initialization Ready",
        border_style="green",
    )
    console.print(layout)
