"""
Interactive TUI widgets for Vulnora AI.

Provides:
- SentinelMascotPanel: ASCII mascot reflecting real-time security posture.
- ImmunityMetricsPanel: Real-time telemetry, antibody counts, and scanner health.
- FindingsListView: Keyboard-navigable list of security findings with severity badges.
- CodeDiffTabs: Multi-tab inspector (Snippet, Surgical Prompt, Remediation Diff, Guardrail)
  with strict Zero-Secret Egress via SecretRedactor.
- ApiKeyModal: Masked modal dialog for entering / saving Gemini API key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Input, Label, ListItem, ListView, Static, TabbedContent, TabPane

from vulnora.core.models import Finding, RemediationProposal, Severity
from vulnora.engine.prompt_compiler import SurgicalPromptCompiler
from vulnora.engine.redactor import SecretRedactor


# -----------------------------------------------------------------------------
# 1. Sentinel Mascot Panel
# -----------------------------------------------------------------------------

MASCOT_ARTWORKS: Dict[str, str] = {
    "VIGILANT": (
        "[bold cyan]      🛡️  [VULNORA SENTINEL][/bold cyan]\n"
        "[bold green]         /───\\ [/bold green]    [bold white]Posture:[/bold white] [bold green]VIGILANT (CLEAN)[/bold green]\n"
        "[bold green]        │ o.o │[/bold green]    [dim]Autonomous Protection Active[/dim]\n"
        "[bold green]         \\───/ [/bold green]    [dim]Git Push Guard: READY[/dim]"
    ),
    "SCANNING": (
        "[bold yellow]      🔍  [VULNORA SENTINEL][/bold yellow]\n"
        "[bold yellow]         /───\\ [/bold yellow]    [bold white]Posture:[/bold white] [bold yellow]INSPECTING CODEBASE...[/bold yellow]\n"
        "[bold yellow]        │ >.< │[/bold yellow]    [dim]Running Concurrent Scanners[/dim]\n"
        "[bold yellow]         \\───/ [/bold yellow]    [dim]AST & Diff Boundary Analysis[/dim]"
    ),
    "ALERT": (
        "[bold red]      ⚠️   [VULNORA SENTINEL][/bold red]\n"
        "[bold red]         /───\\ [/bold red]    [bold white]Posture:[/bold white] [bold red]THREATS DETECTED[/bold red]\n"
        "[bold red]        │ !.! │[/bold red]    [bold red]Vulnerabilities Block Push[/bold red]\n"
        "[bold red]         \\───/ [/bold red]    [dim]Press [A] to Auto-Fix with AI[/dim]"
    ),
    "REMEDIATING": (
        "[bold magenta]      ⚡  [VULNORA SENTINEL][/bold magenta]\n"
        "[bold magenta]         /───\\ [/bold magenta]    [bold white]Posture:[/bold white] [bold magenta]SYNTHESIZING FIX...[/bold magenta]\n"
        "[bold magenta]        │ ^.^ │[/bold magenta]    [dim]Cloud AI Surgical Remediation[/dim]\n"
        "[bold magenta]         \\───/ [/bold magenta]    [dim]Applying AST Verification Loop[/dim]"
    ),
    "VACCINATED": (
        "[bold green]      💉  [VULNORA SENTINEL][/bold green]\n"
        "[bold green]         /───\\ [/bold green]    [bold white]Posture:[/bold white] [bold green]SELF-VACCINATED[/bold green]\n"
        "[bold green]        │ ◕‿◕ │[/bold green]    [dim]Patches Verified Clean[/dim]\n"
        "[bold green]         \\───/ [/bold green]    [dim]Antibodies Recorded in AGENTS.md[/dim]"
    ),
}


class SentinelMascotPanel(Static):
    """
    Renders the Vulnora Sentinel ASCII mascot reflecting security states:
    VIGILANT, SCANNING, ALERT, REMEDIATING, VACCINATED.
    """

    state: reactive[str] = reactive("VIGILANT")
    message: reactive[str] = reactive("")

    def __init__(
        self,
        initial_state: str = "VIGILANT",
        message: str = "",
        *,
        id: Optional[str] = "mascot-panel",
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self.state = initial_state
        self.message = message

    def set_state(self, new_state: str, message: Optional[str] = None) -> None:
        """Sets the mascot state and refreshes the panel."""
        self.state = new_state.upper()
        if message is not None:
            self.message = message
        self.refresh()

    def render(self) -> Panel:
        art = MASCOT_ARTWORKS.get(self.state, MASCOT_ARTWORKS["VIGILANT"])
        body = Text.from_markup(art)
        if self.message:
            body.append(Text(f"\nStatus: {self.message}", style="italic cyan"))

        border_styles = {
            "VIGILANT": "green",
            "SCANNING": "yellow",
            "ALERT": "red",
            "REMEDIATING": "magenta",
            "VACCINATED": "green",
        }
        style = border_styles.get(self.state, "cyan")
        return Panel(
            body,
            title="[bold]Vulnora Sentinel Mascot[/bold]",
            border_style=style,
            expand=True,
        )


# -----------------------------------------------------------------------------
# 2. Immunity Metrics Panel
# -----------------------------------------------------------------------------

class ImmunityMetricsPanel(Static):
    """
    Displays real-time telemetry: stored antibodies, hit rate, branch protection,
    and active security scanner health.
    """

    antibody_count: reactive[int] = reactive(0)
    hit_rate: reactive[float] = reactive(100.0)
    protected_branch: reactive[str] = reactive("main")
    scanner_count: reactive[int] = reactive(6)
    status_label: reactive[str] = reactive("ACTIVE")
    ai_status: reactive[str] = reactive("[yellow]Offline / Prompt-Only (Press [K])[/yellow]")

    def __init__(
        self,
        antibody_count: int = 0,
        hit_rate: float = 100.0,
        protected_branch: str = "main",
        scanner_count: int = 6,
        ai_status: str = "[yellow]Offline / Prompt-Only (Press [K])[/yellow]",
        *,
        id: Optional[str] = "metrics-panel",
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self.antibody_count = antibody_count
        self.hit_rate = hit_rate
        self.protected_branch = protected_branch
        self.scanner_count = scanner_count
        self.ai_status = ai_status

    def update_metrics(
        self,
        antibody_count: Optional[int] = None,
        hit_rate: Optional[float] = None,
        protected_branch: Optional[str] = None,
        scanner_count: Optional[int] = None,
        status_label: Optional[str] = None,
        ai_status: Optional[str] = None,
    ) -> None:
        """Updates reactive metrics and schedules widget render."""
        if antibody_count is not None:
            self.antibody_count = antibody_count
        if hit_rate is not None:
            self.hit_rate = hit_rate
        if protected_branch is not None:
            self.protected_branch = protected_branch
        if scanner_count is not None:
            self.scanner_count = scanner_count
        if status_label is not None:
            self.status_label = status_label
        if ai_status is not None:
            self.ai_status = ai_status
        self.refresh()

    def render(self) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column("Key", style="bold white", justify="left")
        table.add_column("Val", style="cyan", justify="left")

        table.add_row("Immune Memory", f"[bold green]{self.antibody_count}[/bold green] Antibodies Stored")
        table.add_row("Cache Hit Rate", f"[bold cyan]{self.hit_rate:.1f}%[/bold cyan] Instant Interception")
        table.add_row("Target Branch", f"[bold yellow]{self.protected_branch}[/bold yellow] (Protected)")
        table.add_row("Scanner Fleet", f"[bold green]{self.scanner_count}/6[/bold green] Enabled & Gated")
        table.add_row("Guard Engine", f"[bold {'green' if self.status_label == 'ACTIVE' else 'red'}]{self.status_label}[/]")
        table.add_row("Cloud AI", self.ai_status)

        return Panel(
            table,
            title="[bold]Immunity Engine Telemetry[/bold]",
            border_style="cyan",
            expand=True,
        )


# -----------------------------------------------------------------------------
# 3. Findings List View
# -----------------------------------------------------------------------------

class FindingItem(ListItem):
    """Single item representing a security finding within FindingsListView."""

    def __init__(self, finding: Finding, is_resolved: bool = False) -> None:
        super().__init__()
        self.finding = finding
        self.is_resolved = is_resolved

    def render(self) -> Text:
        if self.is_resolved:
            badge = "[CLEAN   ]"
            color = "bold green"
        else:
            sev = self.finding.severity
            color_map = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold dark_orange",
                Severity.MEDIUM: "bold yellow",
                Severity.LOW: "cyan",
                Severity.INFO: "dim white",
            }
            color = color_map.get(sev, "white")
            badge = f"[{sev.value:<8}]"

        loc = f"{Path(self.finding.file_path).name}"
        if self.finding.line_number:
            loc += f":{self.finding.line_number}"

        text = Text()
        text.append(badge, style=color)
        text.append(f" {self.finding.rule_id:<12} ", style="bold white" if not self.is_resolved else "dim white")
        text.append(f"{loc:<22} ", style="italic cyan" if not self.is_resolved else "dim cyan")
        text.append(f"({self.finding.scanner_name})", style="dim")
        return text


class FindingsListView(Widget):
    """
    List view container for findings with keyboard navigation and change events.
    """

    class FindingSelected(Message):
        """Message emitted when user highlights or clicks a finding."""

        def __init__(self, finding: Finding) -> None:
            super().__init__()
            self.finding = finding

    def __init__(
        self,
        findings: Optional[List[Finding]] = None,
        *,
        id: Optional[str] = "findings-pane",
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self.findings: List[Finding] = findings or []
        self._list_view: ListView = ListView(id="findings-list")
        self.resolved_fingerprints: Set[str] = set()

    def compose(self):
        yield Label("[bold cyan] Detected Security Findings[/bold cyan]", id="findings-title")
        yield self._list_view

    def on_mount(self) -> None:
        if self.findings:
            self.set_findings(self.findings)

    def set_findings(self, findings: List[Finding], select_first: bool = True) -> None:
        """Populates the list with findings."""
        self.findings = list(findings)
        if self.is_mounted:
            self._list_view.clear()
            for f in self.findings:
                f_fp = f.fingerprint or f.compute_fingerprint()
                is_res = f_fp in self.resolved_fingerprints
                self._list_view.append(FindingItem(f, is_resolved=is_res))
            if self.findings and select_first:
                self._list_view.index = 0
                self.post_message(self.FindingSelected(self.findings[0]))

    def mark_resolved(self, fingerprint: str) -> None:
        """Marks a finding fingerprint as resolved and refreshes its item display."""
        self.resolved_fingerprints.add(fingerprint)
        if self.is_mounted:
            for item in self._list_view.children:
                if isinstance(item, FindingItem):
                    f_fp = item.finding.fingerprint or item.finding.compute_fingerprint()
                    if f_fp == fingerprint:
                        item.is_resolved = True
                        item.refresh()

    def clear_findings(self) -> None:
        """Clears all findings."""
        self.findings = []
        if self.is_mounted:
            self._list_view.clear()

    def get_selected_finding(self) -> Optional[Finding]:
        """Returns the currently highlighted Finding, if any."""
        idx = self._list_view.index
        if idx is not None and 0 <= idx < len(self.findings):
            return self.findings[idx]
        return None

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Handles selection change on arrow-key navigation."""
        if event.item and isinstance(event.item, FindingItem):
            self.post_message(self.FindingSelected(event.item.finding))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handles Enter key selection."""
        if event.item and isinstance(event.item, FindingItem):
            self.post_message(self.FindingSelected(event.item.finding))


# -----------------------------------------------------------------------------
# 4. Code & Diff Tabs Panel
# -----------------------------------------------------------------------------

class CodeDiffTabs(Widget):
    """
    Split-pane tabbed inspector showing:
    1. Code Snippet (sanitized via SecretRedactor)
    2. Surgical Prompt (AST context and guidance, zero secret)
    3. Remediation Diff (proposed unified diff, zero secret)
    4. Guardrail Rule (AGENTS.md rule & antibody ID)
    """

    def __init__(
        self,
        target_root: Optional[Path] = None,
        *,
        id: Optional[str] = "details-pane",
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self.target_root = target_root or Path.cwd()
        self.redactor = SecretRedactor()
        self.current_finding: Optional[Finding] = None
        self.current_proposal: Optional[RemediationProposal] = None
        self.current_diff: Optional[str] = None
        self.current_antibody: Optional[str] = None
        self.remediations: Dict[str, Dict[str, Any]] = {}

        self.snippet_text: str = "Select a finding to inspect source code."
        self.prompt_text: str = "Surgical prompt will appear here."
        self.diff_text: str = "No remediation generated yet. Press [A] to trigger Cloud AI auto-fix."
        self.rule_text: str = "Guardrail rules will appear upon vaccination."

        self._snippet_display = Static(self.snippet_text, id="tab-snippet-text")
        self._prompt_display = Static(self.prompt_text, id="tab-prompt-text")
        self._diff_display = Static(self.diff_text, id="tab-diff-text")
        self._rule_display = Static(self.rule_text, id="tab-rule-text")
        self._tabbed_content: Optional[TabbedContent] = None

    def compose(self):
        with TabbedContent(id="tabs-container", initial="tab-snippet"):
            with TabPane("Code Snippet", id="tab-snippet"):
                with VerticalScroll():
                    yield self._snippet_display
            with TabPane("Surgical Prompt", id="tab-prompt"):
                with VerticalScroll():
                    yield self._prompt_display
            with TabPane("Remediation & Diff", id="tab-diff"):
                with VerticalScroll():
                    yield self._diff_display
            with TabPane("Guardrail Rule", id="tab-rule"):
                with VerticalScroll():
                    yield self._rule_display

    def on_mount(self) -> None:
        self._tabbed_content = self.query_one("#tabs-container", TabbedContent)
        self._refresh_displays()

    def _refresh_displays(self) -> None:
        if not self.is_mounted:
            return
        try:
            self._snippet_display.update(Text.from_markup(self.snippet_text))
            self._prompt_display.update(Text(self.prompt_text))
            self._diff_display.update(Text.from_markup(self.diff_text))
            self._rule_display.update(Text.from_markup(self.rule_text))
        except Exception:
            pass

    def next_tab(self) -> None:
        """Cycles to the next tab pane."""
        if not self._tabbed_content:
            return
        tabs = ["tab-snippet", "tab-prompt", "tab-diff", "tab-rule"]
        current = self._tabbed_content.active
        try:
            curr_idx = tabs.index(current)
            next_idx = (curr_idx + 1) % len(tabs)
            self._tabbed_content.active = tabs[next_idx]
        except ValueError:
            self._tabbed_content.active = tabs[0]

    def switch_tab(self, tab_id: str) -> None:
        """Switches active tab to tab_id (e.g. 'tab-diff')."""
        if self._tabbed_content:
            self._tabbed_content.active = tab_id

    def store_remediation(
        self,
        finding_id: str,
        root_cause: str,
        explanation: str,
        diff: str,
        provider: str = "",
        model: str = "",
        proposal: Optional[RemediationProposal] = None,
        antibody_id: Optional[str] = None,
    ) -> None:
        """Stores remediation metadata and diff for a finding fingerprint."""
        self.remediations[finding_id] = {
            "root_cause": root_cause,
            "explanation": explanation,
            "diff": diff,
            "provider": provider,
            "model": model,
            "proposal": proposal,
            "antibody_id": antibody_id,
        }

    def update_finding(
        self,
        finding: Optional[Finding],
        proposal: Optional[RemediationProposal] = None,
        diff: Optional[str] = None,
        antibody_id: Optional[str] = None,
        target_root: Optional[Path] = None,
    ) -> None:
        """Updates all tab panes for the given finding, scrubbing all secrets."""
        if target_root:
            self.target_root = target_root

        f_key = (finding.fingerprint or finding.compute_fingerprint()) if finding else ""
        stored = self.remediations.get(f_key, {})

        # If proposal or diff or antibody_id is explicitly passed, update stored cache
        if proposal is not None or diff is not None or antibody_id is not None:
            root_cause = (proposal.root_cause if proposal else "") or stored.get("root_cause", "")
            explanation = (proposal.explanation if proposal else "") or stored.get("explanation", "")
            provider = (proposal.provider if proposal and proposal.provider else "") or stored.get("provider", "")
            model = (proposal.model if proposal and proposal.model else "") or stored.get("model", "")
            self.store_remediation(
                finding_id=f_key,
                root_cause=root_cause,
                explanation=explanation,
                diff=diff if diff is not None else stored.get("diff", ""),
                provider=provider,
                model=model,
                proposal=proposal or stored.get("proposal"),
                antibody_id=antibody_id or stored.get("antibody_id"),
            )
            stored = self.remediations.get(f_key, {})

        active_diff = diff if diff is not None else stored.get("diff")
        active_proposal = proposal if proposal is not None else stored.get("proposal")
        active_antibody = antibody_id if antibody_id is not None else stored.get("antibody_id")

        active_root_cause = (active_proposal.root_cause if active_proposal else "") or stored.get("root_cause", "")
        active_explanation = (active_proposal.explanation if active_proposal else "") or stored.get("explanation", "")
        active_provider = (active_proposal.provider if active_proposal and active_proposal.provider else "") or stored.get("provider", "")
        active_model = (active_proposal.model if active_proposal and active_proposal.model else "") or stored.get("model", "")

        self.current_finding = finding
        self.current_proposal = active_proposal
        self.current_diff = active_diff
        self.current_antibody = active_antibody

        if not finding:
            self.snippet_text = "No finding selected."
            self.prompt_text = "No prompt compiled."
            self.diff_text = "No diff available."
            self.rule_text = "No rule available."
            self._refresh_displays()
            return

        # 1. Update Code Snippet (read file around line, scrub secrets)
        snippet_text = self._extract_snippet(finding)
        scrubbed_snippet = self.redactor.redact(snippet_text).redacted_text
        self.snippet_text = f"[bold cyan]{finding.file_path}:{finding.line_number or 1}[/bold cyan]\n\n{scrubbed_snippet}"

        # 2. Update Surgical Prompt
        try:
            compiler = SurgicalPromptCompiler(target_root=self.target_root)
            prompt = compiler.compile(finding)
            scrubbed_prompt = self.redactor.redact(prompt.compiled_markdown).redacted_text
            self.prompt_text = scrubbed_prompt
        except Exception as exc:
            self.prompt_text = f"Failed to compile surgical prompt: {exc}"

        # 3. Update Remediation & Diff (Formatted Explanation + Diff)
        diff_sections: List[str] = []

        if active_provider or active_model:
            prov_str = f"{active_provider or 'Cloud AI'} ({active_model or 'auto'})"
            diff_sections.append(f"[bold cyan]AI Provider:[/] [white]{prov_str}[/white]")

        if active_root_cause:
            diff_sections.append(f"[bold white]Root Cause:[/bold white]\n{active_root_cause}")

        if active_explanation:
            diff_sections.append(f"[bold white]Explanation:[/bold white]\n{active_explanation}")

        if active_diff:
            scrubbed_diff = self.redactor.redact(active_diff).redacted_text
            colorized = self._colorize_diff(scrubbed_diff)
            diff_sections.append(f"[bold green]Unified Diff (Before vs. After):[/bold green]\n{colorized}")
        elif active_proposal and active_proposal.replacement_code:
            rep = self.redactor.redact(active_proposal.replacement_code).redacted_text
            diff_sections.append(f"[bold green]Proposed Replacement Code:[/bold green]\n{rep}")

        if diff_sections:
            self.diff_text = "\n\n".join(diff_sections)
        else:
            self.diff_text = "[dim]No remediation generated yet. Press [A] to trigger Cloud AI auto-fix.[/dim]"

        # 4. Update Guardrail Rule
        rule_body = []
        if active_antibody:
            rule_body.append(f"[bold green]✔ Antibody Synthesized:[/bold green] [cyan]{active_antibody}[/cyan]")
        if active_proposal and active_proposal.agents_rule:
            rule_body.append(f"\n[bold white]AGENTS.md Preventative Guardrail:[/bold white]\n[yellow]- **[{finding.rule_id}]**: {active_proposal.agents_rule}[/yellow]")
        elif finding:
            rule_body.append(f"\n[bold white]Rule Guidance for {finding.rule_id}:[/bold white]\n[dim]{finding.description}[/dim]")
        self.rule_text = "\n".join(rule_body)

        self._refresh_displays()

    def _extract_snippet(self, finding: Finding) -> str:
        """Extracts source lines surrounding finding line, highlighting the focal line."""
        target_file = self.target_root / finding.file_path
        if not target_file.is_file():
            p = Path(finding.file_path)
            if p.is_file():
                target_file = p
            else:
                return f"[italic red]File not found: {finding.file_path}[/italic red]"

        try:
            lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            return f"[italic red]Error reading file: {exc}[/italic red]"

        target_line = finding.line_number or 1
        start_idx = max(0, target_line - 6)
        end_idx = min(len(lines), target_line + 5)

        output_lines = []
        for i in range(start_idx, end_idx):
            line_no = i + 1
            raw_line = lines[i]
            if line_no == target_line:
                output_lines.append(f"[bold red]► {line_no:4d} │ {raw_line}[/bold red]")
            else:
                output_lines.append(f"[dim]  {line_no:4d} │ {raw_line}[/dim]")

        return "\n".join(output_lines)

    def _colorize_diff(self, diff_text: str) -> str:
        """Colorizes a unified diff for rich text markup."""
        lines = []
        for line in diff_text.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                lines.append(f"[bold white]{line}[/bold white]")
            elif line.startswith("@@"):
                lines.append(f"[bold cyan]{line}[/bold cyan]")
            elif line.startswith("+"):
                lines.append(f"[bold green]{line}[/bold green]")
            elif line.startswith("-"):
                lines.append(f"[bold red]{line}[/bold red]")
            else:
                lines.append(f"[dim]{line}[/dim]")
        return "\n".join(lines)

    def get_copyable_content(self) -> str:
        """
        Returns clean, zero-secret scrubbed content for clipboard export ([C]).
        """
        active_tab = "tab-snippet"
        if self._tabbed_content:
            active_tab = self._tabbed_content.active

        if active_tab == "tab-prompt":
            text = self.prompt_text
        elif active_tab == "tab-diff":
            text = self.diff_text
        elif active_tab == "tab-rule":
            text = self.rule_text
        else:
            text = self.snippet_text

        # Always guarantee zero-secret scrubbing before clipboard copy
        return self.redactor.redact(text).redacted_text


# -----------------------------------------------------------------------------
# 5. Gemini API Key Configuration Modal
# -----------------------------------------------------------------------------

class ApiKeyModal(ModalScreen[Optional[str]]):
    """
    Modal screen for configuring Gemini API key in-TUI.
    Guarantees zero plain-text display via password-masked input.
    Supports session-only storage or local credential persistence (.vulnora/credentials.local with 0o600).
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    CSS = """
    ApiKeyModal {
        align: center middle;
        background: rgba(15, 20, 28, 0.85);
    }

    #api-key-dialog {
        width: 72;
        height: auto;
        border: solid cyan;
        background: #141c2b;
        padding: 1 2;
    }

    #api-key-title {
        text-style: bold;
        color: cyan;
        text-align: center;
        margin-bottom: 1;
    }

    #api-key-subtitle {
        color: #94a3b8;
        margin-bottom: 1;
    }

    #api-key-input {
        margin-bottom: 1;
        border: solid #3b82f6;
    }

    #api-key-buttons {
        layout: horizontal;
        align: center middle;
        height: 3;
    }

    #api-key-buttons Button {
        margin-right: 1;
    }
    """

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        initial_key: Optional[str] = None,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self.target_dir = target_dir or Path.cwd()
        self.initial_key = initial_key or ""

    def compose(self) -> ComposeResult:
        with Container(id="api-key-dialog"):
            yield Label("🔑 Configure Google Gemini API Key", id="api-key-title")
            yield Label(
                "Enter your Gemini API key (AIza... or AQ....).\n"
                "Keys are masked and protected by pre-egress Zero-Secret scrubbing.",
                id="api-key-subtitle",
            )
            yield Input(
                value=self.initial_key,
                placeholder="Enter Gemini API Key (AIza... or AQ....)",
                password=True,
                id="api-key-input",
            )
            with Horizontal(id="api-key-buttons"):
                yield Button("Save for Session", variant="primary", id="btn-session")
                yield Button("Save Locally (.vulnora)", variant="success", id="btn-local")
                yield Button("Cancel", variant="error", id="btn-cancel")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id in ("btn-cancel", "btn_cancel"):
            self.dismiss(None)
            return

        input_widget = self.query_one("#api-key-input", Input)
        key = input_widget.value.strip()

        if not key:
            self.notify("API key cannot be empty.", severity="warning")
            return

        if btn_id in ("btn-local", "btn_local"):
            from vulnora.core.config import save_local_credential
            save_local_credential("GEMINI_API_KEY", key, base_path=self.target_dir)
            self.dismiss(key)
        elif btn_id in ("btn-session", "btn_session"):
            self.dismiss(key)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        key = event.value.strip()
        if key:
            self.dismiss(key)
        else:
            self.dismiss(None)


__all__ = [
    "SentinelMascotPanel",
    "ImmunityMetricsPanel",
    "FindingItem",
    "FindingsListView",
    "CodeDiffTabs",
    "ApiKeyModal",
]
