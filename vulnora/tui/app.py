"""
Textual Application for Vulnora AI.

Provides the responsive, keyboard-driven terminal dashboard:
- [C]: Copy sanitized surgical prompt / diff to clipboard.
- [A]: Auto-fix selected vulnerability via Cloud AI & AST Verification Loop.
- [R]: Re-scan repository with concurrent 6-scanner orchestrator.
- [D]: Cycle through detail tabs (Snippet, Prompt, Diff, Guardrail).
- [G]: Guard action (proceed with push if clean or approve override).
- [Q]: Quit application (returns exit code 1 if blocking findings remain in guard mode).
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any, List, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Footer, Header, Static

from vulnora.core.config import (
    VulnoraConfig,
    get_vulnora_dir,
    load_config,
    load_local_credentials,
)
from vulnora.core.models import Finding, RemediationProposal, Severity
from vulnora.engine.cloud_ai import CloudAIClient
from vulnora.engine.redactor import SecretRedactor
from vulnora.engine.verifier import FixVerifier
from vulnora.immune.memory_store import ImmuneMemoryStore
from vulnora.scanners.runner import ScannerOrchestrator
from vulnora.tui.widgets import (
    ApiKeyModal,
    CodeDiffTabs,
    FindingsListView,
    ImmunityMetricsPanel,
    SentinelMascotPanel,
)


def copy_to_clipboard(text: str) -> bool:
    """Safely copies text to system clipboard with zero crash risk."""
    if not text:
        return False
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False


class VulnoraTUIApp(App[int]):
    """
    Vulnora AI Interactive Terminal User Interface.
    Split-pane keyboard-driven security command center.
    """

    TITLE = "Vulnora AI — Autonomous Codebase Security Sentinel"
    SUB_TITLE = "[C]opy [A]uto-Fix [K]ey [R]e-scan [D]etails [G]uard [Q]uit"

    CSS = """
    Screen {
        layout: vertical;
        background: #0f141c;
    }

    #top-row {
        layout: horizontal;
        height: 9;
        dock: top;
        margin-bottom: 1;
    }

    #mascot-panel {
        width: 50%;
        height: 100%;
        border: solid cyan;
    }

    #metrics-panel {
        width: 50%;
        height: 100%;
        border: solid cyan;
    }

    #main-split {
        layout: horizontal;
        height: 1fr;
    }

    #findings-pane {
        width: 45%;
        height: 100%;
        border-right: solid $primary;
        padding-right: 1;
    }

    #findings-title {
        height: 1;
        dock: top;
        background: #182232;
        color: cyan;
        text-align: center;
        text-style: bold;
    }

    #findings-list {
        height: 1fr;
    }

    #details-pane {
        width: 55%;
        height: 100%;
        padding-left: 1;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: #141c2b;
        color: #94a3b8;
        padding-left: 1;
    }
    """

    BINDINGS = [
        Binding("c", "copy_content", "Copy (Zero-Secret)", show=True),
        Binding("a", "auto_fix", "Auto-Fix (Cloud AI)", show=True),
        Binding("k", "configure_api_key", "API Key", show=True),
        Binding("r", "rescan", "Re-Scan Fleet", show=True),
        Binding("d", "toggle_details", "Next Tab", show=True),
        Binding("g", "guard_action", "Guard/Proceed", show=True),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        findings: Optional[List[Finding]] = None,
        is_guard_mode: bool = False,
        protected_branch: Optional[str] = "main",
        auto_scan_on_mount: bool = True,
        config: Optional[VulnoraConfig] = None,
    ) -> None:
        super().__init__()
        self.target_dir = (target_dir or Path.cwd()).resolve()
        self.initial_findings = findings
        self.is_guard_mode = is_guard_mode
        self.protected_branch = protected_branch or "main"
        self.auto_scan_on_mount = auto_scan_on_mount
        self.config = config or load_config(base_path=self.target_dir)

        self.session_api_key: Optional[str] = None
        self.mock_ai: bool = False
        self.redactor = SecretRedactor()

        # Components
        self.memory_store = ImmuneMemoryStore(
            memory_path=get_vulnora_dir(self.target_dir) / "memory.json"
        )
        self.mascot_panel = SentinelMascotPanel(
            initial_state="VIGILANT" if not findings else "ALERT",
            message="Git Push Interception Active" if is_guard_mode else "Interactive Sentinel Ready",
        )
        self.metrics_panel = ImmunityMetricsPanel(
            antibody_count=self.memory_store.count(),
            hit_rate=self.memory_store.calculate_hit_rate(),
            protected_branch=self.protected_branch,
            scanner_count=len(self.config.scanners.enabled),
        )
        self.findings_view = FindingsListView(findings=findings or [])
        self.details_tabs = CodeDiffTabs(target_root=self.target_dir)
        self.status_message = "Ready. Press [R] to scan or [A] to auto-fix selected finding."
        self.status_bar = Static(self.status_message, id="status-bar")

        self.exit_code: int = 0

    def set_status(self, message: str) -> None:
        """Updates internal status message and status bar widget."""
        self.status_message = message
        if hasattr(self, "status_bar"):
            self.status_bar.update(message)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top-row"):
            yield self.mascot_panel
            yield self.metrics_panel
        with Container(id="main-split"):
            yield self.findings_view
            yield self.details_tabs
        yield self.status_bar
        yield Footer()

    def on_mount(self) -> None:
        """Called when TUI widgets are mounted into the terminal."""
        self._refresh_metrics()
        if self.initial_findings is not None:
            self.findings_view.set_findings(self.initial_findings)
            self._update_mascot_for_findings(self.initial_findings)
        elif self.auto_scan_on_mount:
            self.action_rescan()

    def on_findings_list_view_finding_selected(
        self, event: FindingsListView.FindingSelected
    ) -> None:
        """Handles finding selection changes and updates details tabs."""
        self.details_tabs.update_finding(event.finding)
        self.set_status(
            f"Inspecting [{event.finding.severity.value}] {event.finding.rule_id} in {Path(event.finding.file_path).name}"
        )

    # -------------------------------------------------------------------------
    # Keybinding Action Handlers
    # -------------------------------------------------------------------------

    def action_copy_content(self) -> None:
        """[C] Copies sanitized prompt or diff to clipboard (Zero-Secret guaranteed)."""
        content = self.details_tabs.get_copyable_content()
        if not content:
            self.notify("No active content to copy.", severity="warning")
            return

        copied = copy_to_clipboard(content)
        if copied:
            self.notify("✔ Copied to clipboard! (Zero secrets guaranteed)", title="Vulnora AI", severity="information")
            self.set_status("Copied current tab content to clipboard (Zero-Secret Scrubbed).")
        else:
            self.notify("Content sanitized. (Clipboard daemon unavailable)", title="Vulnora AI", severity="warning")
            self.set_status("Content sanitized (Clipboard daemon unavailable).")

    def get_active_api_key(self) -> Optional[str]:
        """Resolves active Gemini API key from session, environment, local credentials, or config."""
        if self.session_api_key:
            return self.session_api_key
        for env_var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            val = os.environ.get(env_var)
            if val and val.strip():
                return val.strip()
        local_creds = load_local_credentials(self.target_dir)
        for key_name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            val = local_creds.get(key_name)
            if val and val.strip():
                return val.strip()
        if self.config.ai.api_key:
            return self.config.ai.api_key.strip()
        return None

    def action_configure_api_key(self, callback_after: Optional[Any] = None) -> None:
        """[K] Displays modal dialog for configuring Gemini API key."""
        def _on_key_dismiss(key: Optional[str]) -> None:
            if key:
                self.session_api_key = key
                self.redactor.add_custom_secret(key)
                if hasattr(self.details_tabs, "redactor"):
                    self.details_tabs.redactor.add_custom_secret(key)
                self.set_status("Gemini API key configured successfully.")
                self.notify("Gemini API key saved.", title="Vulnora AI", severity="information")
                self._refresh_metrics()
                if callback_after:
                    callback_after()
            else:
                self.set_status("API key entry cancelled.")

        modal = ApiKeyModal(target_dir=self.target_dir, initial_key=self.get_active_api_key())
        self.push_screen(modal, _on_key_dismiss)

    def action_auto_fix(self) -> None:
        """[A] Invokes Cloud AI and FixVerifier loop on selected finding."""
        finding = self.findings_view.get_selected_finding()
        if not finding:
            self.notify("Please select a finding from the list first.", severity="warning")
            return

        active_key = self.get_active_api_key()
        if not active_key and not getattr(self, "mock_ai", False):
            self.notify("Gemini API key required for AI auto-fix. Please enter your key.", severity="information")
            self.action_configure_api_key(callback_after=lambda: self._execute_auto_fix(finding))
            return

        self._execute_auto_fix(finding)

    def _execute_auto_fix(self, finding: Finding) -> None:
        """Begins remediation synthesis for finding."""
        self.mascot_panel.set_state("REMEDIATING", f"Synthesizing surgical patch for {finding.rule_id}...")
        self.set_status(f"[*] Invoking Cloud AI remediation for {finding.rule_id}...")
        self.run_background_fix(finding)

    def action_rescan(self) -> None:
        """[R] Triggers background multi-scanner execution."""
        self.mascot_panel.set_state("SCANNING", "Running 6 concurrent scanners...")
        self.set_status("[*] Re-scanning repository with concurrent scanners...")
        self.run_background_scan()

    def action_toggle_details(self) -> None:
        """[D] Cycles through detail tab panes."""
        self.details_tabs.next_tab()

    def action_guard_action(self) -> None:
        """[G] In guard mode, approves push or proceeds if clean."""
        critical_count = sum(
            1 for f in self.findings_view.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        if critical_count > 0 and self.config.git.block_on_critical:
            self.notify(
                f"Blocked: {critical_count} Critical/High findings remain unaddressed.",
                title="Vulnora Pre-Push Guard",
                severity="error",
            )
            self.set_status(f"[!] Guard blocked: {critical_count} critical/high findings remain.")
            return

        self.exit_code = 0
        self.set_status("[✔] Guard approved. Proceeding with Git push...")
        self.exit(0)

    def action_quit_app(self) -> None:
        """[Q] Quits the application."""
        critical_count = sum(
            1 for f in self.findings_view.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        if self.is_guard_mode and critical_count > 0 and self.config.git.block_on_critical:
            self.exit_code = 1
        else:
            self.exit_code = 0
        self.exit(self.exit_code)

    # -------------------------------------------------------------------------
    # Background Workers (Non-blocking Thread Safety)
    # -------------------------------------------------------------------------

    @work(thread=True)
    def run_background_scan(self) -> None:
        """Executes ScannerOrchestrator without blocking the Textual event loop."""
        try:
            orchestrator = ScannerOrchestrator(config=self.config)
            result = orchestrator.run_scanners(
                target_path=self.target_dir,
                is_full_scan=not self.is_guard_mode,
            )
            findings = result.findings
            self.call_from_thread(self._on_scan_completed, findings, None)
        except Exception as exc:
            self.call_from_thread(self._on_scan_completed, [], str(exc))

    def _on_scan_completed(self, findings: List[Finding], error: Optional[str]) -> None:
        """Callback executed on main UI thread after scan finishes."""
        if error:
            self.mascot_panel.set_state("ALERT", f"Scan error: {error}")
            self.set_status(f"[-] Scan encountered an error: {error}")
            return

        self.findings_view.set_findings(findings)
        self._update_mascot_for_findings(findings)
        self._refresh_metrics()
        self.set_status(f"[✔] Scan complete: {len(findings)} finding(s) detected.")

    @work(thread=True)
    def run_background_fix(self, finding: Finding) -> None:
        """Executes Cloud AI generation and FixVerifier verification loop."""
        try:
            client = CloudAIClient(
                provider=self.config.ai.provider,
                model=self.config.ai.model,
                timeout_seconds=self.config.ai.timeout_seconds,
                api_key=self.get_active_api_key(),
            )
            from vulnora.engine.prompt_compiler import SurgicalPromptCompiler
            compiler = SurgicalPromptCompiler(target_root=self.target_dir, immune_store=self.memory_store)
            prompt = compiler.compile(finding)
            proposal = client.generate_remediation(prompt)

            verifier = FixVerifier(
                target_root=self.target_dir,
                config=self.config,
                immune_store=self.memory_store,
            )
            res = verifier.verify_and_learn(finding=finding, proposal=proposal, auto_rollback=True)
            self.call_from_thread(self._on_fix_completed, finding, proposal, res, None)
        except Exception as exc:
            self.call_from_thread(self._on_fix_completed, finding, None, None, str(exc))

    def _on_fix_completed(
        self,
        finding: Finding,
        proposal: Optional[RemediationProposal],
        res: Any,
        error: Optional[str],
    ) -> None:
        """Callback executed on main UI thread after remediation finishes."""
        if error:
            self.mascot_panel.set_state("ALERT", f"Remediation failed: {error[:60]}")
            self.set_status(f"[-] Remediation failed: {error}")
            self.notify(f"Remediation error: {error}", severity="error")
            return

        if res and res.success:
            self.mascot_panel.set_state("VACCINATED", f"Vaccinated {finding.rule_id}! Verified clean.")
            self.details_tabs.update_finding(
                finding=finding,
                proposal=proposal,
                diff=res.diff_unified,
                antibody_id=res.antibody_id,
            )
            # Remove resolved finding from list
            remaining = [f for f in self.findings_view.findings if f.compute_fingerprint() != finding.compute_fingerprint()]
            self.findings_view.set_findings(remaining)
            self._refresh_metrics()
            self.set_status(f"[✔] Verified clean: Antibody {res.antibody_id} saved to memory.")
            self.notify(f"Vaccinated {finding.rule_id}! Verified clean.", severity="information")
        else:
            msg = res.message if res else "Verification failed"
            self.mascot_panel.set_state("ALERT", f"Verification rolled back: {msg}")
            self.set_status(f"[!] Fix rolled back: {msg}")
            self.notify(f"Patch verification failed: {msg}", severity="warning")

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    def _update_mascot_for_findings(self, findings: List[Finding]) -> None:
        critical_count = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        if critical_count > 0:
            self.mascot_panel.set_state("ALERT", f"{critical_count} Critical/High Threat(s)")
        elif findings:
            self.mascot_panel.set_state("ALERT", f"{len(findings)} Medium/Low Finding(s)")
        else:
            self.mascot_panel.set_state("VIGILANT", "0 Vulnerabilities (Codebase Clean)")

    def _refresh_metrics(self) -> None:
        key = self.get_active_api_key()
        ai_status = "[bold green]Ready (Key Loaded)[/]" if key else "[yellow]Offline / Prompt-Only (Press [K])[/]"
        self.metrics_panel.update_metrics(
            antibody_count=self.memory_store.count(),
            hit_rate=self.memory_store.calculate_hit_rate(),
            protected_branch=self.protected_branch,
            scanner_count=len(self.config.scanners.enabled),
            status_label="BLOCKED" if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings_view.findings) else "ACTIVE",
            ai_status=ai_status,
        )


def launch_tui(
    target_dir: Optional[Path] = None,
    findings: Optional[List[Finding]] = None,
    is_guard_mode: bool = False,
    protected_branch: Optional[str] = "main",
    config: Optional[VulnoraConfig] = None,
) -> int:
    """
    Launches the Vulnora interactive Textual TUI and returns the exit code.
    """
    app = VulnoraTUIApp(
        target_dir=target_dir,
        findings=findings,
        is_guard_mode=is_guard_mode,
        protected_branch=protected_branch,
        auto_scan_on_mount=(findings is None),
        config=config,
    )
    app.run()
    return getattr(app, "exit_code", 0)
