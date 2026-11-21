"""
Async integration tests for Vulnora interactive Textual TUI (`VulnoraTUIApp`).
Tests keyboard navigation, split-pane layout, workers, and [C]/[A]/[R]/[D]/[G]/[Q] actions.
"""

from pathlib import Path
import pytest

from vulnora.core.config import VulnoraConfig
from vulnora.core.models import Finding, RemediationProposal, Severity, VerificationResult
from vulnora.tui.app import VulnoraTUIApp


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Insecure Shell Call",
            description="os.system call detected",
            file_path="service.py",
            line_number=10,
        ),
        Finding(
            rule_id="CWE-89",
            scanner_name="semgrep",
            severity=Severity.MEDIUM,
            title="SQL Injection",
            description="Unsanitized query string",
            file_path="db.py",
            line_number=25,
        ),
    ]


@pytest.mark.anyio
async def test_tui_app_mount_and_widgets(sample_findings, tmp_path: Path):
    """Verifies that the split-pane layout and all sentinel panels mount correctly."""
    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=sample_findings,
        is_guard_mode=False,
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        assert app.is_mounted
        assert app.query_one("#mascot-panel") is not None
        assert app.query_one("#metrics-panel") is not None
        assert app.query_one("#findings-pane") is not None
        assert app.query_one("#details-pane") is not None
        assert app.query_one("#status-bar") is not None

        # Findings view populated
        assert len(app.findings_view.findings) == 2


@pytest.mark.anyio
async def test_tui_details_tab_toggle(sample_findings, tmp_path: Path):
    """Verifies [D] key cycles through CodeDiffTabs panes."""
    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=sample_findings,
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        initial_tab = app.details_tabs._tabbed_content.active
        assert initial_tab == "tab-snippet"

        # Press [D] to cycle to next tab
        await pilot.press("d")
        assert app.details_tabs._tabbed_content.active == "tab-prompt"

        await pilot.press("d")
        assert app.details_tabs._tabbed_content.active == "tab-diff"

        await pilot.press("d")
        assert app.details_tabs._tabbed_content.active == "tab-rule"

        await pilot.press("d")
        assert app.details_tabs._tabbed_content.active == "tab-snippet"


@pytest.mark.anyio
async def test_tui_copy_content_action(sample_findings, tmp_path: Path, monkeypatch):
    """Verifies [C] key triggers zero-secret clipboard copy."""
    copied_texts = []

    def mock_copy(text):
        copied_texts.append(text)

    monkeypatch.setattr("pyperclip.copy", mock_copy, raising=False)

    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=sample_findings,
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        await pilot.press("c")
        assert "Copied" in app.status_message


@pytest.mark.anyio
async def test_tui_guard_action_clean(tmp_path: Path):
    """Verifies [G] in guard mode allows push when 0 blocking findings exist."""
    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=[],
        is_guard_mode=True,
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        await pilot.press("g")
        assert app.exit_code == 0


@pytest.mark.anyio
async def test_tui_guard_action_blocked_then_quit(sample_findings, tmp_path: Path):
    """Verifies [G] blocks push when HIGH/CRITICAL findings exist, and [Q] exits with code 1."""
    config = VulnoraConfig()
    config.git.block_on_critical = True

    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=sample_findings,  # Contains HIGH severity B605
        is_guard_mode=True,
        auto_scan_on_mount=False,
        config=config,
    )

    async with app.run_test() as pilot:
        # [G] should block
        await pilot.press("g")
        assert "Guard blocked" in app.status_message

        # [Q] should exit with blocking code 1
        await pilot.press("q")
        assert app.exit_code == 1


@pytest.mark.anyio
async def test_tui_quit_clean(tmp_path: Path):
    """Verifies [Q] exits with code 0 outside guard mode."""
    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=[],
        is_guard_mode=False,
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        await pilot.press("q")
        assert app.exit_code == 0


@pytest.mark.anyio
async def test_tui_remediation_storage_and_tab_switch(sample_findings, tmp_path: Path):
    """Verifies that successful remediation stores diff + explanation, switches tab, and preserves it on selection."""
    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=sample_findings,
        auto_scan_on_mount=False,
    )

    finding = sample_findings[0]
    proposal = RemediationProposal(
        finding_id="f-001",
        rule_id="B605",
        file_path="service.py",
        root_cause="Use of shell string execution",
        explanation="Safely parse command args with shlex",
        replacement_code="subprocess.run(['backup'], shell=False)",
        agents_rule="Always use subprocess.run with shell=False.",
        provider="gemini",
        model="gemini-2.5-flash",
    )
    diff_text = (
        "--- a/service.py\n"
        "+++ b/service.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-os.system('backup')\n"
        "+subprocess.run(['backup'], shell=False)\n"
    )
    res = VerificationResult(
        success=True,
        file_path="service.py",
        scanner_name="bandit",
        rule_id="B605",
        diff_unified=diff_text,
        antibody_id="ab_B605_test123",
        message="Verified clean.",
    )

    async with app.run_test() as pilot:
        # Initial tab is snippet
        assert app.details_tabs._tabbed_content.active == "tab-snippet"

        # Simulate completion of auto-fix
        app._on_fix_completed(finding=finding, proposal=proposal, res=res, error=None)

        # 1. Verify stored in remediations dict
        f_key = finding.fingerprint or finding.compute_fingerprint()
        assert f_key in app.remediations
        stored = app.remediations[f_key]
        assert stored["root_cause"] == "Use of shell string execution"
        assert stored["explanation"] == "Safely parse command args with shlex"
        assert stored["diff"] == diff_text
        assert stored["provider"] == "gemini"
        assert stored["model"] == "gemini-2.5-flash"

        # 2. Verify automatically switched to tab-diff
        assert app.details_tabs._tabbed_content.active == "tab-diff"

        # 3. Verify formatted explanation + diff is displayed (no placeholder)
        diff_display_text = app.details_tabs.diff_text
        assert "No remediation generated yet" not in diff_display_text
        assert "Root Cause:" in diff_display_text
        assert "Use of shell string execution" in diff_display_text
        assert "Explanation:" in diff_display_text
        assert "Safely parse command args with shlex" in diff_display_text
        assert "subprocess.run" in diff_display_text
        assert "gemini-2.5-flash" in diff_display_text

        # 4. Verify finding is marked resolved
        assert f_key in app.findings_view.resolved_fingerprints

        # 5. Verify selecting another finding and then re-selecting preserves stored remediation
        second_finding = sample_findings[1]
        app.findings_view.post_message(app.findings_view.FindingSelected(second_finding))
        await pilot.pause()

        # Second finding has no remediation
        assert "No remediation generated yet" in app.details_tabs.diff_text

        # Re-select first finding
        app.findings_view.post_message(app.findings_view.FindingSelected(finding))
        await pilot.pause()

        # Stored remediation is preserved and rendered
        assert "No remediation generated yet" not in app.details_tabs.diff_text
        assert "Use of shell string execution" in app.details_tabs.diff_text
        assert "subprocess.run" in app.details_tabs.diff_text
