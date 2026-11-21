"""
Unit tests for Textual TUI widgets (`vulnora.tui.widgets`).
"""

from pathlib import Path
import pytest
from rich.console import Console

from vulnora.core.models import Finding, RemediationProposal, Severity
from vulnora.tui.widgets import (
    CodeDiffTabs,
    FindingItem,
    FindingsListView,
    ImmunityMetricsPanel,
    SentinelMascotPanel,
)


class TestSentinelMascotPanel:
    """Tests for Sentinel mascot states and rich panel rendering."""

    def test_default_vigilant_state(self):
        panel = SentinelMascotPanel()
        assert panel.state == "VIGILANT"
        rendered = panel.render()
        text = str(rendered.renderable)
        assert "VIGILANT (CLEAN)" in text
        assert "Autonomous Protection Active" in text

    def test_state_transitions(self):
        panel = SentinelMascotPanel()

        panel.set_state("SCANNING", "Analyzing 12 diffs")
        assert panel.state == "SCANNING"
        text = str(panel.render().renderable)
        assert "INSPECTING CODEBASE" in text
        assert "Status: Analyzing 12 diffs" in text

        panel.set_state("ALERT", "2 High findings")
        assert panel.state == "ALERT"
        text = str(panel.render().renderable)
        assert "THREATS DETECTED" in text

        panel.set_state("REMEDIATING")
        assert panel.state == "REMEDIATING"
        text = str(panel.render().renderable)
        assert "SYNTHESIZING FIX" in text

        panel.set_state("VACCINATED")
        assert panel.state == "VACCINATED"
        text = str(panel.render().renderable)
        assert "SELF-VACCINATED" in text


class TestImmunityMetricsPanel:
    """Tests for real-time telemetry panel formatting."""

    def test_metrics_formatting(self):
        panel = ImmunityMetricsPanel(
            antibody_count=12,
            hit_rate=95.5,
            protected_branch="production",
            scanner_count=6,
        )
        assert panel.antibody_count == 12
        assert panel.hit_rate == 95.5
        assert panel.protected_branch == "production"

        console = Console()
        with console.capture() as capture:
            console.print(panel.render())
        text = capture.get()
        assert "12 Antibodies Stored" in text
        assert "95.5% Instant Interception" in text
        assert "production (Protected)" in text
        assert "6/6 Enabled & Gated" in text

    def test_update_metrics(self):
        panel = ImmunityMetricsPanel()
        panel.update_metrics(antibody_count=20, hit_rate=100.0, status_label="BLOCKED")
        assert panel.antibody_count == 20
        assert panel.hit_rate == 100.0
        assert panel.status_label == "BLOCKED"


class TestFindingsListView:
    """Tests for findings list and finding items."""

    @pytest.fixture
    def sample_findings(self) -> list[Finding]:
        return [
            Finding(
                rule_id="B605",
                scanner_name="bandit",
                severity=Severity.HIGH,
                title="Command Injection",
                description="Use of os.system detected",
                file_path="service.py",
                line_number=42,
            ),
            Finding(
                rule_id="AWS_KEY",
                scanner_name="gitleaks",
                severity=Severity.CRITICAL,
                title="Secret Exposure",
                description="Hardcoded AWS Access Key",
                file_path="config.py",
                line_number=10,
            ),
        ]

    def test_finding_item_render(self, sample_findings):
        item_high = FindingItem(sample_findings[0])
        rendered_high = item_high.render().plain
        assert "HIGH" in rendered_high
        assert "B605" in rendered_high
        assert "service.py:42" in rendered_high
        assert "bandit" in rendered_high

        item_crit = FindingItem(sample_findings[1])
        rendered_crit = item_crit.render().plain
        assert "CRITICAL" in rendered_crit
        assert "AWS_KEY" in rendered_crit

    def test_list_view_population_and_clearing(self, sample_findings):
        view = FindingsListView(findings=sample_findings)
        assert len(view.findings) == 2
        assert view.findings[0].rule_id == "B605"

        view.clear_findings()
        assert len(view.findings) == 0


class TestCodeDiffTabs:
    """Tests for multi-tab code and diff inspector with secret scrubbing."""

    def test_snippet_extraction_and_secret_redaction(self, tmp_path: Path):
        code_file = tmp_path / "app.py"
        code_file.write_text(
            "import os\n"
            "AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "def run_job(cmd):\n"
            "    os.system(cmd)\n",
            encoding="utf-8",
        )

        finding = Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Insecure Shell Execution",
            description="Direct shell execution via os.system",
            file_path="app.py",
            line_number=4,
        )

        tabs = CodeDiffTabs(target_root=tmp_path)
        tabs.update_finding(finding)

        # Snippet text must be scrubbed: raw secret MUST NOT appear
        assert "run_job" in tabs.snippet_text
        assert "os.system(cmd)" in tabs.snippet_text
        assert "wJalrXUtnFEMI" not in tabs.snippet_text
        assert "***REDACTED***" in tabs.snippet_text

    def test_update_finding_with_proposal_and_diff(self, tmp_path: Path):
        finding = Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Command Injection",
            description="os.system call",
            file_path="job.py",
            line_number=5,
        )
        proposal = RemediationProposal(
            finding_id="f-001",
            rule_id="B605",
            file_path="job.py",
            root_cause="Direct shell string execution",
            explanation="Use subprocess.run with argument list",
            replacement_code="subprocess.run(['backup'], shell=False)",
            agents_rule="Always use subprocess.run with shell=False.",
        )
        diff_text = (
            "--- a/job.py\n"
            "+++ b/job.py\n"
            "@@ -5,1 +5,1 @@\n"
            "-os.system('backup')\n"
            "+subprocess.run(['backup'], shell=False)\n"
        )

        tabs = CodeDiffTabs(target_root=tmp_path)
        tabs.update_finding(
            finding=finding,
            proposal=proposal,
            diff=diff_text,
            antibody_id="ab_B605_test123",
        )

        assert tabs.current_finding == finding
        assert tabs.current_proposal == proposal
        assert tabs.current_diff == diff_text
        assert tabs.current_antibody == "ab_B605_test123"

        copy_text = tabs.get_copyable_content()
        assert isinstance(copy_text, str)
        assert "subprocess.run" in copy_text or "os.system" in copy_text or len(copy_text) > 0
