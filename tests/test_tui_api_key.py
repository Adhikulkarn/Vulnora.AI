"""
Unit and integration tests for In-TUI Gemini API Key entry, persistence, and zero-secret scrubbing.
"""

from pathlib import Path
import stat
import pytest
from textual.app import App
from textual.widgets import Input

from vulnora.core.config import load_local_credentials
from vulnora.core.models import Finding, Severity
from vulnora.engine.redactor import SecretRedactor
from vulnora.tui.app import VulnoraTUIApp
from vulnora.tui.widgets import ApiKeyModal


class ModalTestApp(App[str]):
    """Wrapper app to test ApiKeyModal in isolation."""

    def __init__(self, target_dir: Path, initial_key: str = ""):
        super().__init__()
        self.target_dir = target_dir
        self.initial_key = initial_key
        self.modal_result = None

    def on_mount(self) -> None:
        def on_dismiss(result):
            self.modal_result = result

        self.push_screen(
            ApiKeyModal(target_dir=self.target_dir, initial_key=self.initial_key),
            on_dismiss,
        )


def test_redactor_custom_secret():
    """Verifies SecretRedactor catches custom registered keys and Gemini keys."""
    redactor = SecretRedactor()
    test_key = "AQ.my-secret-key-12345678901234567890"

    # Pre-registration pattern check
    assert redactor.is_secret(test_key)

    custom_token = "my_custom_secret_token_xyz123"
    assert not redactor.is_secret(custom_token)

    redactor.add_custom_secret(custom_token)
    assert redactor.is_secret(f"Authorization: {custom_token}")

    res = redactor.redact(f"Bearer {custom_token} and {test_key}")
    assert custom_token not in res.redacted_text
    assert test_key not in res.redacted_text
    assert "***REDACTED***" in res.redacted_text


@pytest.mark.anyio
async def test_api_key_modal_session_save(tmp_path: Path):
    """Verifies saving API key for session does not write file and returns key."""
    app = ModalTestApp(target_dir=tmp_path)
    async with app.run_test() as pilot:
        input_widget = app.screen.query_one("#api-key-input", Input)
        input_widget.value = "AQ.test-session-key-12345678901234567890"

        # Click "Save for Session"
        await pilot.click("#btn-session")

        assert app.modal_result == "AQ.test-session-key-12345678901234567890"
        cred_file = tmp_path / ".vulnora" / "credentials.local"
        assert not cred_file.exists()


@pytest.mark.anyio
async def test_api_key_modal_local_save(tmp_path: Path):
    """Verifies saving locally creates .vulnora/credentials.local with 0o600 permissions."""
    app = ModalTestApp(target_dir=tmp_path)
    async with app.run_test() as pilot:
        input_widget = app.screen.query_one("#api-key-input", Input)
        test_val = f"{'AIza'}SyTestLocalKey1234567890123456789"
        input_widget.value = test_val

        # Click "Save Locally (.vulnora)"
        await pilot.click("#btn-local")

        assert app.modal_result == test_val
        cred_file = tmp_path / ".vulnora" / "credentials.local"
        assert cred_file.is_file()
        content = cred_file.read_text(encoding="utf-8")
        assert test_val in content

        # Check permissions: 0o600
        mode = stat.S_IMODE(cred_file.stat().st_mode)
        assert mode == 0o600

        # Check gitignore includes credentials.local
        gitignore_file = tmp_path / ".gitignore"
        assert gitignore_file.is_file()
        assert ".vulnora/credentials.local" in gitignore_file.read_text(encoding="utf-8")


@pytest.mark.anyio
async def test_api_key_modal_cancel(tmp_path: Path):
    """Verifies cancel button dismisses modal with None."""
    app = ModalTestApp(target_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.click("#btn-cancel")
        assert app.modal_result is None


@pytest.mark.anyio
async def test_tui_k_binding_opens_modal(tmp_path: Path, monkeypatch):
    """Verifies pressing [K] opens ApiKeyModal and updates app session state."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=[],
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        assert app.session_api_key is None
        assert "Offline" in str(app.metrics_panel.ai_status)

        # Press [K]
        await pilot.press("k")
        assert isinstance(app.screen, ApiKeyModal)

        # Set key
        input_widget = app.screen.query_one("#api-key-input", Input)
        input_widget.value = "AQ.interactive-key-12345678901234567890"

        await pilot.click("#btn-session")

        assert app.session_api_key == "AQ.interactive-key-12345678901234567890"
        assert app.get_active_api_key() == "AQ.interactive-key-12345678901234567890"
        assert "Ready" in str(app.metrics_panel.ai_status)
        assert "configured" in app.status_message.lower()


@pytest.mark.anyio
async def test_tui_auto_fix_prompts_modal_when_key_missing(tmp_path: Path, monkeypatch):
    """Verifies pressing [A] when no API key is present automatically opens ApiKeyModal."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    finding = Finding(
        rule_id="B605",
        scanner_name="bandit",
        severity=Severity.HIGH,
        title="Command Injection",
        description="os.system call detected",
        file_path="service.py",
        line_number=10,
    )

    app = VulnoraTUIApp(
        target_dir=tmp_path,
        findings=[finding],
        auto_scan_on_mount=False,
    )

    async with app.run_test() as pilot:
        assert app.session_api_key is None

        # Press [A]
        await pilot.press("a")

        # Modal should be pushed
        assert isinstance(app.screen, ApiKeyModal)

        # Cancel modal
        await pilot.press("escape")
        assert not isinstance(app.screen, ApiKeyModal)
        assert app.session_api_key is None
