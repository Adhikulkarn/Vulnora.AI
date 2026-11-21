"""
Unit tests for Cloud AI client (`vulnora.engine.cloud_ai`).
"""

import json
from pathlib import Path
import pytest

from vulnora.core.models import Finding, Severity, SurgicalPrompt
from vulnora.engine.cloud_ai import CloudAIClient, CloudAIError


class TestCloudAIClient:
    """Tests for multi-provider Cloud AI configuration and JSON parsing."""

    @pytest.fixture
    def sample_prompt(self) -> SurgicalPrompt:
        return SurgicalPrompt(
            finding_id="test-find-001",
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            file_path="service.py",
            line_number=10,
            enclosing_symbol="execute_command",
            vulnerable_code_block="def execute_command(command):\n    os.system(command)",
            compiled_markdown="# Surgical Fix Prompt: Insecure Command Execution\n\nos.system(command)",
        )

    def test_client_init_defaults(self):
        client = CloudAIClient(provider="gemini")
        assert client.provider == "gemini"
        assert client.model == "gemini-2.5-flash"

        client_groq = CloudAIClient(provider="groq")
        assert client_groq.provider == "groq"
        assert "llama" in client_groq.model

        client_ollama = CloudAIClient(provider="ollama")
        assert client_ollama.provider == "ollama"
        assert "qwen" in client_ollama.model

    def test_model_resolution_cascade_and_prefix(self):
        # Auto cascade with gemini user_model
        client = CloudAIClient(provider="auto", model="gemini-3.8-flash")
        assert client._resolve_model("gemini") == "gemini-3.8-flash"
        assert client._resolve_model("groq") == "llama-3.1-8b-instant"

        # Explicit provider
        client_gemini = CloudAIClient(provider="gemini", model="gemini-2.5-pro")
        assert client_gemini.model == "gemini-2.5-pro"

    def test_dry_run_proposal_generation(self, sample_prompt: SurgicalPrompt):
        client = CloudAIClient(provider="gemini")
        proposal = client.generate_remediation(sample_prompt, dry_run=True)

        assert proposal.finding_id == sample_prompt.finding_id
        assert proposal.rule_id == sample_prompt.rule_id
        assert proposal.file_path == sample_prompt.file_path
        assert "subprocess" in proposal.replacement_code
        assert proposal.root_cause != ""
        assert proposal.agents_rule != ""

    def test_parse_clean_json_response(self, sample_prompt: SurgicalPrompt):
        client = CloudAIClient(provider="gemini")
        raw_json = json.dumps({
            "root_cause": "Direct string interpolation into os.system.",
            "explanation": "Use subprocess.run with argument list to bypass shell parsing.",
            "replacement_code": "def execute_command(command):\n    subprocess.run(['echo', command], shell=False)",
            "agents_rule": "Never pass unvalidated user input to os.system.",
        })

        proposal = client._parse_json_response(raw_json, sample_prompt)
        assert proposal.root_cause == "Direct string interpolation into os.system."
        assert "subprocess.run" in proposal.replacement_code
        assert proposal.agents_rule == "Never pass unvalidated user input to os.system."

    def test_parse_markdown_wrapped_json_response(self, sample_prompt: SurgicalPrompt):
        client = CloudAIClient(provider="gemini")
        raw_text = """```json
{
  "root_cause": "Dangerous shell execution.",
  "explanation": "Replaced with safe list call.",
  "replacement_code": "subprocess.run([cmd], shell=False)",
  "agents_rule": "Always avoid shell=True."
}
```"""
        proposal = client._parse_json_response(raw_text, sample_prompt)
        assert proposal.root_cause == "Dangerous shell execution."
        assert proposal.replacement_code == "subprocess.run([cmd], shell=False)"
        assert proposal.agents_rule == "Always avoid shell=True."

    def test_parse_invalid_json_raises_error(self, sample_prompt: SurgicalPrompt):
        client = CloudAIClient(provider="gemini")
        invalid_text = "Here is your fix: please replace line 10 with subprocess."
        with pytest.raises(CloudAIError) as exc_info:
            client._parse_json_response(invalid_text, sample_prompt)
        assert "Failed to parse LLM response as JSON" in str(exc_info.value)

    def test_missing_api_key_raises_error(self, sample_prompt: SurgicalPrompt, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = CloudAIClient(provider="gemini", api_key=None)
        with pytest.raises(CloudAIError) as exc_info:
            client.generate_remediation(sample_prompt, dry_run=False)
        assert "failed" in str(exc_info.value).lower()

    def test_cascade_ordering_and_providers(self):
        client = CloudAIClient(provider="auto")
        assert client.provider == "auto"
