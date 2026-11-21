"""
Unit tests for the Surgical Fix-Prompt Compiler (`vulnora.engine.prompt_compiler`).
"""

import json
from pathlib import Path
import pytest

from vulnora.cli import build_parser, main
from vulnora.core.models import Finding, ImmuneRecord, ImmunityTier, Severity, SurgicalPrompt
from vulnora.engine.prompt_compiler import SurgicalPromptCompiler
from vulnora.engine.redactor import REDACTION_MARKER, SecretRedactor
from vulnora.immune.ast_normalizer import ASTNormalizer
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestSurgicalPromptCompiler:
    """Tests for AST context extraction, zero-secret egress, and prompt compilation."""

    @pytest.fixture
    def sample_python_file(self, tmp_path: Path) -> Path:
        code = """import os
import subprocess

def benign_worker():
    return "ok"

def run_user_command(command: str):
    # Vulnerable line 8: os.system with user command
    os.system(command)
    return True

def cleanup():
    pass
"""
        file_path = tmp_path / "app.py"
        file_path.write_text(code, encoding="utf-8")
        return file_path

    @pytest.fixture
    def finding(self, sample_python_file: Path) -> Finding:
        return Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Starting a process with a shell: possible injection",
            description="os.system() call detected. This can lead to arbitrary command execution if user input is unvalidated.",
            file_path=sample_python_file.name,
            line_number=8,
            snippet="os.system(command)",
            remediation="Use subprocess.run(['cmd', arg], shell=False) instead.",
        )

    def test_compile_python_function(self, tmp_path: Path, sample_python_file: Path, finding: Finding):
        compiler = SurgicalPromptCompiler(target_root=tmp_path)
        prompt = compiler.compile(finding)

        assert isinstance(prompt, SurgicalPrompt)
        assert prompt.rule_id == "B605"
        assert prompt.scanner_name == "bandit"
        assert prompt.severity == Severity.HIGH
        assert prompt.file_path == "app.py"
        assert prompt.line_number == 8
        assert prompt.enclosing_symbol == "run_user_command"
        assert "os.system(command)" in prompt.vulnerable_code_block
        assert "run_user_command" in prompt.vulnerable_code_block

        # Markdown verification
        md = prompt.compiled_markdown
        assert "# Surgical Fix Prompt: Starting a process with a shell: possible injection" in md
        assert "- **Target File:** `app.py`" in md
        assert "- **Vulnerable Line:** `app.py:8`" in md
        assert "- **Enclosing Scope:** `run_user_command`" in md
        assert "- **Scanner Rule:** `bandit` (`B605`)" in md
        assert "## Target Vulnerable Code Block" in md
        assert "```python" in md
        assert "os.system(command)" in md
        assert "## Scanner Remediation Advice" in md
        assert "Use subprocess.run" in md
        assert "## Instructions for AI Coding Agent" in md

    def test_compile_go_and_typescript_symbols(self, tmp_path: Path):
        go_code = """package main

import "os/exec"

func ExecutePayload(input string) error {
    cmd := exec.Command("sh", "-c", input)
    return cmd.Run()
}
"""
        go_file = tmp_path / "runner.go"
        go_file.write_text(go_code, encoding="utf-8")

        compiler = SurgicalPromptCompiler(target_root=tmp_path)
        go_finding = Finding(
            rule_id="G204",
            scanner_name="gosec",
            severity=Severity.HIGH,
            title="Subprocess launched with variable",
            description="Audit use of command execution",
            file_path="runner.go",
            line_number=6,
        )
        prompt_go = compiler.compile(go_finding)
        assert prompt_go.enclosing_symbol == "ExecutePayload"
        assert "```go" in prompt_go.compiled_markdown

        ts_code = """export function handleAuth(token: string) {
    const query = `SELECT * FROM users WHERE token = '${token}'`;
    return db.query(query);
}
"""
        ts_file = tmp_path / "auth.ts"
        ts_file.write_text(ts_code, encoding="utf-8")
        ts_finding = Finding(
            rule_id="sql-injection",
            scanner_name="semgrep",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="Untrusted user input interpolated in SQL query.",
            file_path="auth.ts",
            line_number=2,
        )
        prompt_ts = compiler.compile(ts_finding)
        assert prompt_ts.enclosing_symbol == "handleAuth"
        assert "```typescript" in prompt_ts.compiled_markdown

    def test_zero_secret_egress_in_compiled_prompt(self, tmp_path: Path):
        code_with_secrets = """import boto3

def get_s3_client():
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    return boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
"""
        secret_file = tmp_path / "s3_service.py"
        secret_file.write_text(code_with_secrets, encoding="utf-8")

        finding = Finding(
            rule_id="HARDCODED_SECRET",
            scanner_name="gitleaks",
            severity=Severity.CRITICAL,
            title="Hardcoded AWS Access Key",
            description="Identified hardcoded AWS credentials in code.",
            file_path="s3_service.py",
            line_number=4,
        )

        compiler = SurgicalPromptCompiler(target_root=tmp_path)
        prompt = compiler.compile(finding)

        # CRITICAL GUARANTEE: The raw secrets MUST NOT appear in the prompt or code block
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt.compiled_markdown
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in prompt.compiled_markdown
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt.vulnerable_code_block
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in prompt.vulnerable_code_block

        # Must contain redacted marker
        assert REDACTION_MARKER in prompt.vulnerable_code_block
        assert prompt.redaction_summary.secrets_found_count >= 1
        assert "Zero-Secret Egress Active" in prompt.compiled_markdown

    def test_prompt_compiler_with_immune_memory_guidance(self, tmp_path: Path, sample_python_file: Path, finding: Finding):
        # Create immune memory store with matching antibody
        memory_path = tmp_path / "memory.json"
        store = ImmuneMemoryStore(memory_path=memory_path)
        
        # Calculate exact AST hash for the snippet
        normalizer = ASTNormalizer()
        norm = normalizer.normalize("os.system(command)", language="python")

        record = ImmuneRecord(
            id="ant-001",
            rule_id="B605",
            scanner_name="bandit",
            language="python",
            severity=Severity.HIGH,
            exact_hash=norm.exact_hash,
            ast_signature=norm.ast_signature,
            anonymized_template="os.system(VAR_0)",
            resolution="REPLACE_WITH_SUBPROCESS_LIST",
            agents_rule="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
        )
        store.save_record(record)

        compiler = SurgicalPromptCompiler(
            target_root=tmp_path,
            immune_store=store,
        )
        prompt = compiler.compile(finding)

        assert prompt.immune_hint is not None
        assert "Tier" in prompt.immune_hint
        assert "REPLACE_WITH_SUBPROCESS_LIST" in prompt.immune_hint
        assert "## Local Immune Memory Guidance" in prompt.compiled_markdown
        assert "Never use os.system()" in prompt.compiled_markdown

    def test_cli_prompt_command(self, tmp_path: Path, sample_python_file: Path, capsys):
        # 1. Run standard prompt command to stdout
        rc = main([
            "-C", str(tmp_path),
            "prompt",
            "--file", "app.py",
            "--line", "8",
            "--rule", "B605",
            "--scanner", "bandit",
            "--severity", "HIGH",
            "--title", "Shell Injection Detection",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "# Surgical Fix Prompt: Shell Injection Detection" in captured.out
        assert "- **Target File:** `app.py`" in captured.out
        assert "os.system(command)" in captured.out

        # 2. Run with --json output
        rc_json = main([
            "-C", str(tmp_path),
            "prompt",
            "--file", "app.py",
            "--line", "8",
            "--rule", "B605",
            "--json",
        ])
        assert rc_json == 0
        captured_json = capsys.readouterr()
        data = json.loads(captured_json.out)
        assert data["rule_id"] == "B605"
        assert data["file_path"] == "app.py"
        assert data["enclosing_symbol"] == "run_user_command"
        assert "compiled_markdown" in data

        # 3. Run with --output file
        out_prompt_file = tmp_path / "fix_prompt.md"
        rc_file = main([
            "-C", str(tmp_path),
            "prompt",
            "--file", "app.py",
            "--line", "8",
            "--rule", "B605",
            "--output", str(out_prompt_file),
        ])
        assert rc_file == 0
        assert out_prompt_file.exists()
        saved_text = out_prompt_file.read_text(encoding="utf-8")
        assert "# Surgical Fix Prompt:" in saved_text
        assert "run_user_command" in saved_text
