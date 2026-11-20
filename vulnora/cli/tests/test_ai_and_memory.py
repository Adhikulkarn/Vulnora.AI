"""
Unit and integration tests for Vulnora AI Remote AI Inference, Secret Redaction,
Local Issue Memory, and Remediation Workflows.
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import requests

from vulnora.cli.ai_client import (
    apply_patch_to_file,
    extract_code_context,
    redact_secrets,
    request_remediation,
    verify_scanner_fix,
)
from vulnora.cli.config import (
    DEFAULT_CONFIG_TEMPLATE,
    get_ai_config,
    get_write_permission,
    load_config,
    save_config,
)
from vulnora.cli.memory import (
    compute_pattern_key,
    init_memory,
    is_vulnerability_discarded,
    load_memory,
    lookup_memory_fix,
    record_discarded_finding,
    record_verified_fix,
    save_memory,
)
from vulnora.cli.remediation_workflow import run_remediation_workflow


class SecretRedactionTests(unittest.TestCase):
    def test_github_token_redaction(self):
        fake_ghp = "".join(["ghp_", "1234567890ABCDEFGHIJKLMNO123456"])
        fake_pat = "".join(["github_", "pat_", "11AAAAAA012345678901234567890"])
        text = f'TOKEN = "{fake_ghp}"\nPAT = "{fake_pat}"'
        redacted = redact_secrets(text)
        self.assertNotIn(fake_ghp, redacted)
        self.assertNotIn(fake_pat, redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_stripe_and_aws_keys_redaction(self):
        fake_stripe = "".join(["sk_", "live_", "dummykey12345678901234567890"])
        fake_aws = "".join(["AKIA", "IOSFODNN7EXAMPLE"])
        text = f'STRIPE = "{fake_stripe}"\nAWS = "{fake_aws}"'
        redacted = redact_secrets(text)
        self.assertNotIn(fake_stripe, redacted)
        self.assertNotIn(fake_aws, redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_private_key_redaction(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz\n"
            "-----END RSA PRIVATE KEY-----\n"
            "print('hello')"
        )
        redacted = redact_secrets(text)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y1+", redacted)
        self.assertIn("***REDACTED***", redacted)
        self.assertIn("print('hello')", redacted)

    def test_bearer_token_redaction(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"
        redacted = redact_secrets(text)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertIn("Bearer ***REDACTED***", redacted)

    def test_password_variable_assignment_redaction(self):
        text = 'db_password = "SuperSecretPassword123!"\napi_key = "abc123xyz"'
        redacted = redact_secrets(text)
        self.assertNotIn("SuperSecretPassword123!", redacted)
        self.assertIn('db_password = "***REDACTED***"', redacted)
        self.assertIn('api_key = "***REDACTED***"', redacted)

    def test_clean_text_unchanged(self):
        clean = "def calculate_sum(a, b):\n    return a + b\n"
        self.assertEqual(redact_secrets(clean), clean)


class CodeContextExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "sample.py"
        lines = [f"line_{i} = {i}" for i in range(1, 31)]
        self.fake_token = "".join(["ghp_", "secrettoken123456789012345"])
        lines[14] = f'api_key = "{self.fake_token}"'
        self.file_path.write_text("\n".join(lines), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extract_context_with_line_number(self):
        context = extract_code_context(self.file_path, line_number=15, context_lines=3)
        self.assertIn("line_12 = 12", context)
        self.assertIn("line_18 = 18", context)
        # Verify secrets are redacted in context
        self.assertNotIn(self.fake_token, context)
        self.assertIn("***REDACTED***", context)

    def test_extract_context_none_line_number(self):
        context = extract_code_context(self.file_path, line_number=None, context_lines=5)
        self.assertIn("line_1 = 1", context)

    def test_extract_context_nonexistent_file(self):
        context = extract_code_context(Path(self.temp_dir.name) / "missing.py", line_number=5)
        self.assertEqual(context, "")


class OllamaClientTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temp_dir.name)
        self.test_file = self.project_root / "vuln.py"
        self.test_file.write_text("import os\n\ndef run(cmd):\n    return eval(cmd)\n", encoding="utf-8")

        self.ai_config = {
            "enabled": True,
            "base_url": "http://127.0.0.1:11435",
            "model": "qwen2.5-coder:7b",
            "timeout_seconds": 30,
            "think": False,
        }
        self.finding = {
            "scanner_name": "bandit",
            "rule_id": "B307",
            "title": "Use of possibly insecure function - eval",
            "description": "Use of eval detected.",
            "severity": "HIGH",
            "file_path": "vuln.py",
            "line_number": 4,
            "remediation": "Replace eval with ast.literal_eval.",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("requests.post")
    def test_request_remediation_json_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "qwen2.5-coder:7b",
            "response": json.dumps({
                "root_cause": "eval() allows arbitrary code execution",
                "explanation": "Replace eval() with ast.literal_eval()",
                "replacement_code": "return ast.literal_eval(cmd)",
            }),
        }
        mock_post.return_value = mock_resp

        result = request_remediation(self.finding, self.project_root, self.ai_config)

        self.assertEqual(result["root_cause"], "eval() allows arbitrary code execution")
        self.assertIn("ast.literal_eval", result["replacement_code"])
        self.assertEqual(result["model"], "qwen2.5-coder:7b")

    @patch("requests.post")
    def test_request_remediation_markdown_fences_and_think(self, mock_post):
        raw_response = (
            "<think>Analyzing AST of eval call...</think>\n"
            "```json\n"
            "{\n"
            '  "root_cause": "Unsafe dynamic evaluation",\n'
            '  "explanation": "Use safe parser",\n'
            '  "replacement_code": "return ast.literal_eval(cmd)"\n'
            "}\n"
            "```"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "qwen2.5-coder:7b",
            "response": raw_response,
        }
        mock_post.return_value = mock_resp

        result = request_remediation(self.finding, self.project_root, self.ai_config)

        self.assertEqual(result["root_cause"], "Unsafe dynamic evaluation")
        self.assertEqual(result["replacement_code"], "return ast.literal_eval(cmd)")

    @patch("requests.post")
    def test_request_remediation_timeout(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        result = request_remediation(self.finding, self.project_root, self.ai_config)

        self.assertIn("timed out", result["explanation"].lower())
        self.assertEqual(result["error"], "timeout")
        self.assertEqual(result["replacement_code"], "")

    @patch("requests.post")
    def test_request_remediation_connection_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = request_remediation(self.finding, self.project_root, self.ai_config)

        self.assertIn("unreachable", result["root_cause"].lower())
        self.assertEqual(result["replacement_code"], "")

    def test_apply_patch_to_file(self):
        applied = apply_patch_to_file(
            file_path=self.test_file,
            line_number=4,
            replacement_code="return ast.literal_eval(cmd)",
        )
        self.assertTrue(applied)
        content = self.test_file.read_text(encoding="utf-8")
        self.assertIn("ast.literal_eval(cmd)", content)
        self.assertNotIn("return eval(cmd)", content)


class IssueMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        init_memory(self.base_path)
        self.finding = {
            "scanner_name": "bandit",
            "rule_id": "B307",
            "file_path": "app.py",
            "line_number": 10,
            "fingerprint": "bandit:B307:app.py:10",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compute_pattern_key_deterministic(self):
        key1 = compute_pattern_key(self.finding)
        key2 = compute_pattern_key(self.finding)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_lookup_memory_fix_hit_and_miss(self):
        memory_data = load_memory(self.base_path)
        # Miss
        self.assertIsNone(lookup_memory_fix(memory_data, self.finding))

        # Record fix
        fix_payload = {
            "root_cause": "eval() execution",
            "explanation": "ast.literal_eval replacement",
            "replacement_code": "return ast.literal_eval(cmd)",
        }
        memory_data = record_verified_fix(memory_data, self.finding, fix_payload, "app.py")
        save_memory(memory_data, self.base_path)

        # Reload and hit
        reloaded = load_memory(self.base_path)
        hit = lookup_memory_fix(reloaded, self.finding)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["replacement_code"], "return ast.literal_eval(cmd)")
        self.assertEqual(hit["source"], "memory")

    def test_is_vulnerability_discarded(self):
        memory_data = load_memory(self.base_path)
        self.assertFalse(is_vulnerability_discarded(memory_data, self.finding))

        memory_data = record_discarded_finding(memory_data, self.finding, reason="false_positive")
        save_memory(memory_data, self.base_path)

        reloaded = load_memory(self.base_path)
        self.assertTrue(is_vulnerability_discarded(reloaded, self.finding))

    def test_record_verified_fix_masks_secrets(self):
        fake_token = "".join(["ghp_", "1234567890ABCDEFGHIJKLMNO123456"])
        memory_data = load_memory(self.base_path)
        fix_payload = {
            "root_cause": "Hardcoded token",
            "explanation": "Replace secret with env var",
            "replacement_code": f'TOKEN = "{fake_token}"',
        }
        memory_data = record_verified_fix(memory_data, self.finding, fix_payload, "config.py")

        entry = memory_data["issue_memory"][0]
        self.assertNotIn(fake_token, entry["patched_snippet"])
        self.assertIn("***REDACTED***", entry["patched_snippet"])


class ConfigDeepMergeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_config_deep_merges_ai_defaults(self):
        # Save a config file that only specifies model and custom protected branches
        partial_config = {
            "git": {
                "protected_branches": ["main", "release"],
            },
            "ai": {
                "model": "qwen3.5:4b",
                "think": True,
            },
        }
        save_config(partial_config, self.base_path)

        loaded = load_config(self.base_path)
        # Overridden fields
        self.assertEqual(loaded["git"]["protected_branches"], ["main", "release"])
        self.assertEqual(loaded["ai"]["model"], "qwen3.5:4b")
        self.assertTrue(loaded["ai"]["think"])
        # Inherited default fields
        self.assertEqual(loaded["ai"]["base_url"], "http://127.0.0.1:11435")
        self.assertEqual(loaded["ai"]["timeout_seconds"], 90)
        self.assertTrue(loaded["git"]["enforce_pre_push"])
        self.assertEqual(loaded["project"]["write_permission"], "prompt")

    def test_helpers(self):
        ai_cfg = get_ai_config(self.base_path)
        self.assertEqual(ai_cfg["base_url"], "http://127.0.0.1:11435")
        self.assertEqual(get_write_permission(self.base_path), "prompt")


class RemediationWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temp_dir.name)
        init_memory(self.project_root)

        self.test_file = self.project_root / "calc.py"
        self.test_file.write_text("def calc(expr):\n    return eval(expr)\n", encoding="utf-8")

        self.finding = {
            "scanner_name": "bandit",
            "rule_id": "B307",
            "title": "Use of eval",
            "description": "Insecure eval call",
            "severity": "HIGH",
            "file_path": "calc.py",
            "line_number": 2,
            "remediation": "Use ast.literal_eval",
            "fingerprint": "bandit:B307:calc.py:2",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("vulnora.cli.remediation_workflow.verify_scanner_fix", return_value=True)
    @patch("vulnora.cli.remediation_workflow.request_remediation")
    def test_workflow_auto_accept(self, mock_ai, mock_verify):
        mock_ai.return_value = {
            "root_cause": "Unsafe eval",
            "explanation": "Replaced with literal_eval",
            "replacement_code": "return ast.literal_eval(expr)",
            "model": "qwen2.5-coder:7b",
        }

        resolved, discarded, unaddressed = run_remediation_workflow(
            project_root=self.project_root,
            findings=[self.finding],
            auto_accept=True,
        )

        self.assertEqual(len(resolved), 1)
        self.assertEqual(len(discarded), 0)
        self.assertEqual(len(unaddressed), 0)

        # Verify file was patched
        patched_code = self.test_file.read_text(encoding="utf-8")
        self.assertIn("ast.literal_eval(expr)", patched_code)

        # Verify recorded in issue_memory
        mem = load_memory(self.project_root)
        self.assertEqual(len(mem["issue_memory"]), 1)
        self.assertEqual(mem["issue_memory"][0]["rule_id"], "B307")

    def test_workflow_previously_discarded_skipped(self):
        mem = load_memory(self.project_root)
        record_discarded_finding(mem, self.finding, reason="already_discarded")
        save_memory(mem, self.project_root)

        resolved, discarded, unaddressed = run_remediation_workflow(
            project_root=self.project_root,
            findings=[self.finding],
            auto_accept=True,
        )

        self.assertEqual(len(resolved), 0)
        self.assertEqual(len(discarded), 1)
        self.assertEqual(len(unaddressed), 0)


if __name__ == "__main__":
    unittest.main()
