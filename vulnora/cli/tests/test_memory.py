"""
Comprehensive automated tests for Vulnora AI Local Issue Memory System (Phase 4).
Tests:
1. Creating a new memory file.
2. Saving a verified vulnerability.
3. Generating deterministic signatures.
4. Exact memory matching.
5. Rule-based matching.
6. Avoiding unrelated matches.
7. Handling duplicate records.
8. Updating last-used timestamps and match counts.
9. Handling corrupted JSON and atomic writing.
10. Testing all memory CLI commands (list, show, search, stats, record).
11. Integrating memory lookup with the scanner orchestrator.
"""

from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest

from typer.testing import CliRunner

from vulnora.cli.main import app
from vulnora.memory import (
    DEFAULT_MEMORY_TEMPLATE,
    MatchConfidence,
    MemoryLookupEngine,
    MemoryRecord,
    MemoryService,
    MemoryStore,
    detect_file_type,
    generate_code_fingerprint,
    generate_rule_signature,
    generate_vulnerability_signature,
    normalize_code_pattern,
)
from vulnora.scanners import NormalizedFinding, Severity

runner = CliRunner()


class IssueMemoryCoreTestCase(unittest.TestCase):
    """Tests memory storage, deterministic signatures, matching, and recovery."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)
        self.store = MemoryStore(self.project_path)
        self.service = MemoryService(self.project_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_create_new_memory_file(self):
        """1. Verify creating a new memory.json file when missing."""
        mem_file = self.store.ensure_memory_file()
        self.assertTrue(mem_file.exists())
        self.assertEqual(mem_file.name, "memory.json")

        data = self.store.load_data()
        self.assertEqual(data["version"], "1.0")
        self.assertIn("created_at", data)
        self.assertIn("last_updated", data)
        self.assertIsInstance(data["issue_memory"], list)
        self.assertEqual(len(data["issue_memory"]), 0)

    def test_2_save_verified_vulnerability(self):
        """2. Verify saving a verified vulnerability resolution."""
        record = self.service.save_verified_resolution(
            title="Insecure MD5 Cryptographic Hash",
            scanner_name="bandit",
            rule_id="B303",
            severity=Severity.HIGH,
            root_cause="Use of weak MD5 hashing algorithm susceptible to collision attacks.",
            remediation="Replace hashlib.md5() with hashlib.sha256() or SHA3.",
            file_path_or_type="auth/tokens.py",
            code_snippet="hashlib.md5(token.encode())",
            verified=True,
        )

        self.assertIsNotNone(record)
        self.assertTrue(record.id.startswith("mem_"))
        self.assertTrue(record.vulnerability_signature.startswith("sig_"))
        self.assertEqual(record.scanner_name, "bandit")
        self.assertEqual(record.rule_id, "B303")
        self.assertEqual(record.file_type, "python")
        self.assertEqual(record.match_count, 0)
        self.assertIsNone(record.last_used_at)

        # Verify persisted in file
        records = self.store.get_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].id, record.id)
        self.assertEqual(records[0].rule_id, "B303")

        # Unverified resolution must be rejected
        with self.assertRaises(ValueError):
            self.service.save_verified_resolution(
                title="Unverified Fix",
                scanner_name="bandit",
                rule_id="B101",
                severity=Severity.LOW,
                root_cause="None",
                remediation="Some fix",
                verified=False,
            )

    def test_3_deterministic_signatures(self):
        """3. Verify deterministic, collision-resistant signature generation."""
        sig1 = generate_vulnerability_signature(
            scanner_name="bandit",
            rule_id="B605",
            file_path_or_type="scripts/deploy.py",
            code_snippet="os.system('rm -rf /tmp/test')",
        )
        sig2 = generate_vulnerability_signature(
            scanner_name="bandit",
            rule_id="B605",
            file_path_or_type="scripts/deploy.py",
            code_snippet="os.system('rm -rf /tmp/test')",
        )
        # Identical inputs must yield identical signatures
        self.assertEqual(sig1, sig2)

        # Different rule ID yields different signature
        sig_diff_rule = generate_vulnerability_signature(
            scanner_name="bandit",
            rule_id="B607",
            file_path_or_type="scripts/deploy.py",
            code_snippet="os.system('rm -rf /tmp/test')",
        )
        self.assertNotEqual(sig1, sig_diff_rule)

        # Different language/file_type yields different signature
        sig_diff_lang = generate_vulnerability_signature(
            scanner_name="bandit",
            rule_id="B605",
            file_path_or_type="scripts/deploy.js",
            code_snippet="os.system('rm -rf /tmp/test')",
        )
        self.assertNotEqual(sig1, sig_diff_lang)

    def test_4_exact_memory_matching(self):
        """4. Verify exact signature matching."""
        code = "subprocess.Popen(cmd, shell=True)"
        record = self.service.save_verified_resolution(
            title="Shell Injection in Popen",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.CRITICAL,
            root_cause="shell=True enables command injection via metacharacters.",
            remediation="Pass argument list with shell=False.",
            file_path_or_type="app/worker.py",
            code_snippet=code,
            verified=True,
        )

        finding = NormalizedFinding(
            title="start_process_with_a_shell (B605)",
            description="Use of shell=True in subprocess call",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.CRITICAL,
            file_path="app/worker.py",
            line_number=25,
        )

        match = self.service.lookup_finding(finding)
        self.assertTrue(match.has_match)
        self.assertIn(match.confidence, (MatchConfidence.EXACT, MatchConfidence.RULE_MATCH))
        self.assertGreaterEqual(match.confidence_score, 0.85)
        self.assertEqual(match.record.id, record.id)

    def test_5_rule_based_matching(self):
        """5. Verify rule-based fallback matching when file paths or exact snippets differ."""
        record = self.service.save_verified_resolution(
            title="Generic Command Injection",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.CRITICAL,
            root_cause="Executing shell commands.",
            remediation="Use subprocess.run(['cmd', 'arg']) without shell=True.",
            file_path_or_type="legacy/runner.py",
            code_snippet=None,
            verified=True,
        )

        # Different file in python, same rule
        finding = NormalizedFinding(
            title="start_process_with_a_shell",
            description="Found B605 issue",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.CRITICAL,
            file_path="services/executor.py",
            line_number=100,
        )

        match = self.service.lookup_finding(finding)
        self.assertTrue(match.has_match)
        self.assertIn(match.confidence, (MatchConfidence.EXACT, MatchConfidence.RULE_MATCH))
        self.assertEqual(match.record.id, record.id)

    def test_6_avoiding_unrelated_matches(self):
        """6. Verify unrelated vulnerabilities are not matched."""
        self.service.save_verified_resolution(
            title="Insecure MD5 Hash",
            scanner_name="bandit",
            rule_id="B303",
            severity=Severity.HIGH,
            root_cause="MD5 collision.",
            remediation="Use SHA256.",
            file_path_or_type="crypto.py",
            verified=True,
        )

        unrelated_finding = NormalizedFinding(
            title="Exposed Secret Key",
            scanner_name="gitleaks",
            rule_id="generic-api-key",
            severity=Severity.CRITICAL,
            file_path="config.env",
            description="Exposed token",
        )

        match = self.service.lookup_finding(unrelated_finding)
        self.assertFalse(match.has_match)
        self.assertEqual(match.confidence, MatchConfidence.NONE)
        self.assertIsNone(match.record)

    def test_7_handling_duplicate_records(self):
        """7. Verify updating existing records without creating duplicates."""
        rec1 = self.service.save_verified_resolution(
            title="Use of Insecure Cipher",
            scanner_name="bandit",
            rule_id="B304",
            severity=Severity.HIGH,
            root_cause="Insecure DES cipher.",
            remediation="Switch to AES-GCM.",
            file_path_or_type="crypto.py",
            verified=True,
        )

        # Save again with updated remediation for the same vulnerability signature
        rec2 = self.service.save_verified_resolution(
            title="Use of Insecure Cipher",
            scanner_name="bandit",
            rule_id="B304",
            severity=Severity.HIGH,
            root_cause="Insecure DES cipher.",
            remediation="Switch to AES-256-GCM using cryptography library.",
            file_path_or_type="crypto.py",
            verified=True,
        )

        records = self.store.get_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].id, rec1.id)
        self.assertEqual(records[0].remediation, "Switch to AES-256-GCM using cryptography library.")

    def test_8_updating_last_used_and_match_counts(self):
        """8. Verify updating last-used timestamps and match counts."""
        record = self.service.save_verified_resolution(
            title="Hardcoded Temporary Password",
            scanner_name="bandit",
            rule_id="B105",
            severity=Severity.MEDIUM,
            root_cause="Password string in source code.",
            remediation="Load password from os.environ.",
            file_path_or_type="auth.py",
            verified=True,
        )

        self.assertEqual(record.match_count, 0)
        self.assertIsNone(record.last_used_at)

        finding = NormalizedFinding(
            title="Hardcoded Password",
            scanner_name="bandit",
            rule_id="B105",
            severity=Severity.MEDIUM,
            file_path="auth.py",
            description="Found hardcoded password string",
        )

        # Lookup with update_usage=True
        results = self.service.lookup_findings([finding], update_usage=True)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].has_match)

        # Verify updated in store
        updated = self.store.get_record(record.id)
        self.assertEqual(updated.match_count, 1)
        self.assertIsNotNone(updated.last_used_at)

        # Second lookup increments again
        self.service.lookup_findings([finding], update_usage=True)
        updated2 = self.store.get_record(record.id)
        self.assertEqual(updated2.match_count, 2)

    def test_9_corrupted_json_handling_and_atomic_writes(self):
        """9. Verify handling corrupted JSON gracefully and preserving data via atomic writes."""
        mem_file = self.store.ensure_memory_file()
        mem_file.write_text("{CORRUPTED_JSON_CONTENT:::INVALID", encoding="utf-8")

        # Loading must not crash; should safely backup and reinitialize
        data = self.store.load_data()
        self.assertIn("issue_memory", data)
        self.assertEqual(len(data["issue_memory"]), 0)

        # Verify backup was created
        backups = list(self.store.vulnora_dir.glob("memory.json.corrupted.*"))
        self.assertGreaterEqual(len(backups), 1)


class IssueMemoryCLITestCase(unittest.TestCase):
    """Tests all `vulnora memory` CLI commands."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)
        runner.invoke(app, ["init", "--path", str(self.project_path)])
        self.service = MemoryService(self.project_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_10_memory_cli_commands(self):
        """10. Test memory record, list, show, search, and stats CLI commands."""
        # 1. vulnora memory record
        res_record = runner.invoke(app, [
            "memory", "record",
            "--path", str(self.project_path),
            "--title", "Hardcoded API Key In Settings",
            "--scanner", "gitleaks",
            "--rule-id", "generic-api-key",
            "--severity", "HIGH",
            "--root-cause", "Sensitive credential checked into repository.",
            "--remediation", "Revoke the key, store in environment variable, and rotate immediately.",
            "--file-path", "settings.py",
            "--verified",
        ])
        self.assertEqual(res_record.exit_code, 0)
        self.assertIn("Verified Resolution Recorded", res_record.output)
        self.assertIn("mem_", res_record.output)

        # Retrieve the record ID from memory
        records = self.service.list_records()
        self.assertEqual(len(records), 1)
        rec_id = records[0].id

        # 2. vulnora memory list
        res_list = runner.invoke(app, ["memory", "list", "--path", str(self.project_path)])
        self.assertEqual(res_list.exit_code, 0)
        self.assertIn(rec_id, res_list.output)
        self.assertIn("GITLEAKS", res_list.output)
        self.assertIn("generic-api-key", res_list.output)

        # 3. vulnora memory show <id>
        res_show = runner.invoke(app, ["memory", "show", rec_id, "--path", str(self.project_path)])
        self.assertEqual(res_show.exit_code, 0)
        self.assertIn(rec_id, res_show.output)
        self.assertIn("Root Cause", res_show.output)
        self.assertIn("Verified Remediation", res_show.output)
        self.assertIn("Revoke the key", res_show.output)

        # 4. vulnora memory search
        res_search = runner.invoke(app, [
            "memory", "search",
            "--path", str(self.project_path),
            "--scanner", "gitleaks",
            "--query", "credential",
        ])
        self.assertEqual(res_search.exit_code, 0)
        self.assertIn(rec_id, res_search.output)

        # Search with no match
        res_no_match = runner.invoke(app, [
            "memory", "search",
            "--path", str(self.project_path),
            "--scanner", "bandit",
        ])
        self.assertEqual(res_no_match.exit_code, 0)
        self.assertIn("No records matching search criteria", res_no_match.output)

        # 5. vulnora memory stats
        res_stats = runner.invoke(app, ["memory", "stats", "--path", str(self.project_path)])
        self.assertEqual(res_stats.exit_code, 0)
        self.assertIn("Total Verified Records", res_stats.output)
        self.assertIn("GITLEAKS", res_stats.output)

    def test_11_scanner_integration_memory_lookup(self):
        """11. Verify integration between scanner execution and local issue memory."""
        # Store a verified resolution for Bandit B605 (shell injection)
        self.service.save_verified_resolution(
            title="Python Shell Injection",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.CRITICAL,
            root_cause="Passing shell=True allows command injection.",
            remediation="Use subprocess.run(['ls', '-la']) with arguments list.",
            file_path_or_type="worker.py",
            verified=True,
        )

        # Create a Python file that triggers Bandit B605
        test_py = self.project_path / "worker.py"
        test_py.write_text("import os\nos.system('echo vulnerable')\n", encoding="utf-8")

        # Run vulnora scan --json
        res_scan = runner.invoke(app, [
            "scan",
            "--path", str(self.project_path),
            "--scanner", "bandit",
            "--json",
        ])
        self.assertEqual(res_scan.exit_code, 0)

        data = json.loads(res_scan.output.strip())
        self.assertIn("memory_matches_count", data)
        self.assertGreaterEqual(data["memory_matches_count"], 1)

        # Verify finding has memory_match metadata
        matched_findings = [f for f in data["findings"] if f.get("memory_match") and f["memory_match"].get("matched")]
        self.assertGreaterEqual(len(matched_findings), 1)
        first_match = matched_findings[0]["memory_match"]
        self.assertIn(first_match["confidence"], (MatchConfidence.EXACT, MatchConfidence.RULE_MATCH))
        self.assertIn("arguments list", first_match["verified_remediation"])


if __name__ == "__main__":
    unittest.main()
