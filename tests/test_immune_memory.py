"""
Unit tests for the 3-Tier Local Immune Memory Store (`vulnora.immune.memory_store`).
"""

from pathlib import Path
import time
import pytest

from vulnora.core.models import Finding, ImmunityTier, Severity
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestImmuneMemoryStore:
    """Tests for Tier 1, 2, and 3 lookups, sub-10ms performance, and atomic persistence."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> ImmuneMemoryStore:
        memory_file = tmp_path / ".vulnora" / "memory.json"
        return ImmuneMemoryStore(memory_path=memory_file)

    def test_tier_1_exact_hash_match(self, store: ImmuneMemoryStore):
        code = "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
        finding = Finding(
            title="SQL Injection",
            description="Unsafe query format",
            scanner_name="semgrep",
            rule_id="sqli-01",
            severity=Severity.CRITICAL,
            file_path="app/db.py",
            line_number=10,
            snippet=code,
        )

        record = store.remember_finding(
            finding=finding,
            code_snippet=code,
            resolution="ACCEPTED_RISK",
            language="python",
            agents_rule="Parameterize all SQL queries.",
        )

        # Query exact same code snippet
        match = store.query(finding, code_snippet=code, language="python")

        assert match.matched is True
        assert match.tier == ImmunityTier.TIER_1_EXACT
        assert match.is_exact is True
        assert match.similarity_score == 1.0
        assert match.record is not None
        assert match.record.id == record.id
        assert match.record.resolution == "ACCEPTED_RISK"
        # Sub-1ms execution check
        assert match.lookup_duration_ms < 5.0

    def test_tier_2_structural_variant_match(self, store: ImmuneMemoryStore):
        original_code = """
def fetch_user_data(client_id):
    sql_query = f"SELECT * FROM customers WHERE id = {client_id}"
    db_cursor.execute(sql_query)
"""
        renamed_variant = """
def get_account_info(account_num):
    raw_statement = f"SELECT * FROM accounts WHERE id = {account_num}"
    connection.execute(raw_statement)
"""
        finding = Finding(
            title="SQL Injection in customer query",
            description="Unsanitized user input",
            scanner_name="semgrep",
            rule_id="sqli-generic",
            severity=Severity.HIGH,
            file_path="src/users.py",
            snippet=original_code,
        )

        store.remember_finding(
            finding=finding,
            code_snippet=original_code,
            resolution="REMEDIATED",
            language="python",
        )

        # Query with renamed variant
        variant_finding = Finding(
            title="SQL Injection in account query",
            description="Unsanitized user input",
            scanner_name="semgrep",
            rule_id="sqli-generic",
            severity=Severity.HIGH,
            file_path="src/accounts.py",
            snippet=renamed_variant,
        )

        match = store.query(variant_finding, code_snippet=renamed_variant, language="python")

        assert match.matched is True
        assert match.tier == ImmunityTier.TIER_2_STRUCTURAL
        assert match.is_variant is True
        assert match.similarity_score >= 0.85
        assert match.record is not None
        assert match.record.resolution == "REMEDIATED"
        # Sub-10ms execution check
        assert match.lookup_duration_ms < 10.0

    def test_tier_3_partial_match(self, store: ImmuneMemoryStore):
        code1 = """
def execute_command_with_prefix(command, prefix):
    formatted = prefix + " " + command
    os.system(formatted)
"""
        code2 = """
def execute_simple_command(cmd):
    os.system(cmd)
"""
        finding1 = Finding(
            title="Command Injection",
            description="os.system call",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.HIGH,
            file_path="cmd.py",
        )
        store.remember_finding(finding1, code_snippet=code1, resolution="FALSE_POSITIVE", language="python")

        finding2 = Finding(
            title="Ping Command Injection",
            description="os.system ping",
            scanner_name="bandit",
            rule_id="B605",
            severity=Severity.HIGH,
            file_path="ping.py",
        )
        match = store.query(finding2, code_snippet=code2, language="python")

        # Either tier 2 or tier 3 depending on AST overlap, but matched
        assert match.matched is True
        assert match.tier in (ImmunityTier.TIER_2_STRUCTURAL, ImmunityTier.TIER_3_PARTIAL)
        assert match.similarity_score >= 0.50

    def test_no_match_on_completely_unrelated_code(self, store: ImmuneMemoryStore):
        code1 = "os.system(untrusted_cmd)"
        code2 = "const PI = 3.14159; return Math.sqrt(PI);"

        f1 = Finding(title="RCE", description="", scanner_name="bandit", rule_id="B605", severity=Severity.HIGH, file_path="rce.py")
        store.remember_finding(f1, code_snippet=code1, resolution="REMEDIATED", language="python")

        f2 = Finding(title="Math helper", description="", scanner_name="semgrep", rule_id="other-rule", severity=Severity.LOW, file_path="math.js")
        match = store.query(f2, code_snippet=code2, language="javascript")

        assert match.matched is False
        assert match.tier == ImmunityTier.NO_MATCH

    def test_atomic_persistence_and_reload(self, tmp_path: Path):
        memory_file = tmp_path / ".vulnora" / "memory.json"
        store1 = ImmuneMemoryStore(memory_path=memory_file)

        finding = Finding(
            title="Secret",
            description="Secret leak",
            scanner_name="gitleaks",
            rule_id="secret-rule",
            severity=Severity.CRITICAL,
            file_path="keys.py",
        )
        store1.remember_finding(finding, code_snippet="API_KEY = 'secret123'", resolution="ACCEPTED_RISK")

        assert memory_file.exists()

        # Reload store from same file
        store2 = ImmuneMemoryStore(memory_path=memory_file)
        assert len(store2.get_all_records()) == 1
        rec = store2.get_all_records()[0]
        assert rec.rule_id == "secret-rule"
        assert rec.resolution == "ACCEPTED_RISK"

    def test_immunity_metrics_tracking(self, store: ImmuneMemoryStore):
        f = Finding(title="T", description="D", scanner_name="s", rule_id="r", severity=Severity.MEDIUM, file_path="a.go")
        store.remember_finding(f, code_snippet="fmt.Println('test')", resolution="FALSE_POSITIVE", language="go")

        metrics = store.get_metrics()
        assert metrics.total_records == 1
        assert metrics.records_by_language.get("go") == 1
        assert metrics.records_by_resolution.get("FALSE_POSITIVE") == 1
        assert metrics.records_by_severity.get("MEDIUM") == 1
