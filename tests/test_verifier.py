"""
Unit tests for the Fix Verification & Learning Loop (`vulnora.engine.verifier`).
"""

from pathlib import Path
import pytest

from vulnora.core.config import VulnoraConfig
from vulnora.core.models import Finding, OrchestratorResult, RemediationProposal, ScannerResult, Severity
from vulnora.engine.agents_md import AgentsMDWriter
from vulnora.engine.verifier import FixVerifier
from vulnora.immune.ast_normalizer import ASTNormalizer
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestFixVerifier:
    """Tests for patch verification, auto-rollback on failure, and immune learning."""

    @pytest.fixture
    def test_env(self, tmp_path: Path):
        code = """import os

def run_task(cmd):
    os.system(cmd)
    return True
"""
        target_file = tmp_path / "worker.py"
        target_file.write_text(code, encoding="utf-8")

        memory_file = tmp_path / "memory.json"
        store = ImmuneMemoryStore(memory_path=memory_file)
        writer = AgentsMDWriter(repo_root=tmp_path)
        normalizer = ASTNormalizer()
        config = VulnoraConfig()

        verifier = FixVerifier(
            target_root=tmp_path,
            config=config,
            immune_store=store,
            normalizer=normalizer,
            agents_writer=writer,
        )

        finding = Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Insecure shell call",
            description="os.system call detected",
            file_path="worker.py",
            line_number=4,
            snippet="os.system(cmd)",
        )

        return verifier, target_file, finding, store, writer

    def test_verify_and_learn_success(self, test_env, mocker):
        verifier, target_file, finding, store, writer = test_env

        proposal = RemediationProposal(
            finding_id=finding.compute_fingerprint(),
            rule_id="B605",
            file_path="worker.py",
            root_cause="os.system executes through system shell.",
            explanation="Replaced with subprocess.run with argument list.",
            replacement_code="subprocess.run(['echo', cmd], shell=False, check=True)",
            original_code="os.system(cmd)",
            agents_rule="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
        )

        # Mock ScannerOrchestrator to return clean result (0 findings)
        mock_result = OrchestratorResult(
            target_path=str(verifier.target_root),
            is_full_scan=False,
            scanner_results=[
                ScannerResult(
                    scanner_name="bandit",
                    status="COMPLETED",
                    findings=[],
                )
            ],
            findings=[],
        )
        mocker.patch("vulnora.engine.verifier.ScannerOrchestrator.run_scanners", return_value=mock_result)

        result = verifier.verify_and_learn(finding, proposal, auto_rollback=True)

        assert result.success is True
        assert result.remaining_findings_count == 0
        assert "subprocess.run" in target_file.read_text(encoding="utf-8")
        assert result.diff_unified != ""
        assert result.antibody_id is not None
        assert result.agents_rule_added is True

        # Check that antibody was committed to immune memory
        records = store.get_all_records()
        assert len(records) == 1
        assert records[0].rule_id == "B605"
        assert records[0].resolution == "REMEDIATED"

        # Check that AGENTS.md was updated
        agents_content = writer.file_path.read_text(encoding="utf-8")
        assert "B605" in agents_content
        assert "subprocess.run" in agents_content

    def test_verify_failure_auto_rollback(self, test_env, mocker):
        verifier, target_file, finding, store, writer = test_env
        original_code = target_file.read_text(encoding="utf-8")

        proposal = RemediationProposal(
            finding_id=finding.compute_fingerprint(),
            rule_id="B605",
            file_path="worker.py",
            root_cause="os.system call",
            explanation="Bad patch that still fails",
            replacement_code="os.system('sh ' + cmd)",
            original_code="os.system(cmd)",
            agents_rule="Avoid shell execution.",
        )

        # Mock ScannerOrchestrator to return remaining finding (verification failed!)
        mock_result = OrchestratorResult(
            target_path=str(verifier.target_root),
            is_full_scan=False,
            scanner_results=[
                ScannerResult(
                    scanner_name="bandit",
                    status="COMPLETED",
                    findings=[finding],
                )
            ],
            findings=[finding],
        )
        mocker.patch("vulnora.engine.verifier.ScannerOrchestrator.run_scanners", return_value=mock_result)

        result = verifier.verify_and_learn(finding, proposal, auto_rollback=True)

        assert result.success is False
        assert result.remaining_findings_count == 1
        # CRITICAL: Auto-rollback restored the original code!
        assert target_file.read_text(encoding="utf-8") == original_code
        # No antibody should have been added
        assert len(store.get_all_records()) == 0
