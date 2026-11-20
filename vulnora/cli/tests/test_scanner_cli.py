"""
Phase 3 Tests for Vulnora AI Security Scanner Integration.
Covers:
- Modular scanner data structures, NormalizedFinding, and secret masking
- ScannerOrchestrator scanner resolution, execution, error handling, and deduplication
- CLI `vulnora scan` command (--path, --scanner, --json, --output, --zap-target)
- CLI `vulnora guard` command triggering scanners on protected branches
- Graceful offline backend synchronization
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from vulnora.cli.config import load_config
from vulnora.cli.main import app
from vulnora.scanners import (
    BanditScannerService,
    GitleaksScannerService,
    NormalizedFinding,
    ScannerExecutionResult,
    ScannerOrchestrator,
    ScanStatus,
    Severity,
    mask_secret,
    sync_scan_to_backend,
)

runner = CliRunner()


class ScannerDataStructuresTestCase(unittest.TestCase):
    """Verifies normalized finding representations, secret masking, and severity levels."""

    def test_mask_secret_redaction(self):
        # Short secret
        self.assertEqual(mask_secret(""), "******")
        self.assertEqual(mask_secret("12345"), "******")

        # Standard API key / secret
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        masked = mask_secret(secret)
        self.assertNotIn(secret, masked)
        self.assertEqual(masked, "ghp...456")

    def test_severity_normalization(self):
        self.assertEqual(Severity.normalize("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.normalize("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.normalize("Error"), Severity.HIGH)
        self.assertEqual(Severity.normalize("warning"), Severity.MEDIUM)
        self.assertEqual(Severity.normalize("MEDIUM"), Severity.MEDIUM)
        self.assertEqual(Severity.normalize("low"), Severity.LOW)
        self.assertEqual(Severity.normalize("info"), Severity.INFO)
        self.assertEqual(Severity.normalize("unknown-level"), Severity.INFO)
        self.assertEqual(Severity.normalize(None), Severity.INFO)

    def test_normalized_finding_fingerprint_and_to_dict(self):
        finding1 = NormalizedFinding(
            title="Hardcoded AWS Access Key",
            description="Found sensitive credential in source code",
            scanner_name="gitleaks",
            rule_id="aws-access-token",
            severity=Severity.CRITICAL,
            file_path="config/settings.py",
            line_number=42,
            remediation="Use environment variables instead of hardcoding keys.",
            reference_urls=["https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html"],
        )

        # Identical issue produces identical fingerprint
        finding2 = NormalizedFinding(
            title="Hardcoded AWS Access Key",
            description="Found sensitive credential in source code",
            scanner_name="gitleaks",
            rule_id="aws-access-token",
            severity=Severity.CRITICAL,
            file_path="config/settings.py",
            line_number=42,
        )
        self.assertEqual(finding1.fingerprint, finding2.fingerprint)

        # Dict export contains all structured fields
        f_dict = finding1.to_dict()
        self.assertEqual(f_dict["title"], "Hardcoded AWS Access Key")
        self.assertEqual(f_dict["scanner_name"], "gitleaks")
        self.assertEqual(f_dict["severity"], Severity.CRITICAL)
        self.assertEqual(f_dict["file_path"], "config/settings.py")
        self.assertEqual(f_dict["line_number"], 42)
        self.assertEqual(f_dict["fingerprint"], finding1.fingerprint)

    def test_gitleaks_finding_secret_redaction(self):
        finding = NormalizedFinding(
            title="Exposed API Token",
            description="Found secret = 'ghp_0123456789abcdef' in code",
            scanner_name="gitleaks",
            rule_id="github-pat",
            severity=Severity.CRITICAL,
            file_path="secrets.env",
            remediation="Rotate token: 'ghp_0123456789abcdef' immediately",
        )
        self.assertNotIn("ghp_0123456789abcdef", finding.description)
        self.assertNotIn("ghp_0123456789abcdef", finding.remediation)
        self.assertIn("[REDACTED]", finding.description)


class ScannerOrchestratorTestCase(unittest.TestCase):
    """Verifies scanner registry, orchestration, aggregation, and failure tolerance."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)
        # Create a sample Python file
        (self.project_path / "main.py").write_text("print('hello world')\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_available_scanners_registry(self):
        orchestrator = ScannerOrchestrator()
        self.assertEqual(len(orchestrator.scanners), 6)
        expected = ["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"]
        for exp in expected:
            self.assertIn(exp, orchestrator.scanners)

        report = orchestrator.get_scanner_availability()
        self.assertEqual(len(report), 6)
        self.assertIn("installed", report["bandit"])

    def test_invalid_project_path_raises_error(self):
        orchestrator = ScannerOrchestrator()
        non_existent = self.project_path / "does_not_exist_dir"
        with self.assertRaises(FileNotFoundError):
            orchestrator.validate_project_path(str(non_existent))

    def test_orchestrator_execution_aggregation_and_deduplication(self):
        orchestrator = ScannerOrchestrator()

        mock_finding_1 = NormalizedFinding(
            title="Insecure MD5 Hash",
            description="Use of weak cryptographic hash MD5",
            scanner_name="bandit",
            rule_id="B303",
            severity=Severity.HIGH,
            file_path="main.py",
            line_number=10,
        )
        mock_finding_duplicate = NormalizedFinding(
            title="Insecure MD5 Hash",
            description="Use of weak cryptographic hash MD5",
            scanner_name="bandit",
            rule_id="B303",
            severity=Severity.HIGH,
            file_path="main.py",
            line_number=10,
        )

        mock_bandit = MagicMock()
        mock_bandit.is_available.return_value = True
        mock_bandit.scan.return_value = ScannerExecutionResult(
            scanner_name="bandit",
            status=ScanStatus.COMPLETED,
            findings=[mock_finding_1, mock_finding_duplicate],
            duration_seconds=0.5,
        )

        with patch.dict(orchestrator.scanners, {"bandit": mock_bandit}):
            overall_status, statuses, findings, duration = orchestrator.run_scan(
                project_path=self.project_path,
                scanners_to_run=["bandit"],
                parallel=False,
            )

            # Deduplication: 2 identical findings reduced to 1 unified finding
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule_id, "B303")
            self.assertIn("bandit", statuses)
            self.assertEqual(statuses["bandit"]["status"], ScanStatus.COMPLETED)
            self.assertEqual(statuses["bandit"]["findings_count"], 2)

            sev_counts = orchestrator.calculate_severity_counts(findings)
            self.assertEqual(sev_counts[Severity.HIGH], 1)
            self.assertEqual(sev_counts[Severity.CRITICAL], 0)
            self.assertEqual(sev_counts["total"], 1)

    def test_orchestrator_handles_missing_and_failed_scanners(self):
        orchestrator = ScannerOrchestrator()

        mock_missing = MagicMock()
        mock_missing.scan.return_value = ScannerExecutionResult(
            scanner_name="gitleaks",
            status=ScanStatus.NOT_INSTALLED,
            error_message="Executable not found",
        )

        mock_failed = MagicMock()
        mock_failed.scan.return_value = ScannerExecutionResult(
            scanner_name="semgrep",
            status=ScanStatus.FAILED,
            error_message="Syntax parse error",
            duration_seconds=1.2,
        )

        with patch.dict(orchestrator.scanners, {
            "gitleaks": mock_missing,
            "semgrep": mock_failed,
        }):
            overall_status, statuses, findings, duration = orchestrator.run_scan(
                project_path=self.project_path,
                scanners_to_run=["gitleaks", "semgrep"],
                parallel=False,
            )

            self.assertEqual(len(findings), 0)
            self.assertEqual(statuses["gitleaks"]["status"], ScanStatus.NOT_INSTALLED)
            self.assertEqual(statuses["semgrep"]["status"], ScanStatus.FAILED)
            self.assertIn("Syntax parse error", statuses["semgrep"]["error_message"])


class VulnoraScanCLITestCase(unittest.TestCase):
    """Verifies `vulnora scan` command line options and Rich outputs."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)
        runner.invoke(app, ["init", "--path", str(self.project_path)])
        (self.project_path / "app.py").write_text("# Safe dummy code\nx = 1\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_json_output_flag(self):
        result = runner.invoke(app, [
            "scan",
            "--path", str(self.project_path),
            "--scanner", "bandit",
            "--json",
        ])
        self.assertEqual(result.exit_code, 0)
        # Parse the output as valid JSON
        data = json.loads(result.output.strip())
        self.assertIn("status", data)
        self.assertIn("project_path", data)
        self.assertIn("scanner_statuses", data)
        self.assertIn("total_findings", data)
        self.assertIn("findings", data)
        self.assertIn("bandit", data["scanner_statuses"])

    def test_scan_output_file_export(self):
        out_file = self.project_path / "scan-report.json"
        result = runner.invoke(app, [
            "scan",
            "--path", str(self.project_path),
            "--scanner", "bandit",
            "--output", str(out_file),
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(out_file.exists())
        file_data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertIn("scanner_statuses", file_data)
        self.assertIn("findings", file_data)

    def test_scan_invalid_path_fails_safely(self):
        non_existent = self.project_path / "non_existent_folder_abc"
        result = runner.invoke(app, [
            "scan",
            "--path", str(non_existent),
        ])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Project directory does not exist", result.output)

    def test_scan_with_zap_target_flag(self):
        # When zap is specified with --zap-target, it should be processed
        with patch.object(ScannerOrchestrator, "run_scan") as mock_run:
            mock_run.return_value = (
                ScanStatus.COMPLETED,
                {"zap": {"scanner_name": "zap", "status": ScanStatus.COMPLETED, "duration_seconds": 0.5, "findings_count": 0}},
                [],
                0.5,
            )
            result = runner.invoke(app, [
                "scan",
                "--path", str(self.project_path),
                "--scanner", "zap",
                "--zap-target", "http://127.0.0.1:8000",
                "--json",
            ])
            self.assertEqual(result.exit_code, 0)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            self.assertEqual(kwargs.get("target_url"), "http://127.0.0.1:8000")
            self.assertIn("zap", kwargs.get("scanners_to_run"))


class VulnoraGuardScanIntegrationTestCase(unittest.TestCase):
    """Verifies `vulnora guard` triggers the security scanning engine on protected branches."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_path = Path(self.temp_dir.name)
        runner.invoke(app, ["init", "--path", str(self.project_path)])

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_guard_triggers_scanners_on_protected_branch(self):
        with patch.object(ScannerOrchestrator, "run_scan") as mock_run:
            mock_run.return_value = (
                ScanStatus.COMPLETED,
                {"gitleaks": {"scanner_name": "gitleaks", "status": ScanStatus.COMPLETED, "duration_seconds": 0.5, "findings_count": 1}},
                [
                    NormalizedFinding(
                        title="Critical Test Vulnerability",
                        description="Vulnerability description",
                        scanner_name="gitleaks",
                        rule_id="secret-rule",
                        severity=Severity.CRITICAL,
                        file_path="app.py",
                        line_number=1,
                    )
                ],
                0.5,
            )

            result = runner.invoke(app, [
                "guard",
                "--path", str(self.project_path),
                "--branch", "main",
            ])

            self.assertEqual(result.exit_code, 0)
            mock_run.assert_called_once()
            self.assertIn("HIGH-SECURITY GUARD ACTIVE", result.output)
            self.assertIn("Security Findings Breakdown", result.output)
            self.assertIn("CRITICAL", result.output)

    def test_backend_sync_graceful_offline(self):
        findings = [
            NormalizedFinding(
                title="Sample Finding",
                description="Sample",
                scanner_name="bandit",
                rule_id="B101",
                severity=Severity.LOW,
                file_path="main.py",
            )
        ]
        mock_cfg = {
            "backend": {
                "sync_history": True,
                "url": "http://127.0.0.1:59999",
            }
        }
        with patch("vulnora.scanners.sync.load_config", return_value=mock_cfg):
            with patch("vulnora.scanners.sync.is_backend_available", return_value=False):
                synced, msg = sync_scan_to_backend(
                    project_path=self.project_path,
                    target_url=None,
                    scanners=["bandit"],
                    findings=findings,
                    base_path=self.project_path,
                )
                self.assertFalse(synced)
                self.assertIn("offline", msg.lower())


if __name__ == "__main__":
    unittest.main()
