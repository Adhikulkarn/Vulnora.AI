import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.scans.models import Finding, ScanSession, ScanStatus, Severity
from apps.scans.services.bandit import BanditScannerService
from apps.scans.services.data_structures import NormalizedFinding
from apps.scans.services.gitleaks import GitleaksScannerService
from apps.scans.services.orchestrator import ScannerOrchestrator
from apps.scans.services.osv_scanner import OSVScannerService
from apps.scans.services.semgrep import SemgrepScannerService


class SecurityScanningEngineTests(TestCase):
    """
    Comprehensive verification of individual scanners, normalization, orchestrator,
    database persistence, safety validations, and REST API endpoints.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls.sample_project_path = Path(cls._temp_dir.name)

        # 1. Sample secrets file for Gitleaks (assembled dynamically so static scanner does not flag test code)
        gh_dummy = "".join(["gh", "p_", "123456789012345678901234567890123456"])
        stripe_dummy = "".join(["sk_", "test_", "4eC39HqLyjWDarjtT1zdp7dc"])
        secrets_file = cls.sample_project_path / "secrets.py"
        secrets_file.write_text(
            f"# Sample secret for automated testing\n"
            f'GITHUB_TOKEN = "{gh_dummy}"\n'
            f'STRIPE_KEY = "{stripe_dummy}"\n',
            encoding="utf-8",
        )

        # 2. Insecure Python code for Bandit & Semgrep
        app_file = cls.sample_project_path / "vulnerable_app.py"
        app_file.write_text(
            'import subprocess\n'
            'import yaml\n\n'
            'def execute_user_calculation(user_formula: str):\n'
            '    return eval(user_formula)\n\n'
            'def run_system_diagnostic(user_flag: str):\n'
            '    return subprocess.Popen(f"ping {user_flag}", shell=True)\n\n'
            'def parse_config(yaml_string: str):\n'
            '    return yaml.load(yaml_string)\n',
            encoding="utf-8",
        )

        # 3. Known vulnerable dependency manifest for OSV-Scanner
        req_file = cls.sample_project_path / "requirements.txt"
        req_file.write_text(
            "requests==2.19.0\nurllib3==1.24.1\n",
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls):
        try:
            cls._temp_dir.cleanup()
        except Exception:
            pass
        super().tearDownClass()

    def setUp(self):
        self.client = APIClient()

    # =========================================================================
    # 1. Scanner Availability & CLI Discovery Tests
    # =========================================================================

    def test_scanner_discovery(self):
        orchestrator = ScannerOrchestrator()
        report = orchestrator.get_scanner_availability()

        for scanner_name in ("gitleaks", "semgrep", "bandit", "osv-scanner"):
            self.assertIn(scanner_name, report)
            self.assertTrue(
                report[scanner_name]["installed"],
                f"Scanner '{scanner_name}' should be installed and available on system.",
            )
            self.assertIsNotNone(report[scanner_name]["executable"])

    # =========================================================================
    # 2. Individual Scanner Unit & Execution Tests
    # =========================================================================

    def test_bandit_scanner_execution_and_normalization(self):
        scanner = BanditScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(self.sample_project_path, timeout_seconds=30)
        self.assertEqual(result.status, "COMPLETED")
        self.assertGreater(len(result.findings), 0)

        # Verify normalized fields
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("B307", rule_ids)  # eval() detection
        self.assertIn("B602", rule_ids)  # subprocess shell=True

        eval_finding = next(f for f in result.findings if f.rule_id == "B307")
        self.assertEqual(eval_finding.scanner_name, "bandit")
        self.assertEqual(eval_finding.severity, "MEDIUM")
        self.assertIn("ast.literal_eval", eval_finding.remediation)
        self.assertIn("vulnerable_app.py", eval_finding.file_path)
        self.assertIsNotNone(eval_finding.line_number)

    def test_gitleaks_scanner_execution_and_redaction(self):
        scanner = GitleaksScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(self.sample_project_path, timeout_seconds=30)
        self.assertEqual(result.status, "COMPLETED")
        self.assertGreater(len(result.findings), 0)

        # Verify that secret strings are completely masked
        for finding in result.findings:
            self.assertEqual(finding.scanner_name, "gitleaks")
            self.assertIn(finding.severity, ("HIGH", "CRITICAL"))
            self.assertIn("secrets.py", finding.file_path)
            # Ensure raw secret is not leaked in raw_details
            raw = finding.raw_details
            self.assertEqual(raw.get("secret_masked"), "***REDACTED***")

    def test_semgrep_scanner_execution_and_normalization(self):
        scanner = SemgrepScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(self.sample_project_path, timeout_seconds=60)
        self.assertEqual(result.status, "COMPLETED")

        # Find eval finding
        rule_ids = [f.rule_id for f in result.findings]
        eval_rules = [r for r in rule_ids if "eval" in r.lower()]
        self.assertTrue(len(eval_rules) > 0, "Semgrep should detect eval pattern.")

        for f in result.findings:
            self.assertEqual(f.scanner_name, "semgrep")
            self.assertIn(f.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertTrue(f.title)
            self.assertTrue(f.description)

    def test_osv_scanner_execution_and_normalization(self):
        scanner = OSVScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(self.sample_project_path, timeout_seconds=60)
        self.assertEqual(result.status, "COMPLETED")
        self.assertGreater(len(result.findings), 0)

        # Verify dependency finding
        packages_flagged = [f.raw_details.get("package") for f in result.findings]
        self.assertIn("requests", packages_flagged)

        first_vuln = result.findings[0]
        self.assertEqual(first_vuln.scanner_name, "osv-scanner")
        self.assertIn("requirements.txt", first_vuln.file_path)
        self.assertIn("Upgrade", first_vuln.remediation)

    # =========================================================================
    # 3. Scanner Orchestrator & Persistence Tests
    # =========================================================================

    def test_orchestrator_execute_and_record(self):
        orchestrator = ScannerOrchestrator()
        session = orchestrator.execute_and_record(
            raw_project_path=str(self.sample_project_path),
            scanners_to_run=["bandit", "gitleaks"],  # Fast deterministic test
            timeout_seconds=30,
        )

        # Verify scan session record
        self.assertIsNotNone(session.id)
        self.assertEqual(session.status, ScanStatus.COMPLETED)
        self.assertGreater(session.total_findings, 0)
        self.assertGreater(session.duration_seconds, 0)
        self.assertIn("bandit", session.scanner_statuses)
        self.assertIn("gitleaks", session.scanner_statuses)

        # Verify database relations
        db_findings = Finding.objects.filter(scan_session=session)
        self.assertEqual(db_findings.count(), session.total_findings)

        # Verify deduplication
        fingerprints = [f.fingerprint for f in db_findings]
        self.assertEqual(len(fingerprints), len(set(fingerprints)), "Fingerprints must be unique.")

    def test_orchestrator_handles_missing_scanner_gracefully(self):
        orchestrator = ScannerOrchestrator()

        # Mock a scanner being not installed
        with patch.object(orchestrator.scanners["bandit"], "is_available", return_value=False):
            with patch.object(orchestrator.scanners["bandit"], "find_executable", return_value=None):
                overall_status, statuses, findings, _ = orchestrator.run_scan(
                    project_path=self.sample_project_path,
                    scanners_to_run=["bandit", "gitleaks"],
                    parallel=False,
                )

                self.assertEqual(statuses["bandit"]["status"], "NOT_INSTALLED")
                self.assertEqual(statuses["gitleaks"]["status"], "COMPLETED")
                self.assertEqual(overall_status, ScanStatus.PARTIALLY_FAILED)

    def test_orchestrator_path_safety_validations(self):
        orchestrator = ScannerOrchestrator()

        # Non-existent path
        with self.assertRaises(FileNotFoundError):
            orchestrator.validate_project_path("C:/invalid_non_existent_directory_12345")

        # System root path
        with self.assertRaises(PermissionError):
            orchestrator.validate_project_path("C:\\")

    # =========================================================================
    # 4. REST API Endpoint Tests
    # =========================================================================

    def test_api_scans_module_overview(self):
        url = reverse("scans:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["module"], "scans")
        self.assertIn("scanner_details", response.data)

    def test_api_initiate_scan_success(self):
        url = reverse("scans:scan-list-create")
        payload = {
            "project_path": str(self.sample_project_path),
            "scanners": ["bandit"],
            "timeout_seconds": 30,
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", response.data)
        self.assertEqual(response.data["status"], "COMPLETED")
        self.assertGreater(response.data["total_findings"], 0)
        self.assertIn("findings", response.data)

    def test_api_initiate_scan_invalid_path(self):
        url = reverse("scans:scan-list-create")
        payload = {"project_path": "C:\\nonexistent\\random\\directory\\xyz"}
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_api_list_scans(self):
        # Create a mock session
        ScanSession.objects.create(
            project_path=str(self.sample_project_path),
            status=ScanStatus.COMPLETED,
            total_findings=2,
        )
        url = reverse("scans:scan-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_api_retrieve_scan_detail(self):
        session = ScanSession.objects.create(
            project_path=str(self.sample_project_path),
            status=ScanStatus.COMPLETED,
            total_findings=1,
            medium_count=1,
        )
        Finding.objects.create(
            scan_session=session,
            title="Test Finding",
            description="Test Description",
            scanner_name="bandit",
            rule_id="B307",
            severity=Severity.MEDIUM,
            file_path="test.py",
            line_number=10,
        )

        url = reverse("scans:scan-detail", kwargs={"pk": session.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(str(response.data["id"]), str(session.id))
        self.assertEqual(len(response.data["findings"]), 1)
        self.assertEqual(response.data["findings"][0]["rule_id"], "B307")

    def test_api_retrieve_scan_summary(self):
        session = ScanSession.objects.create(
            project_path=str(self.sample_project_path),
            status=ScanStatus.COMPLETED,
            total_findings=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            scanner_statuses={"bandit": {"status": "COMPLETED", "findings_count": 3}},
            duration_seconds=1.25,
        )

        url = reverse("scans:scan-summary", kwargs={"pk": session.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(str(response.data["scan_id"]), str(session.id))
        self.assertEqual(response.data["severity_summary"]["total"], 3)
        self.assertEqual(response.data["severity_summary"]["CRITICAL"], 1)
        self.assertEqual(response.data["severity_summary"]["HIGH"], 1)
        self.assertEqual(response.data["severity_summary"]["MEDIUM"], 1)

    def test_api_list_vulnerabilities(self):
        session = ScanSession.objects.create(
            project_path=str(self.sample_project_path),
            status=ScanStatus.COMPLETED,
        )
        Finding.objects.create(
            scan_session=session,
            title="Secret Leak",
            description="PAT leaked",
            scanner_name="gitleaks",
            rule_id="github-pat",
            severity=Severity.CRITICAL,
            file_path="secrets.py",
            line_number=5,
        )

        url = reverse("vulnerabilities-list")
        response = self.client.get(url, {"severity": "CRITICAL"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["scanner_name"], "gitleaks")
        self.assertEqual(response.data[0]["severity"], "CRITICAL")
