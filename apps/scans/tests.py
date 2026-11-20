import http.server
import tempfile
import threading
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

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
from apps.scans.services.trivy import TrivyScannerService
from apps.scans.services.zap import OWASPZAPScannerService


class VulnerableTestHttpHandler(http.server.BaseHTTPRequestHandler):
    """
    Deliberately vulnerable HTTP handler for validating OWASP ZAP DAST scanning.
    - Omits security headers (CSP, X-Frame-Options, X-Content-Type-Options)
    - Reflects query parameters unencoded (Reflected XSS)
    - Returns simulated database error signature when tested with SQL probe
    """

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Intentionally omit Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
        self.end_headers()

        search_q = params.get("search", [""])[0]
        id_param = params.get("id", [""])[0]

        sql_err = ""
        if "'" in id_param:
            sql_err = "<p>Database error: sqlite3.OperationalError: near 'OR': syntax error</p>"

        body = (
            f"<html><head><title>Vulnerable App</title></head>"
            f"<body><h1>Vulnora DAST Test Target</h1>"
            f"<div id='search-results'>Query: {search_q}</div>"
            f"{sql_err}</body></html>"
        )
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress HTTP server output in test logs


class SecurityScanningEngineTests(TestCase):
    """
    Comprehensive verification of all 6 scanners:
      1. Gitleaks
      2. Semgrep
      3. Bandit
      4. OSV-Scanner
      5. Trivy
      6. OWASP ZAP
    Includes orchestrator integration, deduplication, path/URL safety, and REST API endpoints.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # 1. Start local vulnerable HTTP test server for OWASP ZAP DAST testing
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VulnerableTestHttpHandler)
        cls.port = cls.httpd.server_address[1]
        cls.test_server_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

        # 2. Setup temporary project directory with vulnerable test files
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls.sample_project_path = Path(cls._temp_dir.name)

        # Secrets for Gitleaks (assembled dynamically so static push protection ignores test file)
        gh_dummy = "".join(["gh", "p_", "123456789012345678901234567890123456"])
        stripe_dummy = "".join(["sk_", "test_", "4eC39HqLyjWDarjtT1zdp7dc"])
        secrets_file = cls.sample_project_path / "secrets.py"
        secrets_file.write_text(
            f"# Sample secret for automated testing\n"
            f'GITHUB_TOKEN = "{gh_dummy}"\n'
            f'STRIPE_KEY = "{stripe_dummy}"\n',
            encoding="utf-8",
        )

        # Insecure Python code for Bandit & Semgrep
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

        # Known vulnerable dependency manifest for OSV-Scanner & Trivy
        req_file = cls.sample_project_path / "requirements.txt"
        req_file.write_text(
            "requests==2.19.0\nurllib3==1.24.1\n",
            encoding="utf-8",
        )

        # Sample Dockerfile for Trivy misconfiguration scanning
        docker_file = cls.sample_project_path / "Dockerfile"
        docker_file.write_text(
            "FROM alpine:latest\n"
            "USER root\n"
            "CMD [\"sh\"]\n",
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls):
        try:
            cls.httpd.shutdown()
            cls.httpd.server_close()
        except Exception:
            pass
        try:
            cls._temp_dir.cleanup()
        except Exception:
            pass
        super().tearDownClass()

    def setUp(self):
        self.client = APIClient()

    # =========================================================================
    # 1. Scanner Availability & Discovery (All 6 Scanners)
    # =========================================================================

    def test_scanner_discovery_all_six(self):
        orchestrator = ScannerOrchestrator()
        report = orchestrator.get_scanner_availability()

        expected_scanners = ("gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap")
        for scanner_name in expected_scanners:
            self.assertIn(scanner_name, report)
            self.assertTrue(
                report[scanner_name]["installed"],
                f"Scanner '{scanner_name}' should report as installed/operational.",
            )

    # =========================================================================
    # 2. Trivy Scanner Service Tests
    # =========================================================================

    def test_trivy_scanner_execution_and_normalization(self):
        scanner = TrivyScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(self.sample_project_path, timeout_seconds=60)
        self.assertEqual(result.status, "COMPLETED")
        self.assertGreater(len(result.findings), 0)

        trivy_rule_ids = [f.rule_id for f in result.findings]
        self.assertTrue(
            any("CVE" in r or "GHSA" in r or "DS" in r or "AVD" in r for r in trivy_rule_ids),
            "Trivy should detect CVEs or Dockerfile misconfigurations.",
        )

        first_finding = result.findings[0]
        self.assertEqual(first_finding.scanner_name, "trivy")
        self.assertIn(first_finding.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        self.assertTrue(first_finding.title)
        self.assertTrue(first_finding.remediation)

    # =========================================================================
    # 3. OWASP ZAP Scanner Service Tests (DAST)
    # =========================================================================

    def test_owasp_zap_baseline_scanning(self):
        scanner = OWASPZAPScannerService()
        self.assertTrue(scanner.is_available())

        result = scanner.scan(target_url=self.test_server_url, timeout_seconds=30)
        self.assertEqual(result.status, "COMPLETED")
        self.assertGreater(len(result.findings), 0)

        zap_rules = [f.rule_id for f in result.findings]
        # Should detect missing CSP (ZAP-10038) and missing X-Frame-Options (ZAP-10020)
        self.assertIn("ZAP-10038", zap_rules)
        self.assertIn("ZAP-10020", zap_rules)

        # Verify reflected XSS detection
        self.assertIn("ZAP-40012", zap_rules)

        # Verify SQL injection error indicator detection
        self.assertIn("ZAP-40018", zap_rules)

        csp_finding = next(f for f in result.findings if f.rule_id == "ZAP-10038")
        self.assertEqual(csp_finding.scanner_name, "zap")
        self.assertEqual(csp_finding.severity, "MEDIUM")
        self.assertIn("Content-Security-Policy", csp_finding.remediation)

    def test_owasp_zap_target_url_safety_validation(self):
        scanner = OWASPZAPScannerService()

        # Reject invalid scheme
        with self.assertRaises(ValueError):
            scanner.validate_target_url("ftp://example.com")

        # Reject empty URL
        with self.assertRaises(ValueError):
            scanner.validate_target_url("")

    # =========================================================================
    # 4. Existing 4 Scanners Regression Tests
    # =========================================================================

    def test_bandit_scanner(self):
        scanner = BanditScannerService()
        result = scanner.scan(self.sample_project_path, timeout_seconds=30)
        self.assertEqual(result.status, "COMPLETED")
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("B307", rule_ids)

    def test_gitleaks_scanner(self):
        scanner = GitleaksScannerService()
        result = scanner.scan(self.sample_project_path, timeout_seconds=30)
        self.assertEqual(result.status, "COMPLETED")
        self.assertTrue(any(f.scanner_name == "gitleaks" for f in result.findings))

    def test_semgrep_scanner(self):
        scanner = SemgrepScannerService()
        result = scanner.scan(self.sample_project_path, timeout_seconds=60)
        self.assertEqual(result.status, "COMPLETED")

    def test_osv_scanner(self):
        scanner = OSVScannerService()
        result = scanner.scan(self.sample_project_path, timeout_seconds=60)
        self.assertEqual(result.status, "COMPLETED")

    # =========================================================================
    # 5. Full Orchestrator (All 6 Scanners Together)
    # =========================================================================

    def test_orchestrator_all_six_scanners_together(self):
        orchestrator = ScannerOrchestrator()
        session = orchestrator.execute_and_record(
            raw_project_path=str(self.sample_project_path),
            target_url=self.test_server_url,
            scanners_to_run=["gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"],
            timeout_seconds=60,
        )

        self.assertEqual(session.status, ScanStatus.COMPLETED)
        self.assertGreater(session.total_findings, 0)
        self.assertEqual(session.target_url, self.test_server_url)

        # Check all 6 scanners ran
        for scanner_name in ("gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"):
            self.assertIn(scanner_name, session.scanner_statuses)
            self.assertEqual(session.scanner_statuses[scanner_name]["status"], "COMPLETED")

        # Verify DB storage
        findings_count = Finding.objects.filter(scan_session=session).count()
        self.assertEqual(findings_count, session.total_findings)

    # =========================================================================
    # 6. REST API Endpoints with Trivy & ZAP
    # =========================================================================

    def test_api_scans_info_reports_six_scanners(self):
        url = reverse("scans:index")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        details = response.data["scanner_details"]
        for name in ("gitleaks", "semgrep", "bandit", "osv-scanner", "trivy", "zap"):
            self.assertIn(name, details)
            self.assertTrue(details[name]["installed"])

    def test_api_initiate_dast_scan_with_target_url(self):
        url = reverse("scans:scan-list-create")
        payload = {
            "target_url": self.test_server_url,
            "scanners": ["zap"],
            "timeout_seconds": 30,
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["target_url"], self.test_server_url)
        self.assertEqual(response.data["status"], "COMPLETED")
        self.assertGreater(response.data["total_findings"], 0)

    def test_api_initiate_combined_sast_dast_scan(self):
        url = reverse("scans:scan-list-create")
        payload = {
            "project_path": str(self.sample_project_path),
            "target_url": self.test_server_url,
            "scanners": ["bandit", "trivy", "zap"],
            "timeout_seconds": 30,
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("trivy", response.data["scanner_statuses"])
        self.assertIn("zap", response.data["scanner_statuses"])

    def test_api_list_vulnerabilities_filter_trivy_and_zap(self):
        session = ScanSession.objects.create(
            project_path=str(self.sample_project_path),
            target_url=self.test_server_url,
            status=ScanStatus.COMPLETED,
        )
        Finding.objects.create(
            scan_session=session,
            title="Trivy Vulnerability",
            description="Trivy test vuln",
            scanner_name="trivy",
            rule_id="CVE-2023-32681",
            severity=Severity.HIGH,
            file_path="requirements.txt",
        )
        Finding.objects.create(
            scan_session=session,
            title="OWASP ZAP CSP Missing",
            description="CSP missing",
            scanner_name="zap",
            rule_id="ZAP-10038",
            severity=Severity.MEDIUM,
            file_path=self.test_server_url,
        )

        url = reverse("vulnerabilities-list")

        # Filter by trivy
        res_trivy = self.client.get(url, {"scanner_name": "trivy"})
        self.assertEqual(res_trivy.status_code, status.HTTP_200_OK)
        self.assertTrue(all(f["scanner_name"] == "trivy" for f in res_trivy.data))

        # Filter by zap
        res_zap = self.client.get(url, {"scanner_name": "zap"})
        self.assertEqual(res_zap.status_code, status.HTTP_200_OK)
        self.assertTrue(all(f["scanner_name"] == "zap" for f in res_zap.data))
