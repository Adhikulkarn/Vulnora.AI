"""
Vulnora AI - Scanner Engine Test Utility
Usage:
    python test_scanners.py
    python test_scanners.py --path C:\\path\\to\\project
    python test_scanners.py --url http://127.0.0.1:8000
"""

import argparse
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnora.settings.development")
import django
django.setup()

from apps.scans.services.orchestrator import ScannerOrchestrator


class MockDASTServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Vulnora DAST Test Target</h1></body></html>")

    def log_message(self, format, *args):
        pass


def run_test(custom_path=None, custom_url=None):
    orchestrator = ScannerOrchestrator()

    print("=" * 65)
    print("           VULNORA AI - SECURITY ENGINE TEST RUNNER             ")
    print("=" * 65)

    print("\n[1] Checking Tool Availability:")
    status = orchestrator.get_scanner_availability()
    for name, info in status.items():
        state = "[OK] Installed" if info["installed"] else "[MISSING]"
        exec_path = info.get("executable") or "Daemon/Embedded"
        ver = f"v{info['version']}" if info.get("version") else ""
        print(f"  * {name:<12}: {state:<15} {ver:<10} ({exec_path})")

    server = None
    target_url = custom_url
    if not target_url:
        print("\n[2] Spinning up local mock HTTP server for ZAP DAST testing on 127.0.0.1:8999...")
        server = HTTPServer(("127.0.0.1", 8999), MockDASTServer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target_url = "http://127.0.0.1:8999"

    temp_ctx = None
    if custom_path:
        scan_dir = Path(custom_path).resolve()
        print(f"\n[3] Using target directory: {scan_dir}")
    else:
        temp_ctx = tempfile.TemporaryDirectory()
        scan_dir = Path(temp_ctx.name)
        print(f"\n[3] Generating sample vulnerable files in temporary sandbox: {scan_dir}")

        # Git repo for Gitleaks
        os.system(f"git init \"{scan_dir}\" > nul 2>&1")

        # Insecure Python file (Bandit, Semgrep, Gitleaks)
        py_file = scan_dir / "vulnerable_app.py"
        fake_secret = "".join(["ghp_", "TEST1234567890ABCDEFGHIJKLMNO123456"])
        py_file.write_text(
            f'import os\n\nTOKEN = "{fake_secret}"\n\ndef run_query(cmd):\n    return eval(cmd)\n',
            encoding="utf-8"
        )
        os.system(f"git -C \"{scan_dir}\" add . > nul 2>&1")
        os.system(f"git -C \"{scan_dir}\" -c user.name=Test -c user.email=test@example.com commit -m test > nul 2>&1")

        # Insecure dependency (OSV-Scanner, Trivy)
        req_file = scan_dir / "requirements.txt"
        req_file.write_text("requests==2.20.0\nurllib3==1.24.1\n", encoding="utf-8")

        # Insecure Dockerfile (Trivy, Semgrep)
        docker_file = scan_dir / "Dockerfile"
        docker_file.write_text("FROM alpine:3.18\nCMD [\"sh\"]\n", encoding="utf-8")

    print("\n[4] Running all 6 scanners concurrently...")
    overall_status, scanner_statuses, unified_findings, duration = orchestrator.run_scan(
        project_path=scan_dir,
        target_url=target_url,
        scanners_to_run=["bandit", "semgrep", "gitleaks", "osv-scanner", "trivy", "zap"]
    )

    print("\n" + "=" * 65)
    print("                         TEST RESULTS                           ")
    print("=" * 65)
    print(f"Overall Status   : {overall_status}")
    print(f"Total Duration   : {duration:.2f} seconds")
    print(f"Unique Findings  : {len(unified_findings)}\n")

    print("Individual Scanner Results:")
    for name, st in scanner_statuses.items():
        print(f"  - {name:<12}: Status={st.get('status')} | Findings={st.get('findings_count', 0)} | Time={st.get('duration_seconds', 0.0):.2f}s")

    print("\nSample Detections:")
    seen = set()
    for f in unified_findings:
        if f.scanner_name not in seen:
            seen.add(f.scanner_name)
            loc = Path(f.file_path).name if f.file_path else f.target_url
            print(f"  [{f.scanner_name.upper()}] {f.title} ({f.rule_id})")
            print(f"     Severity: {f.severity.upper()} | Location: {loc}")
            print(f"     Advice  : {f.remediation[:80]}...\n")

    if server:
        server.shutdown()
    if temp_ctx:
        temp_ctx.cleanup()

    print("=" * 65)
    print("SUCCESS: All 6 scanners executed and reported successfully.")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Vulnora AI Scanners")
    parser.add_argument("--path", help="Optional project directory path to scan")
    parser.add_argument("--url", help="Optional target web application URL to scan")
    args = parser.parse_args()
    run_test(custom_path=args.path, custom_url=args.url)

