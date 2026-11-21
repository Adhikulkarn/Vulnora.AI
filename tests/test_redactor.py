"""
Unit tests for the Pre-Egress Secret Redactor (`vulnora.engine.redactor`).
"""

from pathlib import Path
import pytest

from vulnora.engine.redactor import REDACTION_MARKER, SecretRedactor


class TestSecretRedactor:
    """Tests for multi-pattern and entropy-based secret detection and scrubbing."""

    @pytest.fixture
    def redactor(self) -> SecretRedactor:
        return SecretRedactor()

    def test_aws_access_key_redaction(self, redactor: SecretRedactor):
        raw = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        res = redactor.redact(raw)
        assert res.secrets_found_count == 1
        assert "AWS_ACCESS_KEY" in res.detected_types
        assert "AKIAIOSFODNN7EXAMPLE" not in res.redacted_text
        assert f'aws_access_key_id = "{REDACTION_MARKER}"' in res.redacted_text

    def test_aws_secret_key_redaction(self, redactor: SecretRedactor):
        raw = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 1
        assert "AWS_SECRET_KEY" in res.detected_types
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in res.redacted_text
        assert REDACTION_MARKER in res.redacted_text

    def test_github_token_redaction(self, redactor: SecretRedactor):
        prefix_ghp = "ghp"
        prefix_pat = "github_pat"
        token_classic = f"{prefix_ghp}_123456789012345678901234567890123456"
        token_fine = f"{prefix_pat}_11AAAAAAA0000000000000_12345678901234567890123456789012345678901234567890123456789"
        
        raw = f'auth_token = "{token_classic}"\npat = "{token_fine}"'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 2
        assert "GITHUB_TOKEN" in res.detected_types
        assert token_classic not in res.redacted_text
        assert token_fine not in res.redacted_text
        assert res.redacted_text.count(REDACTION_MARKER) >= 2

    def test_google_api_key_redaction(self, redactor: SecretRedactor):
        prefix_aiza = "AIza"
        api_key = f"{prefix_aiza}SyD-1234567890abcdefghijklmnopqrst"
        raw = f'const GOOGLE_MAPS_KEY = "{api_key}";'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 1
        assert "GOOGLE_API_KEY" in res.detected_types
        assert api_key not in res.redacted_text
        assert REDACTION_MARKER in res.redacted_text

    def test_slack_and_stripe_tokens(self, redactor: SecretRedactor):
        # Assembled dynamically to avoid GitHub Push Protection false positives
        prefix_slack = "xoxb"
        prefix_stripe = "sk_live"
        slack = f"{prefix_slack}-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
        stripe = f"{prefix_stripe}_51Abcdefghijklmnopqrstuvwx9999"
        raw = f'slack_token = "{slack}"\nstripe_secret = "{stripe}"'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 2
        assert "SLACK_TOKEN" in res.detected_types
        assert "STRIPE_KEY" in res.detected_types
        assert slack not in res.redacted_text
        assert stripe not in res.redacted_text

    def test_jwt_token_redaction(self, redactor: SecretRedactor):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw = f'Authorization: Bearer {jwt}'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 1
        assert jwt not in res.redacted_text
        assert REDACTION_MARKER in res.redacted_text

    def test_db_connection_url_password_redaction(self, redactor: SecretRedactor):
        raw_url = "postgres://postgres:super_secret_pw987@db.internal.company.com:5432/production_db"
        res = redactor.redact(raw_url)
        assert res.secrets_found_count == 1
        assert "DB_CONNECTION_URL" in res.detected_types
        assert "super_secret_pw987" not in res.redacted_text
        # Scheme, username, host, port, and DB must remain intact!
        expected = f"postgres://postgres:{REDACTION_MARKER}@db.internal.company.com:5432/production_db"
        assert res.redacted_text == expected

    def test_pem_private_key_line_preservation(self, redactor: SecretRedactor):
        pem_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3L5abcdefghijklmnopqrstuvwxyz1234567890==
MIIEowIBAAKCAQEA0Y3L5abcdefghijklmnopqrstuvwxyz1234567890==
MIIEowIBAAKCAQEA0Y3L5abcdefghijklmnopqrstuvwxyz1234567890==
-----END RSA PRIVATE KEY-----"""
        code = f"""import ssl

key_data = \"\"\"{pem_key}\"\"\"

def setup_ssl():
    return ssl.create_default_context()
"""
        initial_line_count = len(code.splitlines())
        res = redactor.redact(code)

        assert res.secrets_found_count >= 1
        assert "PEM_PRIVATE_KEY" in res.detected_types
        assert "MIIEowIBAAKCAQEA" not in res.redacted_text
        assert REDACTION_MARKER in res.redacted_text
        # Enforce that line count is preserved exactly so AST and scanner line numbers never drift
        redacted_line_count = len(res.redacted_text.splitlines())
        assert redacted_line_count == initial_line_count

    def test_generic_credential_assignment(self, redactor: SecretRedactor):
        raw = """
password = "ultra_confidential_pass_456"
client_secret = "secret_client_token_xyz"
"""
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 2
        assert "ultra_confidential_pass_456" not in res.redacted_text
        assert "secret_client_token_xyz" not in res.redacted_text
        assert f'password = "{REDACTION_MARKER}"' in res.redacted_text
        assert f'client_secret = "{REDACTION_MARKER}"' in res.redacted_text

    def test_entropy_calculation(self, redactor: SecretRedactor):
        # Repetitive low entropy
        low = redactor.calculate_entropy("aaaaaaaaaaaaaaaaaaaa")
        assert low == 0.0

        # Uniform character distribution
        high = redactor.calculate_entropy("aB9#qZ2$xL8!pM5*rT1@")
        assert high > 3.8

    def test_high_entropy_secret_assignment(self, redactor: SecretRedactor):
        raw = 'data_signature = "qZ8$vL2#mK9!pX5*rW1@bC4^"'
        res = redactor.redact(raw)
        assert res.secrets_found_count >= 1
        assert "HIGH_ENTROPY_TOKEN" in res.detected_types
        assert "qZ8$vL2#mK9!pX5*rW1@bC4^" not in res.redacted_text
        assert REDACTION_MARKER in res.redacted_text

    def test_non_secret_code_preservation(self, redactor: SecretRedactor):
        code = """
import os
import sys

def calculate_discount(price: float, rate: float = 0.15) -> float:
    discount = price * rate
    return price - discount

class OrderManager:
    def __init__(self, order_id: str):
        self.order_id = order_id
        self.status = "pending"
"""
        res = redactor.redact(code)
        assert res.secrets_found_count == 0
        assert len(res.detected_types) == 0
        assert res.redacted_text == code

    def test_redact_file(self, tmp_path: Path, redactor: SecretRedactor):
        file_path = tmp_path / "secrets.env"
        file_path.write_text('GITHUB_TOKEN="ghp_123456789012345678901234567890123456"\n', encoding="utf-8")
        res = redactor.redact_file(file_path)
        assert res.secrets_found_count == 1
        assert "GITHUB_TOKEN" in res.detected_types
        assert "ghp_123456" not in res.redacted_text

    def test_is_secret_helper(self, redactor: SecretRedactor):
        assert redactor.is_secret('api_key = "AIzaSyD-1234567890abcdefghijklmnopqrst"') is True
        assert redactor.is_secret('x = 42\ny = "normal string"') is False
