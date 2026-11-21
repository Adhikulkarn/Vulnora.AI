"""
Unit tests for the Multi-Language AST Normalizer (`vulnora.immune.ast_normalizer`).
"""

import pytest

from vulnora.immune.ast_normalizer import ASTNormalizer, NormalizedAST


class TestASTNormalizer:
    """Tests for multi-language parsing, enclosing block extraction, and variable invariance."""

    @pytest.fixture
    def normalizer(self) -> ASTNormalizer:
        return ASTNormalizer()

    def test_detect_language(self, normalizer: ASTNormalizer):
        assert normalizer.detect_language("app/server.py") == "python"
        assert normalizer.detect_language("src/index.ts") == "typescript"
        assert normalizer.detect_language("web/app.jsx") == "javascript"
        assert normalizer.detect_language("main.go") == "go"
        assert normalizer.detect_language("src/lib.rs") == "rust"
        assert normalizer.detect_language("com/service/Main.java") == "java"
        assert normalizer.detect_language("Dockerfile") == "dockerfile"
        assert normalizer.detect_language("main.tf") == "hcl"
        assert normalizer.detect_language("config.yaml") == "yaml"
        assert normalizer.detect_language("script.unknown") == "generic"

    def test_variable_rename_invariance_python(self, normalizer: ASTNormalizer):
        code1 = """
def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
"""
        code2 = """
def fetch_account(account_number):
    sql = f"SELECT * FROM accounts WHERE id = {account_number}"
    db_conn.execute(sql)
"""
        norm1 = normalizer.normalize(code1, language="python")
        norm2 = normalizer.normalize(code2, language="python")

        assert isinstance(norm1, NormalizedAST)
        assert isinstance(norm2, NormalizedAST)

        similarity = normalizer.calculate_similarity(norm1.ast_signature, norm2.ast_signature)
        assert similarity >= 0.85, f"Expected similarity >= 0.85, got {similarity}"

    def test_variable_rename_invariance_go(self, normalizer: ASTNormalizer):
        code1 = """
func HandleRequest(payload string) {
    untrusted := payload
    exec.Command("sh", "-c", untrusted).Run()
}
"""
        code2 = """
func ProcessInput(data string) {
    commandString := data
    exec.Command("sh", "-c", commandString).Run()
}
"""
        norm1 = normalizer.normalize(code1, language="go")
        norm2 = normalizer.normalize(code2, language="go")

        similarity = normalizer.calculate_similarity(norm1.ast_signature, norm2.ast_signature)
        assert similarity >= 0.85, f"Expected similarity >= 0.85, got {similarity}"

    def test_variable_rename_invariance_javascript_typescript(self, normalizer: ASTNormalizer):
        code1 = """
function authenticateUser(req, res) {
    const userInput = req.body.token;
    eval(userInput);
}
"""
        code2 = """
function verifySession(request, response) {
    const rawData = request.body.token;
    eval(rawData);
}
"""
        norm1 = normalizer.normalize(code1, language="javascript")
        norm2 = normalizer.normalize(code2, language="javascript")

        similarity = normalizer.calculate_similarity(norm1.ast_signature, norm2.ast_signature)
        assert similarity >= 0.85, f"Expected similarity >= 0.85, got {similarity}"

    def test_variable_rename_invariance_rust(self, normalizer: ASTNormalizer):
        code1 = """
fn verify_token(api_key: &str) -> bool {
    let secret = "super_secret_admin_token";
    api_key == secret
}
"""
        code2 = """
fn check_credential(provided_hash: &str) -> bool {
    let internal_master = "super_secret_admin_token";
    provided_hash == internal_master
}
"""
        norm1 = normalizer.normalize(code1, language="rust")
        norm2 = normalizer.normalize(code2, language="rust")

        similarity = normalizer.calculate_similarity(norm1.ast_signature, norm2.ast_signature)
        assert similarity >= 0.85, f"Expected similarity >= 0.85, got {similarity}"

    def test_anonymization_strips_proprietary_identifiers(self, normalizer: ASTNormalizer):
        code = """
def process_client_ssn(secret_social_security_number, corporate_secret_api_key):
    database_table_acme_corp = "acme_classified_users"
    return execute_query(secret_social_security_number, corporate_secret_api_key)
"""
        normalized = normalizer.normalize(code, language="python")

        # Verify proprietary names are wiped from template and signature
        assert "secret_social_security_number" not in normalized.anonymized_template
        assert "corporate_secret_api_key" not in normalized.anonymized_template
        assert "acme_classified_users" not in normalized.anonymized_template
        assert "acme_corp" not in normalized.anonymized_template

        # Identifiers converted to VAR_N and string to STR_LIT
        assert "VAR_" in normalized.anonymized_template
        assert "STR_LIT" in normalized.anonymized_template

    def test_enclosing_block_extraction(self, normalizer: ASTNormalizer):
        source = """import os
import sys

def outer_helper():
    pass

def vulnerable_endpoint(user_input):
    print("starting endpoint")
    os.system(user_input)
    print("finished endpoint")

def after_helper():
    pass
"""
        # Line 9 is os.system(user_input)
        block = normalizer.extract_enclosing_block(source, line_number=9, language="python")
        assert "os.system(user_input)" in block
        assert "vulnerable_endpoint" in block

    def test_token_fallback_when_parser_unavailable(self, normalizer: ASTNormalizer):
        # Force fallback by specifying non-existent grammar
        code = "rule vulnerable_config { key = 'sensitive_value'; threshold = 99; }"
        norm = normalizer._normalize_token_fallback(code, language="custom_dsl", exact_hash="abc123hash")

        assert norm.language == "custom_dsl"
        assert "sensitive_value" not in norm.anonymized_template
        assert "STR_LIT" in norm.anonymized_template
        assert "0" in norm.anonymized_template
        assert len(norm.structural_tokens) > 0
