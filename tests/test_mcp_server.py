"""
Unit tests for the Local Model Context Protocol (MCP) Server (`vulnora.engine.mcp_server`).
"""

import io
import json
from pathlib import Path
import pytest

from vulnora.core.models import AgentRule, Finding, Severity
from vulnora.engine.agents_md import AgentsMDWriter
from vulnora.engine.mcp_server import VulnoraMCPServer
from vulnora.immune.memory_store import ImmuneMemoryStore


class TestVulnoraMCPServer:
    """Tests for stdio JSON-RPC 2.0 protocol and MCP tool dispatch."""

    @pytest.fixture
    def server(self, tmp_path: Path) -> VulnoraMCPServer:
        mem_file = tmp_path / "memory.json"
        store = ImmuneMemoryStore(memory_path=mem_file)
        writer = AgentsMDWriter(repo_root=tmp_path)

        # Populate sample antibody and agent rule
        finding = Finding(
            rule_id="B605",
            scanner_name="bandit",
            severity=Severity.HIGH,
            title="Shell injection",
            description="os.system call",
            file_path="app.py",
        )
        store.remember_finding(
            finding=finding,
            code_snippet="os.system(cmd)",
            resolution="REMEDIATED",
            language="python",
            agents_rule="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
        )
        writer.add_rule(
            AgentRule(
                rule_id="B605",
                language="python",
                rule_text="Never use os.system(); always pass argument list to subprocess.run(..., shell=False).",
            )
        )

        return VulnoraMCPServer(repo_root=tmp_path, immune_store=store, agents_writer=writer)

    def test_initialize_request(self, server: VulnoraMCPServer):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        resp = server.handle_request(req)
        assert resp is not None
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        assert resp["result"]["serverInfo"]["name"] == "vulnora-mcp-server"

    def test_tools_list_request(self, server: VulnoraMCPServer):
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        resp = server.handle_request(req)
        assert resp is not None
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "vulnora_query_immune_memory" in tool_names
        assert "vulnora_get_security_guardrails" in tool_names
        assert "vulnora_check_code_snippet" in tool_names

    def test_tool_call_query_immune_memory(self, server: VulnoraMCPServer):
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "vulnora_query_immune_memory",
                "arguments": {"rule_id": "B605"},
            },
        }
        resp = server.handle_request(req)
        assert resp is not None
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        assert data["total_found"] == 1
        assert data["matched_antibodies"][0]["rule_id"] == "B605"

    def test_tool_call_get_security_guardrails(self, server: VulnoraMCPServer):
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "vulnora_get_security_guardrails",
                "arguments": {"language": "python"},
            },
        }
        resp = server.handle_request(req)
        assert resp is not None
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        assert data["total_rules"] == 1
        assert data["guardrails"][0]["rule_id"] == "B605"

    def test_tool_call_check_code_snippet_detects_secret(self, server: VulnoraMCPServer):
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "vulnora_check_code_snippet",
                "arguments": {"code": 'aws_key = "AKIAIOSFODNN7EXAMPLE"'},
            },
        }
        resp = server.handle_request(req)
        assert resp is not None
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        assert data["is_clean"] is False
        assert data["secrets_detected"] >= 1
        assert "AWS_ACCESS_KEY" in data["detected_types"]

    def test_stdio_event_loop(self, server: VulnoraMCPServer):
        input_lines = [
            json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping"}),
            json.dumps({"jsonrpc": "2.0", "id": 11, "method": "tools/list"}),
        ]
        in_stream = io.StringIO("\n".join(input_lines) + "\n")
        out_stream = io.StringIO()

        server.serve_stdio(reader=in_stream, writer=out_stream)

        output_lines = out_stream.getvalue().strip().splitlines()
        assert len(output_lines) == 2
        resp1 = json.loads(output_lines[0])
        assert resp1["id"] == 10
        resp2 = json.loads(output_lines[1])
        assert resp2["id"] == 11
