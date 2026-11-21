"""
Local Model Context Protocol (MCP) stdio server for Vulnora AI.

Exposes local AST Immune Memory, repository security guardrails (AGENTS.md),
and in-memory code security checking over standard JSON-RPC 2.0 (stdio)
so coding agents (Cursor, Claude Code, Copilot, Antigravity) can query
known pitfalls before and during code authoring.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, TextIO, Union

import vulnora
from vulnora.engine.agents_md import AgentsMDWriter
from vulnora.engine.redactor import SecretRedactor
from vulnora.immune.ast_normalizer import ASTNormalizer
from vulnora.immune.memory_store import ImmuneMemoryStore


class VulnoraMCPServer:
    """
    Implements standard Model Context Protocol (MCP) server over stdin/stdout.
    """

    def __init__(
        self,
        repo_root: Optional[Union[str, Path]] = None,
        immune_store: Optional[ImmuneMemoryStore] = None,
        agents_writer: Optional[AgentsMDWriter] = None,
    ):
        self.repo_root = Path(repo_root or Path.cwd()).resolve()
        mem_file = self.repo_root / ".vulnora" / "memory.json"
        self.immune_store = immune_store or ImmuneMemoryStore(memory_path=mem_file)
        self.agents_writer = agents_writer or AgentsMDWriter(repo_root=self.repo_root)
        self.redactor = SecretRedactor()
        self.normalizer = ASTNormalizer()

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatches an MCP JSON-RPC 2.0 request and returns JSON-RPC response."""
        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "vulnora-mcp-server",
                        "version": vulnora.__version__,
                    },
                },
            }

        if method == "notifications/initialized":
            return None  # No response for notifications

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "vulnora_query_immune_memory",
                            "description": "Query local AST immune memory for known vulnerability patterns, prior fixes, and antibody rules.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rule_id": {"type": "string", "description": "Optional security rule ID to search for."},
                                    "code_snippet": {"type": "string", "description": "Code snippet to evaluate for structural AST hits."},
                                    "language": {"type": "string", "description": "Programming language of code snippet."},
                                },
                            },
                        },
                        {
                            "name": "vulnora_get_security_guardrails",
                            "description": "Retrieve active repository security guardrails and preventative rules from AGENTS.md.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "language": {"type": "string", "description": "Filter rules by language (e.g. 'python', 'go')."},
                                },
                            },
                        },
                        {
                            "name": "vulnora_check_code_snippet",
                            "description": "Check a code snippet in memory for hardcoded secrets, high entropy tokens, and syntax pitfalls before writing.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["code"],
                                "properties": {
                                    "code": {"type": "string", "description": "Source code text to inspect."},
                                    "language": {"type": "string", "description": "Programming language."},
                                },
                            },
                        },
                    ]
                },
            }

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            return self._dispatch_tool_call(req_id, tool_name, arguments)

        # Unrecognized method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _dispatch_tool_call(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Executes tool implementation and wraps output in MCP CallToolResult format."""
        if name == "vulnora_query_immune_memory":
            rule_id = args.get("rule_id")
            snippet = args.get("code_snippet", "")
            lang = args.get("language", "generic")

            records = self.immune_store.get_all_records()
            if rule_id:
                records = [r for r in records if r.rule_id.lower() == rule_id.lower()]

            results: List[Dict[str, Any]] = []
            for r in records[:5]:
                results.append({
                    "id": r.id,
                    "rule_id": r.rule_id,
                    "language": r.language,
                    "resolution": r.resolution,
                    "agents_rule": r.agents_rule,
                })

            res_text = json.dumps({"matched_antibodies": results, "total_found": len(results)}, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": res_text}]},
            }

        if name == "vulnora_get_security_guardrails":
            rules = self.agents_writer.load_rules()
            lang_filter = args.get("language")
            if lang_filter:
                rules = [r for r in rules if r.language.lower() == lang_filter.lower()]

            rule_list = [{"rule_id": r.rule_id, "language": r.language, "rule": r.rule_text} for r in rules]
            res_text = json.dumps({"guardrails": rule_list, "total_rules": len(rule_list)}, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": res_text}]},
            }

        if name == "vulnora_check_code_snippet":
            code = args.get("code", "")
            redaction = self.redactor.redact(code)
            res_text = json.dumps({
                "secrets_detected": redaction.secrets_found_count,
                "detected_types": redaction.detected_types,
                "is_clean": redaction.secrets_found_count == 0,
            }, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": res_text}]},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": f"Unknown tool: {name}"},
        }

    def serve_stdio(self, reader: Optional[TextIO] = None, writer: Optional[TextIO] = None) -> None:
        """Runs the stdio event loop processing line-delimited JSON-RPC messages."""
        in_stream = reader or sys.stdin
        out_stream = writer or sys.stdout

        for line in in_stream:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                req = json.loads(line_str)
                resp = self.handle_request(req)
                if resp is not None:
                    out_stream.write(json.dumps(resp) + "\n")
                    out_stream.flush()
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
