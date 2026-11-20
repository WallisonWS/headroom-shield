#!/usr/bin/env python3
"""
Zero-Dependency Standalone MCP Server (JSON-RPC 2.0 over stdio).
Works with Antigravity, Claude Code, Cursor, Codex, Windsurf & any MCP Host
without installing `mcp` or `httpx` packages!

Tools exposed:
  - headroom_compress        : Stage-0 Security Shield + Statistical/Log/Code/RAG Compression + CCR offload
  - headroom_retrieve        : Retrieve exact original uncompressed data from local SQLite CCR store by hash
  - headroom_stats           : Session & SQLite store token/USD savings ledger
  - headroom_security_audit  : Standalone OWASP LLM + LGPD/PII security inspection
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

from .ccr_store import CCRStore
from .compressors import compress_content
from .security import apply_security_shield


class HeadroomShieldMCPServer:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.store = CCRStore(db_path=db_path)
        self.session_tokens_before = 0
        self.session_tokens_after = 0
        self.session_calls = 0
        self.session_threats_blocked = 0

    def list_tools(self) -> Dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "headroom_compress",
                    "description": "Compress JSON arrays, logs, code, diffs or RAG chunks with built-in OWASP LLM Prompt-Injection Shield & Reversible PII Vault. Returns compressed output + CCR hash for lossless retrieval.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {"type": "string", "description": "Raw tool output, JSON array, log or RAG chunk"},
                            "csv_schema": {"type": "boolean", "default": False, "description": "Use lossless CSV-schema tabular compaction for uniform JSON arrays"},
                            "redact_pii": {"type": "boolean", "default": True, "description": "Scrub PII/Secrets into reversible tokens"},
                        },
                        "required": ["content"],
                    },
                },
                {
                    "name": "headroom_retrieve",
                    "description": "Retrieve original uncompressed payload from the local SQLite CCR store using its 12-char hash (from <<ccr:HASH>>).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"hash": {"type": "string", "description": "12-char CCR hash"}},
                        "required": ["hash"],
                    },
                },
                {
                    "name": "headroom_stats",
                    "description": "Return session token compression ratio, tokens saved, threats neutralized and SQLite CCR store metrics.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "headroom_security_audit",
                    "description": "Audit text/logs/RAG chunks for Indirect Prompt Injections (OWASP LLM Top 10), invisible Unicode smuggling and leaked secrets/PII.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"content": {"type": "string"}},
                        "required": ["content"],
                    },
                },
            ]
        }

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name == "headroom_compress":
            res, audit = compress_content(
                str(arguments.get("content", "")),
                store=self.store,
                security_shield=True,
                redact_pii=bool(arguments.get("redact_pii", True)),
                csv_schema=bool(arguments.get("csv_schema", False)),
            )
            self.session_calls += 1
            self.session_tokens_before += res.tokens_before
            self.session_tokens_after += res.tokens_after
            self.session_threats_blocked += len(res.security_threats)
            return {"content": [{"type": "text", "text": json.dumps(res.to_dict(), indent=2, ensure_ascii=False)}]}

        if name == "headroom_retrieve":
            rec = self.store.retrieve(str(arguments.get("hash", "")).strip())
            payload = rec if rec else {"error": "CCR hash not found or TTL expired"}
            return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}

        if name == "headroom_stats":
            saved = max(0, self.session_tokens_before - self.session_tokens_after)
            pct = round((saved / max(1, self.session_tokens_before)) * 100.0, 2)
            out = {
                "calls": self.session_calls,
                "tokens_before": self.session_tokens_before,
                "tokens_after": self.session_tokens_after,
                "tokens_saved": saved,
                "savings_percent": pct,
                "threats_neutralized": self.session_threats_blocked,
                "telemetry_beacon": "DISABLED (100% Air-Gapped Local)",
                "ccr_store": self.store.stats(),
            }
            return {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}

        if name == "headroom_security_audit":
            audit = apply_security_shield(str(arguments.get("content", "")))
            out = {
                "threats_neutralized": audit.threats_neutralized,
                "redacted_entities": len(audit.redacted_tokens),
                "unicode_chars_stripped": audit.unicode_chars_stripped,
                "sanitized_preview": audit.sanitized_text[:500],
            }
            return {"content": [{"type": "text", "text": json.dumps(out, indent=2, ensure_ascii=False)}]}

        raise ValueError(f"Unknown tool: {name}")

    def handle_jsonrpc(self, msg: Dict[str, Any]) -> Dict[str, Any] | None:
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "headroom-shield-mcp", "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                },
            }
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": self.list_tools()}
        if method == "tools/call":
            params = msg.get("params", {})
            result = self.call_tool(params.get("name", ""), params.get("arguments", {}))
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    def run_stdio(self) -> None:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_jsonrpc(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as exc:
                err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(exc)}}
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()


def main() -> None:
    db = Path.home() / ".headroom-shield" / "ccr_store.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    HeadroomShieldMCPServer(db_path=db).run_stdio()


if __name__ == "__main__":
    main()
