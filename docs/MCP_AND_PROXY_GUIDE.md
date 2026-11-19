# 🔌 MCP Server & Local HTTP Proxy Guide

## 1. Zero-Dependency MCP Server Setup (Antigravity, Claude Code, Cursor, Codex)

Add `headroom-shield` to your MCP configuration (`mcp_config.json` / `.cursor/mcp.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "headroom-shield": {
      "command": "python3",
      "args": ["-m", "headroom_shield.mcp_server"],
      "cwd": "/path/to/headroom-shield"
    }
  }
}
```

### Exposed MCP Tools
| Tool Name | Purpose |
| :--- | :--- |
| `headroom_compress` | Runs Stage-0 OWASP/PII Shield + JSON/Log/Code/RAG compression + stores original in SQLite CCR store. |
| `headroom_retrieve` | Retrieves the lossless original payload from SQLite by its 12-char `hash` (`<<ccr:HASH>>`). |
| `headroom_stats` | Reports session token savings, percentage saved, threats neutralized & CCR store entry count. |
| `headroom_security_audit` | Audits untrusted tool output or RAG chunks for Prompt Injection, invisible Unicode & PII leaks. |

---

## 2. Local Zero-Telemetry HTTP Proxy

Start the proxy pointing to OpenAI, Anthropic, or a Gemini OpenAI-compatible endpoint:

```bash
python3 -m headroom_shield.proxy_server --port 8787 --upstream https://api.openai.com
```

Point any SDK or coding agent at `http://127.0.0.1:8787`:
```bash
export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"
```

Every proxied response includes transparent observability headers:
* `X-Headroom-Shield-Savings: 84.2%`
* `X-Headroom-Shield-Threats-Blocked: 2`
* Check proxy health anytime: `GET http://127.0.0.1:8787/health`
