# 📐 Architecture & REA Reverse-Engineering Audit

This document explains how **Headroom Shield** was designed using structured static & storage inspection via **REA (Reverse Engineer Anything)** against [`headroomlabs-ai/headroom`](https://github.com/headroomlabs-ai/headroom) (Apache-2.0).

---

## 1. REA Evidence Summary (Observed Upstream Artifacts)

### A) Production CCR SQLite Schema Inspection
* **REA Operation:** `inspect_sqlite_database` (SQLite 3.53.3)
* **Evidence ID:** `ev_7a5078f12d0f43bc7231dcd3fb5caedab06e9b9e5c41482281c9bd89a8897857`
* **Observed Artifact:** Local `.headroom/ccr_store.db` + WAL sidecar (`PRAGMA journal_mode=WAL`)
* **Observed Table & Index:**
  ```sql
  CREATE TABLE ccr_entries (
      hash TEXT PRIMARY KEY,
      entry_json TEXT NOT NULL,
      created_at REAL NOT NULL,
      ttl INTEGER NOT NULL
  );
  CREATE INDEX idx_ccr_expiry_deadline ON ccr_entries (created_at + ttl);
  ```
* **Headroom Shield Upgrade (`headroom_shield/ccr_store.py`):** Preserves full schema compatibility (`ccr_entries` + `idx_ccr_expiry_deadline`) while wrapping payloads in a `zlib+b64` envelope (`~60–80%` smaller SQLite footprint on disk) and supporting atomic TTL pruning.

### B) TypeScript SDK Application Graph Analysis
* **REA Operation:** `analyze_javascript_application` (`detail: "summary"`)
* **Parent Evidence ID:** `ev_ce357a9c6de8c95774d461f8dad088e0cc82b675b9a66da0aeabcdda186eca2c`
* **Summary View ID:** `ev_fff2dab3f9c09c83f87865da4e04ed26b379ef37f369ca326c4ac61a1afc05dd`
* **Observed Metrics:** 56 parsed JS/TS source files, 59,418 AST nodes, 54 boundary relations, 23 configuration reads, 11 outbound HTTP request paths.
* **Key Architectural Findings:**
  1. Upstream Python `smart_crusher.py` enforces a hard import on the compiled Rust PyO3 extension (`headroom._core`) with no pure-Python fallback.
  2. Upstream MCP server (`headroom/ccr/mcp_server.py`) relies on external `mcp` and `httpx` packages plus Unix-only `fcntl`.
  3. Upstream OSS ships an anonymous usage beacon enabled by default and excludes token security scrubbing from OSS.

---

## 2. Headroom Shield Multi-Stage Architecture

1. **Stage 0 — `SecurityShield` (`headroom_shield/security.py`):**
   * Strips invisible Unicode tags (`U+E0000–U+E007F`) and BiDi Trojan overrides (`U+202A–U+202E`).
   * Blocks Markdown image exfiltration (`![...](https://...)`) and neutralizes `<IMPORTANT>` / instruction-override prompt injections.
   * Redacts AWS/Google/GitHub keys, JWTs, CPF/CNPJ, emails, and RFC 1918 internal IPs into deterministic tokens (`<EMAIL_1>`, `<CPF_1>`) backed by an in-memory `.rehydrate()` vault.
2. **Stage 1 — `ContentRouter` (`headroom_shield/compressors.py`):**
   * Routes payloads automatically to `SmartCrusher` (JSON arrays), `LogCrusher` (repetitive logs), `Code/Diff Compactor`, or `RAG Chunk Deduplicator`.
   * Computes z-score statistical outliers (`|x - μ| > 2σ`) and error/status heuristics (`status >= 400`, `ERROR`/`FATAL`/`CRITICAL`) so critical signals are **never dropped**.
3. **Stage 2 — Reversible CCR Offload (`<<ccr:HASH>>`):**
   * Emits Headroom-compatible sentinel markers (`{"_ccr_dropped": "<<ccr:HASH N_rows_offloaded>>"}`) allowing any LLM or agent to recover 100% lossless originals via `headroom_retrieve`.
