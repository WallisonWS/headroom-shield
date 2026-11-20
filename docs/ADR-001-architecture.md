# ADR-001: Zero-Dependency Portable Compression & Stage-0 Security Architecture

- **Status:** Accepted
- **Date:** 2026-11-20
- **Author:** Wallison Araujo (@WallisonWS)

## Context
Enterprise security teams, SREs, and developers working in regulated or air-gapped environments need LLM context compression without:
1. Compiled native binary build friction (Rust PyO3 wheels / PyTorch / ONNX).
2. Outbound telemetry beacons enabled by default.
3. Passing untrusted tool outputs or RAG chunks containing Indirect Prompt Injections or raw PII straight into LLM providers (Google Gemini, Microsoft Azure OpenAI, Anthropic).

## Decision
1. **Zero External Runtime Dependencies:** Implement the full SmartCrusher, Log Deduplicator, Code/Diff Compactor, SQLite WAL CCR Store, JSON-RPC 2.0 MCP Server, and HTTP Proxy using exclusively Python 3 stdlib and pure ES Module JavaScript.
2. **Stage-0 Security Before Compression:** Execute Unicode/BiDi stripping, OWASP LLM01/06/07 injection neutralization, and reversible PII redaction *prior* to statistical compression so malicious payloads cannot survive inside boundary or outlier samples.
3. **Schema-Compatible SQLite WAL + `zlib`:** Preserve Headroom's observed `ccr_entries` SQLite schema (`ev_7a5078f1...`) while transparently compressing stored entries with `zlib` to minimize local disk footprint.

## Consequences
- **Positive:** Instant deployment across Linux, Windows, macOS, Docker, GitHub Pages, and Edge Workers; zero network leakage; auditability under 1,000 lines of clean code.
- **Trade-off:** Pure Python/JS heuristic token estimation (`len / 3.8`) replaces heavy tokenizer/ML models; deterministic and sub-millisecond at the cost of ~3–5% estimator variance vs BPE tokenizers.
