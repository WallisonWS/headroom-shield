"""
Google Gemini / Vertex AI Integration Example with Headroom Shield.
Compresses bulky tool outputs & logs by 60-95%, blocks indirect prompt injections,
scrubs PII/LGPD locally BEFORE calling Google Gemini, and rehydrates the reply.

Install Google GenAI SDK (optional): pip install google-genai
"""

from __future__ import annotations

import json
import os
from headroom_shield import CCRStore, compress_content


def run_gemini_pipeline(raw_tool_output: str) -> None:
    store = CCRStore("gemini_ccr_store.db")

    # 1) Stage-0 OWASP Security Shield + SmartCrusher Compression (100% Local)
    compressed, audit = compress_content(
        raw_tool_output,
        store=store,
        security_shield=True,
        redact_pii=True,
        csv_schema=True,
    )
    print(f"[Headroom Shield] {compressed.tokens_before} -> {compressed.tokens_after} tokens (-{compressed.savings_percent}%)")
    print(f"[Security Shield] Threats neutralized: {len(compressed.security_threats)} | PII vaulted: {compressed.redacted_entities_count}")

    # 2) Forward safe, compressed context to Google Gemini (Vertex AI / Gemini API)
    if os.environ.get("GEMINI_API_KEY"):
        from google import genai  # type: ignore

        client = genai.Client()
        resp = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"Root-cause this incident concisely:\n\n{compressed.content}",
        )
        raw_reply = resp.text or ""
    else:
        raw_reply = f"[Offline Dry-Run] Incident root-caused from CCR:{compressed.ccr_hash}. Notify <EMAIL_1>."

    # 3) Rehydrate PII locally without ever exposing raw values to the LLM
    print("\n[Final Rehydrated Reply]:")
    print(audit.rehydrate(raw_reply))


if __name__ == "__main__":
    sample_rows = [{"id": i, "status": 200, "latency_ms": 14} for i in range(120)]
    sample_rows[42] = {"id": 42, "status": 500, "error": "FATAL DB timeout for maria@corp.com (CPF 123.456.789-00)"}
    run_gemini_pipeline(json.dumps(sample_rows))
