"""
Microsoft Azure OpenAI / Enterprise Agent Integration Example with Headroom Shield.
Demonstrates running Headroom Shield as an in-process pre-flight security & compression
stage before sending logs, telemetry, or RAG chunks to Microsoft Azure OpenAI Service.
"""

from __future__ import annotations

import os
from headroom_shield import CCRStore, compress_messages


def build_azure_openai_payload(raw_server_logs: str) -> dict:
    store = CCRStore("azure_ccr_store.db")
    messages = [
        {"role": "system", "content": "You are an Azure Site Reliability & Security Engineer."},
        {"role": "user", "content": "Diagnose the production failure in these AKS logs."},
        {"role": "tool", "tool_call_id": "aks_logs_01", "content": raw_server_logs},
    ]

    result = compress_messages(messages, store=store, security_shield=True, redact_pii=True)
    print(
        f"[Headroom Shield -> Azure OpenAI] {result['tokens_before']} -> {result['tokens_after']} tokens "
        f"(-{result['savings_percent']}%) | Threats neutralized: {result['security_threats_neutralized']}"
    )
    return {
        "deployment": os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        "messages": result["messages"],
        "ccr_hashes": result["ccr_hashes"],
    }


if __name__ == "__main__":
    logs = "\n".join(f"2026-11-20T12:00:{i%60:02d}Z INFO aks-node-01 healthcheck ok" for i in range(300))
    logs += "\n2026-11-20T12:06:00Z FATAL KeyVault access denied for admin@contoso.com"
    payload = build_azure_openai_payload(logs)
    print("Ready Azure payload messages:", len(payload["messages"]), "| CCR refs:", payload["ccr_hashes"])
