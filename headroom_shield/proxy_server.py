#!/usr/bin/env python3
"""
Zero-Dependency Local HTTP Compression & Security Proxy (OpenAI / Anthropic / Gemini compatible).
Compresses tool messages + strips Prompt Injections & PII in flight with ZERO telemetry beacons!
Usage:
  python3 -m headroom_shield.proxy_server --port 8787 --upstream https://api.openai.com
"""

from __future__ import annotations

import argparse
import http.server
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

from .ccr_store import CCRStore
from .compressors import compress_messages


def create_proxy_handler(upstream_base: str, store: CCRStore, redact_pii: bool = True):
    class HeadroomShieldProxyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                payload = json.dumps({"status": "ok", "telemetry": "off", "ccr": store.stats()}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_error(404, "Use POST for LLM API proxying or GET /health")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            out_body = raw_body
            savings_hdr = "0%"
            threats_hdr = "0"

            try:
                data: Dict[str, Any] = json.loads(raw_body.decode("utf-8"))
                if isinstance(data.get("messages"), list):
                    res = compress_messages(data["messages"], store=store, security_shield=True, redact_pii=redact_pii)
                    data["messages"] = res["messages"]
                    out_body = json.dumps(data).encode("utf-8")
                    savings_hdr = f"{res['savings_percent']}%"
                    threats_hdr = str(res["security_threats_neutralized"])
            except Exception:
                pass

            target_url = upstream_base.rstrip("/") + self.path
            fwd_headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in ("host", "content-length", "accept-encoding")
            }
            fwd_headers["Content-Length"] = str(len(out_body))
            req = urllib.request.Request(target_url, data=out_body, headers=fwd_headers, method="POST")

            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    resp_bytes = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                    self.send_header("X-Headroom-Shield-Savings", savings_hdr)
                    self.send_header("X-Headroom-Shield-Threats-Blocked", threats_hdr)
                    self.end_headers()
                    self.wfile.write(resp_bytes)
            except urllib.error.HTTPError as err:
                self.send_response(err.code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(err.read())

        def log_message(self, fmt: str, *args: Any) -> None:
            print(f"[headroom-shield-proxy] {self.address_string()} - {fmt % args}")

    return HeadroomShieldProxyHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Headroom Shield Local HTTP Proxy (Zero Telemetry)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--upstream", default="https://api.openai.com")
    parser.add_argument("--no-pii-redact", action="store_true")
    args = parser.parse_args()

    db = Path.home() / ".headroom-shield" / "ccr_store.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    store = CCRStore(db_path=db)
    server = http.server.ThreadingHTTPServer(
        (args.host, args.port),
        create_proxy_handler(args.upstream, store, redact_pii=not args.no_pii_redact),
    )
    print(f"⚡ Headroom Shield Proxy listening on http://{args.host}:{args.port} -> {args.upstream} (Telemetry: OFF)")
    server.serve_forever()


if __name__ == "__main__":
    main()
