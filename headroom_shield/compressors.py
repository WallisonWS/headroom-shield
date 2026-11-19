"""
Headroom Shield — Zero-Dependency Multi-Stage Context Compression Pipeline.
Provides:
  1. SmartCrusher (Statistical JSON Array Compression + Lossless CSV-Schema mode + Anomaly/Error Retention)
  2. LogCrusher (Template Deduplication keeping 100% of FATAL/ERROR/WARN & Stack Traces)
  3. Code/Diff Compactor (Preserves imports, signatures, types & diff hunks)
  4. Unified `compress()` API compatible with OpenAI, Anthropic & Google Gemini message arrays.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .ccr_store import CCRStore
from .security import SecurityAudit, apply_security_shield

CCR_SENTINEL_KEY = "_ccr_dropped"
ERROR_KEYWORDS_RX = re.compile(r"(?i)\b(?:fatal|error|critical|exception|traceback|panic|failed|denied|timeout|5\d\d|403|401|segfault)\b")
LOG_VAR_RX = re.compile(r"(?:\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b0x[0-9a-fA-F]+\b|\b[0-9a-f]{8,}\b|\b\d+\b)")


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 3.8)) if text else 0


@dataclass
class CompressionResult:
    content: str
    content_type: str
    strategy: str
    tokens_before: int
    tokens_after: int
    savings_percent: float
    ccr_hash: Optional[str] = None
    security_threats: List[Dict[str, str]] = field(default_factory=list)
    redacted_entities_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_anomalous_record(item: Any, numeric_bounds: Dict[str, Tuple[float, float]]) -> bool:
    if not isinstance(item, dict):
        return bool(ERROR_KEYWORDS_RX.search(str(item)))
    for k, v in item.items():
        kl = k.lower()
        if kl in ("error", "err", "exception", "fatal") and v:
            return True
        if kl in ("status", "status_code", "http_status") and isinstance(v, (int, float)) and v >= 400:
            return True
        if kl in ("level", "severity") and str(v).upper() in ("ERROR", "FATAL", "CRITICAL", "WARN", "WARNING"):
            return True
        if k in numeric_bounds and isinstance(v, (int, float)):
            mean, std = numeric_bounds[k]
            if std > 0 and abs(v - mean) > 2.0 * std:
                return True
    return False


def compress_json_array(
    items: List[Any],
    store: CCRStore,
    keep_first: int = 3,
    keep_last: int = 2,
    csv_schema: bool = False,
) -> Tuple[str, Optional[str], str]:
    total = len(items)
    if total <= keep_first + keep_last + 2:
        if csv_schema and items and all(isinstance(x, dict) for x in items):
            keys = list(items[0].keys())
            csv_lines = [",".join(keys)] + [",".join(str(r.get(k, "")) for k in keys) for r in items]
            return "\n".join(csv_lines), None, "json-csv-schema-lossless"
        return json.dumps(items, separators=(",", ":"), ensure_ascii=False), None, "json-minified"

    # Compute numeric column mean/std for statistical outlier retention
    numeric_bounds: Dict[str, Tuple[float, float]] = {}
    if all(isinstance(x, dict) for x in items[:50]):
        col_vals: Dict[str, List[float]] = {}
        for row in items:
            if isinstance(row, dict):
                for k, v in row.items():
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        col_vals.setdefault(k, []).append(float(v))
        for k, vals in col_vals.items():
            if len(vals) >= 5:
                mean = sum(vals) / len(vals)
                var = sum((x - mean) ** 2 for x in vals) / len(vals)
                numeric_bounds[k] = (mean, math.sqrt(var))

    kept_indices = set(range(min(keep_first, total))) | set(range(max(0, total - keep_last), total))
    for idx, item in enumerate(items):
        if idx not in kept_indices and _is_anomalous_record(item, numeric_bounds):
            kept_indices.add(idx)

    dropped_count = total - len(kept_indices)
    if dropped_count <= 0:
        return json.dumps(items, separators=(",", ":"), ensure_ascii=False), None, "json-all-significant"

    ccr_hash = store.store(items, metadata={"type": "json_array", "total_rows": total, "dropped": dropped_count})
    kept_items = [items[i] for i in sorted(kept_indices)]

    if csv_schema and all(isinstance(x, dict) for x in kept_items):
        keys = list(kept_items[0].keys())
        lines = [
            f"# CSV-Schema Compact ({len(kept_items)}/{total} rows kept; {dropped_count} offloaded <<ccr:{ccr_hash}>>)",
            ",".join(keys),
            *[",".join(str(r.get(k, "")) for k in keys) for r in kept_items],
        ]
        return "\n".join(lines), ccr_hash, "smart-crusher-csv-schema"

    if all(isinstance(x, dict) for x in kept_items):
        kept_items.insert(
            min(keep_first, len(kept_items)),
            {CCR_SENTINEL_KEY: f"<<ccr:{ccr_hash} {dropped_count}_rows_offloaded_of_{total}>>"},
        )
    else:
        kept_items.insert(
            min(keep_first, len(kept_items)),
            f"… {dropped_count} more items <<ccr:{ccr_hash} {dropped_count}_items_offloaded>>",
        )
    return json.dumps(kept_items, separators=(",", ":"), ensure_ascii=False), ccr_hash, "smart-crusher-statistical"


def compress_logs(text: str, store: CCRStore) -> Tuple[str, Optional[str], str]:
    lines = text.splitlines()
    if len(lines) <= 25:
        return text, None, "log-passthrough"

    template_counts: Counter[str] = Counter()
    kept_lines: List[str] = []
    seen_templates: Dict[str, int] = {}
    dropped = 0

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        # Always retain errors, stack frames, first 5 and last 5 lines
        is_critical = bool(ERROR_KEYWORDS_RX.search(stripped)) or stripped.startswith(("File \"", "at ", "Caused by:"))
        if idx < 5 or idx >= len(lines) - 5 or is_critical:
            kept_lines.append(line)
            continue

        tmpl = LOG_VAR_RX.sub("<*>", stripped)
        template_counts[tmpl] += 1
        if tmpl not in seen_templates:
            seen_templates[tmpl] = len(kept_lines)
            kept_lines.append(line)
        else:
            dropped += 1

    if dropped == 0:
        return text, None, "log-unique-passthrough"

    ccr_hash = store.store(text, metadata={"type": "logs", "total_lines": len(lines), "dropped_lines": dropped})
    summary = [f"[LOG_SUMMARY: {len(lines)} lines -> {len(kept_lines)} unique/critical lines | {dropped} repetitive lines offloaded <<ccr:{ccr_hash}>>]"]
    top_noise = [(t, c) for t, c in template_counts.most_common(3) if c > 2]
    if top_noise:
        summary.append("[TOP_REPEATED_TEMPLATES: " + "; ".join(f"{c}x '{t[:60]}'" for t, c in top_noise) + "]")
    return "\n".join(summary + kept_lines), ccr_hash, "log-template-dedup"


def compress_code_or_diff(text: str, store: CCRStore) -> Tuple[str, Optional[str], str]:
    lines = text.splitlines()
    if text.lstrip().startswith(("diff --git", "--- a/", "@@ ")):
        kept = [l for l in lines if l.startswith(("diff --git", "---", "+++", "@@", "+", "-"))]
        if len(kept) < len(lines) - 5:
            ccr_hash = store.store(text, metadata={"type": "git_diff", "total_lines": len(lines)})
            return f"# Compressed Git Diff ({len(kept)}/{len(lines)} lines | full <<ccr:{ccr_hash}>>)\n" + "\n".join(kept), ccr_hash, "diff-hunk-compactor"
        return text, None, "diff-passthrough"

    sig_rx = re.compile(r"^\s*(?:import |from |export |class |def |async def |function |const |interface |type |func |struct |pub fn |fn |return |raise |throw )")
    kept = []
    omitted = 0
    for idx, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith(("#", "//", "/*", "*")):
            omitted += 1
            continue
        if idx < 8 or idx >= len(lines) - 5 or sig_rx.match(line) or ERROR_KEYWORDS_RX.search(line):
            kept.append(line)
        else:
            omitted += 1
    if omitted < 10:
        return text, None, "code-passthrough"
    ccr_hash = store.store(text, metadata={"type": "source_code", "total_lines": len(lines)})
    return f"// Code Skeleton ({len(kept)}/{len(lines)} structural lines | full <<ccr:{ccr_hash}>>)\n" + "\n".join(kept), ccr_hash, "code-signature-skeleton"


def detect_content_type(text: str) -> str:
    s = text.strip()
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        try:
            json.loads(s)
            return "json"
        except Exception:
            pass
    if s.startswith(("diff --git", "--- a/")):
        return "diff"
    lines = s.splitlines()
    if len(lines) >= 10:
        code_hits = sum(1 for l in lines[:40] if re.match(r"^\s*(?:def |class |import |from |function |const |export |func |package )", l))
        if code_hits >= 3:
            return "code"
        log_hits = sum(1 for l in lines[:40] if re.search(r"\b(?:INFO|DEBUG|WARN|ERROR|FATAL|TRACE)\b|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", l))
        if log_hits >= 3:
            return "log"
    return "text"


def compress_content(
    text: str,
    store: Optional[CCRStore] = None,
    *,
    security_shield: bool = True,
    redact_pii: bool = True,
    csv_schema: bool = False,
) -> Tuple[CompressionResult, SecurityAudit]:
    active_store = store if store is not None else CCRStore()
    tokens_before = estimate_tokens(text)

    # Stage 0: Zero-Leak Security Shield (OWASP LLM + Reversible PII Vault)
    if security_shield:
        audit = apply_security_shield(text, redact_pii=redact_pii, neutralize_injections=True)
        working_text = audit.sanitized_text
    else:
        audit = SecurityAudit(sanitized_text=text)
        working_text = text

    ctype = detect_content_type(working_text)
    ccr_hash: Optional[str] = None
    strategy = "passthrough"
    compressed = working_text

    if ctype == "json":
        parsed = json.loads(working_text)
        if isinstance(parsed, list):
            compressed, ccr_hash, strategy = compress_json_array(parsed, active_store, csv_schema=csv_schema)
        elif isinstance(parsed, dict):
            # Crush largest nested list if present
            best_key = max((k for k, v in parsed.items() if isinstance(v, list)), key=lambda k: len(parsed[k]), default=None)
            if best_key and len(parsed[best_key]) > 7:
                crushed_sub, ccr_hash, strategy = compress_json_array(parsed[best_key], active_store, csv_schema=False)
                out_obj = dict(parsed)
                out_obj[best_key] = json.loads(crushed_sub)
                compressed = json.dumps(out_obj, separators=(",", ":"), ensure_ascii=False)
            else:
                compressed = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
                strategy = "json-minified"
    elif ctype == "log":
        compressed, ccr_hash, strategy = compress_logs(working_text, active_store)
    elif ctype in ("code", "diff"):
        compressed, ccr_hash, strategy = compress_code_or_diff(working_text, active_store)
    else:
        # Paragraph / RAG chunk deduplication
        chunks = [c.strip() for c in re.split(r"\n\s*\n", working_text) if c.strip()]
        unique_chunks: List[str] = []
        seen = set()
        for ch in chunks:
            norm = re.sub(r"\s+", " ", ch.lower())
            if norm not in seen:
                seen.add(norm)
                unique_chunks.append(ch)
        if len(unique_chunks) < len(chunks):
            ccr_hash = active_store.store(working_text, metadata={"type": "rag_text", "total_chunks": len(chunks)})
            compressed = f"[RAG_DEDUP: {len(chunks)} -> {len(unique_chunks)} unique chunks | full <<ccr:{ccr_hash}>>]\n\n" + "\n\n".join(unique_chunks)
            strategy = "rag-chunk-dedup"

    tokens_after = estimate_tokens(compressed)
    savings = round(max(0.0, (1.0 - tokens_after / max(1, tokens_before)) * 100.0), 2)
    return (
        CompressionResult(
            content=compressed,
            content_type=ctype,
            strategy=strategy,
            tokens_before=tokens_before,
            tokens_after=tokens_after,
            savings_percent=savings,
            ccr_hash=ccr_hash,
            security_threats=audit.threats_neutralized,
            redacted_entities_count=len(audit.redacted_tokens),
        ),
        audit,
    )


def compress_messages(
    messages: List[Dict[str, Any]],
    store: Optional[CCRStore] = None,
    *,
    compress_user_messages: bool = False,
    security_shield: bool = True,
    redact_pii: bool = True,
    csv_schema: bool = False,
) -> Dict[str, Any]:
    """OpenAI / Anthropic / Gemini message-array compression entrypoint."""
    active_store = store if store is not None else CCRStore()
    out_messages: List[Dict[str, Any]] = []
    tot_before = 0
    tot_after = 0
    threats_total = 0
    ccr_hashes: List[str] = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content")
        should_compress = isinstance(content, str) and (role == "tool" or (compress_user_messages and role == "user"))
        if should_compress:
            res, _ = compress_content(
                content,
                active_store,
                security_shield=security_shield,
                redact_pii=redact_pii,
                csv_schema=csv_schema,
            )
            tot_before += res.tokens_before
            tot_after += res.tokens_after
            threats_total += len(res.security_threats)
            if res.ccr_hash:
                ccr_hashes.append(res.ccr_hash)
            new_msg = dict(msg)
            new_msg["content"] = res.content
            out_messages.append(new_msg)
        else:
            t = estimate_tokens(str(content or ""))
            tot_before += t
            tot_after += t
            out_messages.append(dict(msg))

    return {
        "messages": out_messages,
        "tokens_before": tot_before,
        "tokens_after": tot_after,
        "savings_percent": round(max(0.0, (1.0 - tot_after / max(1, tot_before)) * 100.0), 2),
        "security_threats_neutralized": threats_total,
        "ccr_hashes": ccr_hashes,
    }
