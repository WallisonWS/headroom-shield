"""
Stage-0 Security Shield for Headroom Shield.
Neutralizes Indirect Prompt Injection (OWASP LLM01/LLM06/LLM07), strips invisible Unicode
smuggling (U+E0000..U+E007F / BiDi), blocks Markdown image exfiltration, and redacts PII/Secrets
into a reversible in-memory vault before compression reaches any LLM.
Zero external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


INVISIBLE_UNICODE_RX = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]")
MD_EXFIL_RX = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)", re.IGNORECASE)
INJECTION_PATTERNS: List[Tuple[str, str, re.Pattern[str]]] = [
    ("LLM01", "Prompt Injection Override", re.compile(r"(?i)<IMPORTANT>[\s\S]*?</IMPORTANT>|(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules)")),
    ("LLM07", "System Prompt Exfiltration", re.compile(r"(?i)(?:reveal|dump|print|output)\s+(?:your\s+)?(?:system prompt|hidden instructions|developer message)")),
    ("LLM06", "Destructive Tool Abuse", re.compile(r"(?i)(?:curl\s+[^\n]+\|\s*(?:ba)?sh|rm\s+-rf\s+/|powershell\s+-enc|169\.254\.169\.254)")),
]

PII_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")),
    ("CNPJ", re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")),
    ("CPF", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")),
    ("EMAIL", re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    ("IPV4_INTERNAL", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d{1,3}\.\d{1,3}\b")),
]


@dataclass
class SecurityAudit:
    sanitized_text: str
    threats_neutralized: List[Dict[str, str]] = field(default_factory=list)
    redacted_tokens: Dict[str, str] = field(default_factory=dict)
    unicode_chars_stripped: int = 0

    def rehydrate(self, model_reply: str) -> str:
        out = model_reply
        for token, original in self.redacted_tokens.items():
            out = out.replace(token, original)
        return out


def apply_security_shield(text: str, redact_pii: bool = True, neutralize_injections: bool = True) -> SecurityAudit:
    clean = text
    threats: List[Dict[str, str]] = []
    token_to_raw: Dict[str, str] = {}
    raw_to_token: Dict[str, str] = {}
    counts: Dict[str, int] = {}

    # 1. Strip invisible Unicode smuggling & BiDi overrides
    inv = INVISIBLE_UNICODE_RX.findall(clean)
    if inv:
        clean = INVISIBLE_UNICODE_RX.sub("", clean)
        threats.append({"owasp": "LLM01", "rule": "Invisible Unicode / BiDi Smuggling Stripped", "count": str(len(inv))})

    # 2. Neutralize external Markdown image exfiltration links
    if neutralize_injections:
        if MD_EXFIL_RX.search(clean):
            clean = MD_EXFIL_RX.sub("[BLOCKED_EXTERNAL_MD_IMAGE]", clean)
            threats.append({"owasp": "LLM02", "rule": "Markdown Image Data-Exfiltration Blocked", "count": "1+"})
        for owasp_id, rule_name, rx in INJECTION_PATTERNS:
            if rx.search(clean):
                clean = rx.sub(f"[NEUTRALIZED_{owasp_id}_INJECTION]", clean)
                threats.append({"owasp": owasp_id, "rule": rule_name, "count": "1+"})

    # 3. Reversible PII & Secret Vault redaction
    if redact_pii:
        for ent_type, rx in PII_PATTERNS:
            def _sub(match: re.Match[str]) -> str:
                raw = match.group(0)
                if raw in raw_to_token:
                    return raw_to_token[raw]
                counts[ent_type] = counts.get(ent_type, 0) + 1
                tok = f"<{ent_type}_{counts[ent_type]}>"
                raw_to_token[raw] = tok
                token_to_raw[tok] = raw
                return tok

            clean = rx.sub(_sub, clean)

    return SecurityAudit(
        sanitized_text=clean,
        threats_neutralized=threats,
        redacted_tokens=token_to_raw,
        unicode_chars_stripped=len(inv),
    )
