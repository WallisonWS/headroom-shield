"""Headroom Shield — Zero-Dependency, Security-First LLM Context Compression Suite."""

from .ccr_store import CCRStore
from .compressors import CompressionResult, compress_content, compress_messages, estimate_tokens
from .security import SecurityAudit, apply_security_shield

__version__ = "1.0.0"
__all__ = [
    "CCRStore",
    "CompressionResult",
    "SecurityAudit",
    "apply_security_shield",
    "compress_content",
    "compress_messages",
    "estimate_tokens",
]
