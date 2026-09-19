"""Secret-safe redaction before logging or returning diagnostics."""
from __future__ import annotations
import re
_PATTERNS=[
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,]+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,]+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)[^\s,]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[^\s,]+"),
]
def redact(value: str) -> str:
    for pattern in _PATTERNS:
        value=pattern.sub(r"\1***REDACTED***",value)
    return value
