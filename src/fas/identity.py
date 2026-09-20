"""Canonical deterministic FAS identifiers."""
from __future__ import annotations
import hashlib

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def stable_ulid_suffix(material: str) -> str:
    """Encode a 128-bit SHA-256 digest into exactly 26 Crockford base32 chars."""
    digest = hashlib.sha256(material.encode("utf-8")).digest()[:16]
    value = int.from_bytes(digest, "big")
    chars = []
    for _ in range(26):
        chars.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))

def stable_id(prefix: str, material: str) -> str:
    if not prefix or "_" in prefix:
        raise ValueError("invalid identifier prefix")
    return f"{prefix}_{stable_ulid_suffix(material)}"
