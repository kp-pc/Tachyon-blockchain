"""Canonical byte encoding, base58, and domain separated hashing.

Every hash produced by Tachyon is domain separated so that values from
different contexts (transactions, blocks, merkle nodes, votes...) can never be
confused with each other, even when the underlying payloads are identical.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

CHAIN_DOMAIN = b"tachyon:v1:"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: i for i, ch in enumerate(B58_ALPHABET)}


def b58encode(data: bytes) -> str:
    """Base58 (Bitcoin alphabet) encode raw bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("b58encode expects bytes")
    num = int.from_bytes(data, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(B58_ALPHABET[rem])
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    """Decode a base58 string, returning raw bytes."""
    if not isinstance(text, str) or not text:
        raise ValueError("b58decode expects a non-empty string")
    num = 0
    for ch in text:
        try:
            idx = _B58_INDEX[ch]
        except KeyError as exc:
            raise ValueError(f"invalid base58 character: {ch!r}") from exc
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def u64(value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise ValueError("u64 out of range")
    return value.to_bytes(8, "big")


def u32(value: int) -> bytes:
    if not 0 <= value < 1 << 32:
        raise ValueError("u32 out of range")
    return value.to_bytes(4, "big")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every signed/hashed structure."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def digest(tag: str, *chunks: bytes) -> bytes:
    """SHA-256 over a domain tag plus payload chunks."""
    hasher = hashlib.sha256(CHAIN_DOMAIN + tag.encode("ascii") + b"\x00")
    for chunk in chunks:
        hasher.update(chunk)
    return hasher.digest()


def digest_hex(tag: str, *chunks: bytes) -> str:
    return digest(tag, *chunks).hex()


def checksum(payload: bytes) -> bytes:
    return digest("checksum", payload)[:4]


def encode_with_checksum(payload: bytes, prefix: str = "") -> str:
    return prefix + b58encode(payload + checksum(payload))


def decode_with_checksum(text: str, prefix: str = "") -> bytes:
    if prefix:
        if not text.startswith(prefix):
            raise ValueError(f"expected prefix {prefix!r}")
        text = text[len(prefix):]
    raw = b58decode(text)
    if len(raw) < 5:
        raise ValueError("payload too short")
    payload, check = raw[:-4], raw[-4:]
    if checksum(payload) != check:
        raise ValueError("checksum mismatch")
    return payload

def i64(value: int) -> bytes:
    """Signed 64-bit big-endian encoding (two's complement)."""
    if not -(1 << 63) <= value < (1 << 63):
        raise ValueError("i64 out of range")
    return value.to_bytes(8, "big", signed=True)
