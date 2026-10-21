"""Pure-Python Ed25519 (RFC 8032) with a precomputed base-point table.

No third party dependency is required, which keeps the node portable. Signing
uses cached multiples of the base point (fast path, no doublings); arbitrary
point multiplication uses a 4-bit window.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .encoding import (
    b58decode,
    digest,
    encode_with_checksum,
    decode_with_checksum,
    sha512,
)

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_COFACTOR = 8

ADDRESS_PREFIX = "tch"
SIGNATURE_SIZE = 64
PUBLIC_KEY_SIZE = 32
SEED_SIZE = 32

IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    if y >= _P:
        raise ValueError("invalid point encoding")
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            raise ValueError("invalid point sign")
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("point is not on curve")
    if (x & 1) != sign:
        x = _P - x
    return x


def _encode_point(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    z_inv = pow(z, _P - 2, _P)
    x = x * z_inv % _P
    y = y * z_inv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != 32:
        raise ValueError("invalid public key length")
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_double(pt):
    x1, y1, z1, _ = pt
    a = x1 * x1 % _P
    b = y1 * y1 % _P
    c = 2 * z1 * z1 % _P
    d = -a % _P
    e = ((x1 + y1) * (x1 + y1) - a - b) % _P
    g = (d + b) % _P
    f = (g - c) % _P
    h = (d - b) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _negate(pt):
    x, y, z, t = pt
    return (-x % _P, y, z, -t % _P)


def _scalar_mult(pt, scalar: int):
    scalar %= (1 << 256)
    if scalar == 0:
        return IDENTITY
    table = [IDENTITY, pt]
    for _ in range(2, 16):
        table.append(_point_add(table[-1], pt))
    acc = IDENTITY
    nibbles = []
    value = scalar
    while value:
        nibbles.append(value & 15)
        value >>= 4
    for nibble in reversed(nibbles):
        for _ in range(4):
            acc = _point_double(acc)
        if nibble:
            acc = _point_add(acc, table[nibble])
    return acc


def _build_base_table():
    tables = []
    current = _decode_point(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))
    for _ in range(64):
        row = [IDENTITY]
        for _ in range(15):
            row.append(_point_add(row[-1], current))
        tables.append(row)
        current = _point_double(_point_double(_point_double(_point_double(current))))
    return tables


_BASE_TABLE = _build_base_table()


def _base_mult(scalar: int):
    acc = IDENTITY
    index = 0
    value = scalar
    while value:
        nibble = value & 15
        if nibble:
            acc = _point_add(acc, _BASE_TABLE[index][nibble])
        value >>= 4
        index += 1
    return acc


def _clamp(scalar_bytes: bytes) -> int:
    raw = bytearray(scalar_bytes)
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return int.from_bytes(raw, "little")


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    hashed = sha512(seed)
    secret = _clamp(hashed[:32])
    return _encode_point(_base_mult(secret))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    hashed = sha512(seed)
    secret = _clamp(hashed[:32])
    prefix = hashed[32:]
    public = _encode_point(_base_mult(secret))
    nonce = int.from_bytes(sha512(prefix + message), "little") % _L
    encoded_r = _encode_point(_base_mult(nonce))
    challenge = int.from_bytes(sha512(encoded_r + public + message), "little") % _L
    s = (nonce + challenge * secret) % _L
    return encoded_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != SIGNATURE_SIZE or len(public_key) != PUBLIC_KEY_SIZE:
        return False
    try:
        point_a = _decode_point(public_key)
        point_r = _decode_point(signature[:32])
    except ValueError:
        return False
    if _encode_point(point_a) != public_key or _encode_point(point_r) != signature[:32]:
        return False
    if _encode_point(point_a) == _encode_point(IDENTITY):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    challenge = int.from_bytes(sha512(signature[:32] + public_key + message), "little") % _L
    left = _base_mult(s)
    right = _point_add(point_r, _scalar_mult(point_a, challenge))
    return _encode_point(left) == _encode_point(right)


def address_from_public_key(public_key: bytes) -> str:
    body = digest("address", public_key)[:20]
    return encode_with_checksum(body, ADDRESS_PREFIX)


def public_key_from_address(address: str) -> bytes:
    return decode_with_checksum(address, ADDRESS_PREFIX)


@dataclass(frozen=True)
class KeyPair:
    """Ed25519 key pair plus the derived account address."""

    seed: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls.from_seed(os.urandom(SEED_SIZE))

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        return cls(seed=bytes(seed), public_key=public_key_from_seed(bytes(seed)))

    @property
    def address(self) -> str:
        return address_from_public_key(self.public_key)

    @property
    def seed_hex(self) -> str:
        return self.seed.hex()

    def sign(self, message: bytes) -> bytes:
        return sign(self.seed, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return verify(self.public_key, message, signature)
