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


# ---------------------------------------------------------------------------
# Constant-time helpers
# ---------------------------------------------------------------------------

def _ct_select(a: int, b: int, mask: int) -> int:
    """Select `a` when `mask` is non-zero, `b` when `mask` is zero.

    `mask` must be 0 or 1.  The operation is constant-time with respect to
    the value of `mask`.
    """
    # In Python, -1 is all 1s and 0 is all 0s.
    # mask=1: (a & -1) | (b & 0) = a
    # mask=0: (a & 0) | (b & -1) = b
    return (a & -mask) | (b & (mask - 1))


def _ct_select_point(a: tuple, b: tuple, mask: int) -> tuple:
    """Constant-time point selection."""
    return tuple(_ct_select(ai, bi, mask) for ai, bi in zip(a, b))


def _ct_eq(x: int, y: int, bits: int = 4) -> int:
    """Constant-time equality check.  Returns 1 if x == y, 0 otherwise.

    Works for non-negative integers x, y < 2**bits.
    """
    mask_bits = (1 << bits) - 1
    diff = (x ^ y) & mask_bits
    neg_diff = (-diff) & mask_bits
    is_nonzero = ((diff | neg_diff) >> (bits - 1)) & 1
    return 1 - is_nonzero


def _ct_lookup(table: list, index: int, bits: int = 4) -> tuple:
    """Constant-time lookup in a table of 2**bits entries."""
    result = table[0]
    for i in range(1, len(table)):
        mask = _ct_eq(i, index, bits)
        result = _ct_select_point(table[i], result, mask)
    return result


def _ct_bytes_eq(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# Field and curve operations
# ---------------------------------------------------------------------------

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
    """Constant-time point addition on twisted Edwards curve."""
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
    """Constant-time point doubling on twisted Edwards curve."""
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
    """Constant-time scalar multiplication using 4-bit window method.

    Always processes all 64 nibbles (256 bits) regardless of scalar value.
    Uses constant-time table lookup for point selection.
    """
    scalar %= (1 << 256)

    # Build table of 16 points: [0*pt, 1*pt, ..., 15*pt]
    table = [IDENTITY, pt]
    for _ in range(2, 16):
        table.append(_point_add(table[-1], pt))

    acc = IDENTITY
    # Process all 64 nibbles from MSB to LSB
    for nibble_pos in range(63, -1, -1):
        # Always double 4 times
        for _ in range(4):
            acc = _point_double(acc)
        # Always add, but use constant-time lookup
        nibble = (scalar >> (nibble_pos * 4)) & 15
        to_add = _ct_lookup(table, nibble, 4)
        acc = _point_add(acc, to_add)

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
    """Constant-time base point multiplication.

    Always processes all 64 nibbles regardless of scalar value.
    Uses constant-time table lookup for point selection.
    """
    scalar %= (1 << 256)
    acc = IDENTITY
    for index in range(64):
        nibble = (scalar >> (index * 4)) & 15
        to_add = _ct_lookup(_BASE_TABLE[index], nibble, 4)
        acc = _point_add(acc, to_add)
    return acc


def _clamp(scalar_bytes: bytes) -> int:
    raw = bytearray(scalar_bytes)
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return int.from_bytes(raw, "little")


def _hash_to_scalar(data: bytes) -> int:
    """Hash data to a scalar in [0, _L-1] using SHA-512.

    Uses consistent reduction as required by RFC 8032.
    """
    return int.from_bytes(sha512(data), "little") % _L


def is_valid_public_key(pk_bytes: bytes) -> bool:
    """Check that a public key is in the prime-order subgroup.

    Returns True if the public key:
    1. Is a valid encoding (32 bytes, decodes to a point on the curve)
    2. Is not the identity element
    3. Is in the prime-order subgroup (L * point == identity)
    """
    if len(pk_bytes) != PUBLIC_KEY_SIZE:
        return False
    try:
        point = _decode_point(pk_bytes)
    except ValueError:
        return False

    # Check not identity
    if _encode_point(point) == _encode_point(IDENTITY):
        return False

    # Check subgroup: L * point should be identity
    check = _scalar_mult(point, _L)
    return _encode_point(check) == _encode_point(IDENTITY)


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    hashed = sha512(seed)
    secret = _clamp(hashed[:32])
    public_point = _base_mult(secret)
    # Validate that the resulting point is not the identity
    if _encode_point(public_point) == _encode_point(IDENTITY):
        raise ValueError("derived public key is the identity element")
    return _encode_point(public_point)


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    hashed = sha512(seed)
    secret = _clamp(hashed[:32])
    prefix = hashed[32:]
    public = _encode_point(_base_mult(secret))
    nonce = _hash_to_scalar(prefix + message)
    encoded_r = _encode_point(_base_mult(nonce))
    challenge = _hash_to_scalar(encoded_r + public + message)
    s = (nonce + challenge * secret) % _L
    return encoded_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != SIGNATURE_SIZE or len(public_key) != PUBLIC_KEY_SIZE:
        return False

    # Subgroup validation
    if not is_valid_public_key(public_key):
        return False

    try:
        point_a = _decode_point(public_key)
        point_r = _decode_point(signature[:32])
    except ValueError:
        return False

    # Verify canonical encoding
    if _encode_point(point_a) != public_key or _encode_point(point_r) != signature[:32]:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False

    challenge = _hash_to_scalar(signature[:32] + public_key + message)

    # Compute [s]G + [challenge]A
    left = _base_mult(s)
    right = _point_add(point_r, _scalar_mult(point_a, challenge))

    # Constant-time comparison
    left_enc = _encode_point(left)
    right_enc = _encode_point(right)

    return _ct_bytes_eq(left_enc, right_enc)


def verify_batch(public_keys: list, messages: list, signatures: list) -> bool:
    """Batch verification of multiple Ed25519 signatures.

    Uses random linear combination technique to verify multiple signatures
    in a single operation.  The verification equation is:
        [s_i]G + [c_i]A_i - R_i = 0

    By combining with random coefficients a_i:
        sum(a_i * ([s_i]G + [c_i]A_i - R_i)) = 0

    This reduces N scalar multiplications and point additions to a single
    combined computation.
    """
    if len(public_keys) != len(messages) or len(public_keys) != len(signatures):
        return False

    n = len(public_keys)
    if n == 0:
        return True

    # Generate deterministic random coefficients from the batch data
    seed_data = b"".join(pk + msg + sig for pk, msg, sig in zip(public_keys, messages, signatures))

    g_scalar = 0
    acc = IDENTITY

    for i in range(n):
        pk = public_keys[i]
        msg = messages[i]
        sig = signatures[i]

        if len(pk) != PUBLIC_KEY_SIZE or len(sig) != SIGNATURE_SIZE:
            return False

        # Subgroup validation for each public key
        if not is_valid_public_key(pk):
            return False

        try:
            point_a = _decode_point(pk)
            point_r = _decode_point(sig[:32])
        except ValueError:
            return False

        # Verify canonical encoding
        if _encode_point(point_a) != pk or _encode_point(point_r) != sig[:32]:
            return False

        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False

        # Generate random coefficient for this signature
        coeff = int.from_bytes(digest("batch", seed_data + i.to_bytes(4, "little")), "little") % _L
        if coeff == 0:
            coeff = 1

        challenge = _hash_to_scalar(sig[:32] + pk + msg)

        # Accumulate g_scalar: sum(a_i * s_i)
        g_scalar = (g_scalar + coeff * s) % _L

        # Add [-coeff * challenge] * A_i to accumulator
        # The verification equation is: [s]G = R + [c]A
        # So: [s]G - R - [c]A = 0
        # With coefficient a: [a*s]G - [a]R - [a*c]A = 0
        neg_c = (-coeff * challenge) % _L
        acc = _point_add(acc, _scalar_mult(point_a, neg_c))

        # Add [-coeff] * R_i to accumulator
        neg_coeff = (-coeff) % _L
        acc = _point_add(acc, _scalar_mult(point_r, neg_coeff))

    # Add [g_scalar] * G to accumulator
    acc = _point_add(acc, _base_mult(g_scalar))

    return _encode_point(acc) == _encode_point(IDENTITY)


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
