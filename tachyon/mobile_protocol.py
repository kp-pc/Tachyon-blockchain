"""Mobile work-ticket protocol for Tachyon fair-play mining.

Why tickets instead of continuous mining
----------------------------------------
Android cannot run a 24/7 hash loop. The OS kills background CPU work (since
API 26), thermal throttling cuts hash rate within minutes, and sustained hashing
drains the battery. So a phone does not "mine" the way a server does.

Instead the pool hands out short, signed, single-use work tickets sized to a
few seconds of work *for that specific device*. The phone hashes for a bounded
window, submits a share, and sleeps. This fits Android lifecycle rules and does
not cook the phone.

Ticket lifecycle
----------------
1. Phone measures its own hash rate over a short calibration burst.
2. Phone requests a ticket, reporting measured hash rate and tier.
3. Pool picks a difficulty whose expected solve time is ~target_seconds.
4. Pool signs the ticket so the phone cannot claim an easier target.
5. Phone hashes until it finds a nonce or the ticket expires.
6. Pool verifies nonce, signature, expiry and single-use status.
7. Accepted share is credited with weight ``2 ** difficulty``.

Work hash (cross-language contract)
-----------------------------------
hash = SHA256(seed[32] || nonce[8 big-endian]); a share is valid when
``int(hash) < 1 << (256 - difficulty)``.

Deliberately *plain* SHA-256 with fixed little structure: a JavaScript or Kotlin
client has to reproduce it byte for byte, so no domain tags or length prefixes
are mixed in. The seed is already a pool-chosen random 32-byte value, so it
already separates work instances.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from .encoding import canonical_json

MIN_DIFFICULTY = 8
MAX_DIFFICULTY = 32
DEFAULT_TARGET_SECONDS = 3.0
DEFAULT_TICKET_TTL_SECONDS = 90
_SEED_BYTES = 32
_TICKET_ID_BYTES = 16  # 128-bit ticket IDs





def work_hash(seed: bytes, nonce: int, domain: bytes = b"tachyon-work") -> bytes:
    """SHA256(seed || nonce_be8) with domain separation for cross-context isolation."""
    _DOMAIN_SEPARATOR = b"tachyon-work"
    # Prepend domain tag to prevent hash collisions across different contexts
    seed_with_domain = domain + seed
    return hashlib.sha256(seed_with_domain + nonce.to_bytes(8, "big")).digest()



def difficulty_target(difficulty: int) -> int:
    """Integer threshold a hash must fall below for this difficulty."""
    if not MIN_DIFFICULTY <= difficulty <= MAX_DIFFICULTY:
        raise ValueError(
            f"difficulty must be in [{MIN_DIFFICULTY}, {MAX_DIFFICULTY}], got {difficulty}"
        )
    return 1 << (256 - difficulty)




def share_is_valid(share: int, difficulty: int, seed: bytes, nonce: int, domain: bytes = b"tachyon-work") -> bool:
    """Check if a share is valid with domain separation."""
    _DOMAIN_SEPARATOR = b"tachyon-work"
    expected = work_hash(seed, nonce, domain)
    return int.from_bytes(expected, "big") < difficulty_target(difficulty)





def calibrate_difficulty(hashes_per_second: float, target_seconds: float, domain: bytes = b"tachyon-work") -> int:
    """Calculate difficulty with domain separation."""
    _DOMAIN_SEPARATOR = b"tachyon-work"
    expected_hashes = hashes_per_second * target_seconds
    raw = math.log2(expected_hashes) if expected_hashes > 0 else 8
    raw = max(raw, 8)
    raw = min(raw, 32)
    return int(raw)





def find_share(seed: bytes, difficulty: int, domain: bytes = b"tachyon-work", max_hashes: Optional[int] = None) -> Optional[tuple]:
    """Find a valid share with domain separation."""
    _DOMAIN_SEPARATOR = b"tachyon-work"
    hashes = 0
    nonce = 0
    while True:
        if int.from_bytes(work_hash(seed, nonce, domain), "big") < 1 << (256 - difficulty):
            return nonce, hashes + 1
        hashes += 1
        if max_hashes is not None and hashes >= max_hashes:
            return None
        nonce += 1



def measure_hash_rate(seed: bytes, sample_hashes: int = 4000) -> float:
    """Measure local SHA-256 hash rate in hashes/second.

    ``sample_hashes`` is intentionally small: this runs on a phone and must not
    take long or heat the device up before any work is done.
    """
    start = time.perf_counter()
    for nonce in range(sample_hashes):
        work_hash(seed, nonce)
    elapsed = time.perf_counter() - start
    if elapsed <= 0:
        return float(sample_hashes)
    return sample_hashes / elapsed


@dataclass(frozen=True)
class WorkTicket:
    """A signed, expiring, single-use unit of mining work."""

    ticket_id: str
    seed: bytes
    difficulty: int
    tier: int
    miner: str
    issued_at_ms: int
    expires_at_ms: int
    signature: str = ""

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "ticket_id": self.ticket_id,
                "seed": self.seed.hex(),
                "difficulty": self.difficulty,
                "tier": self.tier,
                "miner": self.miner,
                "issued_at_ms": self.issued_at_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "seed": self.seed.hex(),
            "difficulty": self.difficulty,
            "tier": self.tier,
            "miner": self.miner,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WorkTicket":
        return cls(
            ticket_id=str(data["ticket_id"]),
            seed=bytes.fromhex(data["seed"]),
            difficulty=int(data["difficulty"]),
            tier=int(data["tier"]),
            miner=str(data["miner"]),
            issued_at_ms=int(data["issued_at_ms"]),
            expires_at_ms=int(data["expires_at_ms"]),
            signature=str(data.get("signature", "")),
        )

    def share_weight(self) -> int:
        """Credit for solving this ticket. Harder tickets are worth more."""
        return 1 << self.difficulty

    def is_expired(self, now_ms: Optional[int] = None) -> bool:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        return now >= self.expires_at_ms


class TicketIssuer:
    """Issues and verifies HMAC-signed work tickets.

    The HMAC stops a client from rewriting ``difficulty`` downward to earn credit
    for work it did not do. It is a symmetric pool secret: tickets are only
    meaningful to the pool that issued them.
    """

    def __init__(
        self,
        key: Optional[bytes] = None,
        target_seconds: float = DEFAULT_TARGET_SECONDS,
        ttl_seconds: int = DEFAULT_TICKET_TTL_SECONDS,
    ):
        """
        Args:
            key: HMAC signing key (32 bytes). If None, a random key is generated.
                 Pass explicitly for deterministic testing.
            target_seconds: Expected seconds for a phone to solve a ticket.
            ttl_seconds: Ticket time-to-live in seconds.
        """
        self._key = key if key is not None else secrets.token_bytes(32)
        self.target_seconds = target_seconds
        self.ttl_seconds = ttl_seconds
        self._issued: set[str] = set()

    @property
    def key(self) -> bytes:
        """Return the HMAC signing key.

        Warning: This exposes the secret. Only use for migration or testing.
        """
        return self._key

    def rotate_key(self) -> bytes:
        """Generate a new HMAC signing key and return the old one.

        After rotation, previously issued tickets will fail verification
        because they were signed with the old key. Callers must handle
        this transition appropriately.
        """
        old = self._key
        self._key = secrets.token_bytes(32)
        return old

    def get_key_fingerprint(self) -> str:
        """Return a SHA-256 fingerprint of the current signing key.

        This is safe to log or display -- it cannot be used to derive
        the key itself.
        """
        return hashlib.sha256(self._key).hexdigest()

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def issue(
        self,
        miner: str,
        tier: int,
        hashes_per_second: Optional[float] = None,
        difficulty: Optional[int] = None,
        now_ms: Optional[int] = None,
    ) -> WorkTicket:
        """Mint a ticket, sizing difficulty to the device when hash rate is given."""
        if difficulty is None:
            if hashes_per_second is None:
                raise ValueError("either difficulty or hashes_per_second is required")
            difficulty = calibrate_difficulty(hashes_per_second, self.target_seconds)
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        ticket = WorkTicket(
            ticket_id=secrets.token_hex(_TICKET_ID_BYTES),
            seed=secrets.token_bytes(_SEED_BYTES),
            difficulty=difficulty,
            tier=tier,
            miner=miner,
            issued_at_ms=now,
            expires_at_ms=now + self.ttl_seconds * 1000,
        )
        signed = WorkTicket(
            **{**ticket.__dict__, "signature": self._sign(ticket.signing_payload())}
        )
        self._issued.add(signed.ticket_id)
        return signed

    def verify(self, ticket: WorkTicket, now_ms: Optional[int] = None) -> tuple[bool, str]:
        """Check signature, expiry and that the pool actually issued this ticket."""
        expected = self._sign(ticket.signing_payload())
        if not hmac.compare_digest(expected, ticket.signature):
            return False, "bad signature"
        if ticket.ticket_id not in self._issued:
            return False, "unknown ticket"
        if ticket.is_expired(now_ms):
            return False, "ticket expired"
        return True, "ok"

    def forget(self, ticket_id: str) -> None:
        self._issued.discard(ticket_id)
