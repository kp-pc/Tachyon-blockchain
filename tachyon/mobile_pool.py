"""Mobile mining pool for Tachyon: ticket issuance, share accounting, block assembly.

Why a pool and not solo mining
------------------------------
A phone finds a share only once every ~3 seconds at its calibrated difficulty.
Alone, that phone would need thousands of tickets before it assembled a block.
The pool aggregates millions of small shares into one block, then credits each
miner proportionally by accumulated share weight. This is how a 200k H/s phone
participates meaningfully next to a 10M H/s server.

Share weight
------------
Each accepted share is credited ``2 ** difficulty``. A phone solving difficulty
16 earns 65,536 per share; a server solving difficulty 23 earns 8,388,608. So the
server still earns more absolute credit (it does more work) but the phone earns
*proportionally fair* credit for its actual hashes -- which is the honest
meaning of 'equal playing field': no tier is cheated on payout per unit of work.

Replay and latency handling
---------------------------
- A ticket is single-use: once a share is accepted for it, resubmission is rejected.
- Tickets expire, but submits are allowed for a grace window after expiry so a
  phone that solved just before expiry is not punished for network latency.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from .mobile_protocol import (
    MAX_DIFFICULTY,
    MIN_DIFFICULTY,
    TicketIssuer,
    WorkTicket,
    calibrate_difficulty,
    share_is_valid,
)
from .mobile_chain import BlockAssembler

SUBMIT_GRACE_MS = 15_000
BLOCK_WEIGHT_THRESHOLD = 1 << 24  # ~16.7M share weight per block

# Rate limiting: minimum seconds between ticket requests per miner
MIN_TICKET_REQUEST_INTERVAL_S = 1.0
# Maximum consumed tickets to track before cleanup
MAX_CONSUMED_TICKETS = 100_000
# Cleanup runs every N operations
CLEANUP_INTERVAL = 1000


@dataclass
class ShareRecord:
    miner: str
    ticket_id: str
    difficulty: int
    tier: int
    nonce: int
    weight: int
    accepted_at_ms: int
    credited: bool
    reason: str
    block_hash: Optional[bytes] = None


@dataclass
class MinerAccount:
    address: str
    tier: int
    credit: int = 0
    shares_accepted: int = 0
    shares_rejected: int = 0
    difficulty: int = MIN_DIFFICULTY
    last_submit_ms: int = 0
    last_ticket_request_ms: int = 0


class MobilePool:
    """Coordinates mobile miners and assembles blocks from accumulated shares."""

    def __init__(
        self,
        target_seconds: float = 3.0,
        block_weight_threshold: int = BLOCK_WEIGHT_THRESHOLD,
        issuer: Optional[TicketIssuer] = None,
        assembler: Optional[BlockAssembler] = None,
        min_ticket_interval_s: float = 0.0,
    ):
        self.issuer = issuer or TicketIssuer(target_seconds=target_seconds)
        self.block_weight_threshold = block_weight_threshold
        # When an assembler is supplied, crossing the threshold produces a real,
        # hash-linked chain block instead of only incrementing a counter.
        self.assembler = assembler
        # Rate limiting: minimum seconds between ticket requests per miner.
        # Default 0.0 disables rate limiting. Set to e.g. 1.0 to enforce
        # a 1-second minimum interval between ticket requests.
        self.min_ticket_interval_s = min_ticket_interval_s
        self._lock = threading.RLock()
        self._accounts: Dict[str, MinerAccount] = {}
        self._open_tickets: Dict[str, WorkTicket] = {}
        # Consumed tickets with their expiry time for bounded cleanup
        self._consumed_tickets: Dict[str, int] = {}
        self._recent_shares: Deque[ShareRecord] = deque(maxlen=500)
        self._pending_weight = 0
        self._blocks_assembled = 0
        self._last_block_hash: Optional[bytes] = None
        self._recent_solve_ms: Deque[int] = deque(maxlen=20)
        self._operation_count = 0

    # ---------- cleanup ----------

    def _cleanup_expired(self) -> None:
        """Remove consumed tickets that have expired and bound the dict size."""
        now_ms = int(time.time() * 1000)
        expired = [
            tid
            for tid, expires_at in self._consumed_tickets.items()
            if expires_at < now_ms
        ]
        for tid in expired:
            del self._consumed_tickets[tid]

        # Hard bound: if still too large, evict oldest entries
        if len(self._consumed_tickets) > MAX_CONSUMED_TICKETS:
            # Sort by expiry and remove the most expired ones
            sorted_items = sorted(
                self._consumed_tickets.items(), key=lambda x: x[1]
            )
            excess = len(self._consumed_tickets) - MAX_CONSUMED_TICKETS
            for tid, _ in sorted_items[:excess]:
                del self._consumed_tickets[tid]

    def _maybe_cleanup(self) -> None:
        """Run cleanup periodically based on operation count."""
        self._operation_count += 1
        if self._operation_count % CLEANUP_INTERVAL == 0:
            self._cleanup_expired()

    # ---------- registration and tickets ----------

    def register(self, miner: str, tier: int) -> MinerAccount:
        with self._lock:
            account = self._accounts.get(miner)
            if account is None:
                account = MinerAccount(address=miner, tier=tier)
                self._accounts[miner] = account
            else:
                account.tier = tier
            return account

    def request_ticket(
        self,
        miner: str,
        tier: int,
        hashes_per_second: Optional[float] = None,
    ) -> WorkTicket:
        """Issue a ticket, adapting difficulty to observed solve times.

        Returns a rejection record if the miner is rate limited.
        """
        with self._lock:
            account = self.register(miner, tier)

            # Rate limiting: enforce minimum interval between ticket requests
            now_ms = int(time.time() * 1000)
            if account.last_ticket_request_ms > 0 and self.min_ticket_interval_s > 0:
                elapsed_since_last = now_ms - account.last_ticket_request_ms
                min_interval_ms = int(self.min_ticket_interval_s * 1000)
                if elapsed_since_last < min_interval_ms:
                    account.shares_rejected += 1
                    raise RateLimitError(
                        f"rate limited: {elapsed_since_last}ms since last request "
                        f"(min {min_interval_ms}ms)"
                    )
            account.last_ticket_request_ms = now_ms

            difficulty = account.difficulty

            if hashes_per_second is not None and hashes_per_second > 0:
                calibrated = calibrate_difficulty(hashes_per_second, self.issuer.target_seconds)
                difficulty = calibrated

            # Adapt from real solve times if we have enough samples
            if len(self._recent_solve_ms) >= 5:
                avg_ms = sum(self._recent_solve_ms) / len(self._recent_solve_ms)
                target_ms = self.issuer.target_seconds * 1000
                if avg_ms < target_ms * 0.4 and difficulty < MAX_DIFFICULTY:
                    difficulty += 1
                elif avg_ms > target_ms * 2.5 and difficulty > MIN_DIFFICULTY:
                    difficulty -= 1

            difficulty = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, difficulty))
            account.difficulty = difficulty

            ticket = self.issuer.issue(miner=miner, tier=tier, difficulty=difficulty)
            self._open_tickets[ticket.ticket_id] = ticket
            self._maybe_cleanup()
            return ticket

    # ---------- share submission ----------

    def submit_share(
        self,
        ticket_dict: dict,
        nonce: int,
        hashes_tried: Optional[int] = None,
        elapsed_ms: Optional[int] = None,
        now_ms: Optional[int] = None,
    ) -> ShareRecord:
        """Validate and credit a share. Rejects replays, forgeries and stale tickets."""
        now = now_ms if now_ms is not None else int(time.time() * 1000)

        try:
            ticket = WorkTicket.from_dict(ticket_dict)
        except (KeyError, TypeError, ValueError) as exc:
            return ShareRecord(
                miner=ticket_dict.get("miner", "unknown") if isinstance(ticket_dict, dict) else "unknown",
                ticket_id="invalid",
                difficulty=0,
                tier=0,
                nonce=nonce if isinstance(nonce, int) else -1,
                weight=0,
                accepted_at_ms=now,
                credited=False,
                reason=f"malformed ticket: {exc}",
            )

        with self._lock:
            account = self._accounts.get(ticket.miner)
            if account is None:
                account = self.register(ticket.miner, ticket.tier)

            def reject(reason: str) -> ShareRecord:
                account.shares_rejected += 1
                record = ShareRecord(
                    miner=ticket.miner,
                    ticket_id=ticket.ticket_id,
                    difficulty=ticket.difficulty,
                    tier=ticket.tier,
                    nonce=nonce if isinstance(nonce, int) else -1,
                    weight=0,
                    accepted_at_ms=now,
                    credited=False,
                    reason=reason,
                )
                self._recent_shares.append(record)
                return record

            # 1. Replay protection
            if ticket.ticket_id in self._consumed_tickets:
                return reject("ticket already used")

            # 2. Signature + issuance + expiry (with submit grace)
            ok, reason = self.issuer.verify(ticket, now_ms=now - SUBMIT_GRACE_MS)
            if not ok:
                return reject(reason)

            # 3. Nonce actually solves the ticket
            if not share_is_valid(ticket.seed, nonce, ticket.difficulty):
                return reject("share does not meet difficulty target")

            # Accept the share
            weight = ticket.share_weight()
            record = ShareRecord(
                miner=ticket.miner,
                ticket_id=ticket.ticket_id,
                difficulty=ticket.difficulty,
                tier=ticket.tier,
                nonce=nonce if isinstance(nonce, int) else -1,
                weight=weight,
                accepted_at_ms=now,
                credited=True,
                reason="ok",
            )
            self._recent_shares.append(record)

            # Mark as consumed with expiry for cleanup
            self._consumed_tickets[ticket.ticket_id] = ticket.expires_at_ms
            self._open_tickets.pop(ticket.ticket_id, None)

            account.shares_accepted += 1
            account.last_submit_ms = now
            account.credit += weight
            self._pending_weight += weight
            self._recent_solve_ms.append(elapsed_ms if elapsed_ms is not None else 0)

            # Feed the assembler when threshold crossed
            if self._pending_weight >= self.block_weight_threshold:
                if self.assembler is not None:
                    assembled = self.assembler.credit(ticket.miner, weight)
                    if assembled is not None:
                        record.block_hash = assembled.block_hash
                        self._blocks_assembled += 1
                self._pending_weight = 0

            self._maybe_cleanup()
            return record

    def leaderboard(self) -> List[dict]:
        """Return miners ranked by credit, highest first."""
        with self._lock:
            accounts = sorted(
                self._accounts.values(), key=lambda a: a.credit, reverse=True
            )
            return [
                {"miner": a.address, "credit": a.credit, "tier": a.tier}
                for a in accounts
            ]

    def status(self) -> dict:
        """Return a snapshot of pool state for monitoring."""
        with self._lock:
            real_blocks = self._blocks_assembled
            if self.assembler is not None:
                real_blocks = len(self.assembler.assembled)
            last_block_hash = None
            if self.assembler is not None and self.assembler.assembled:
                last_block_hash = self.assembler.assembled[-1].block_hash
            elif self._last_block_hash is not None:
                last_block_hash = self._last_block_hash
            return {
                "real_blocks": real_blocks,
                "last_block_hash": last_block_hash,
                "blocks_assembled": self._blocks_assembled,
                "pending_weight": self._pending_weight,
                "open_tickets": len(self._open_tickets),
                "consumed_tickets": len(self._consumed_tickets),
                "accounts": len(self._accounts),
                "shares_accepted": sum(a.shares_accepted for a in self._accounts.values()),
                "shares_rejected": sum(a.shares_rejected for a in self._accounts.values()),
            }


class RateLimitError(Exception):
    """Raised when a miner exceeds the ticket request rate limit."""
    pass
