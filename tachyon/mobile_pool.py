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

import json
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

SUBMIT_GRACE_MS = 15_000
BLOCK_WEIGHT_THRESHOLD = 1 << 24  # ~16.7M share weight per block


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


@dataclass
class MinerAccount:
    address: str
    tier: int
    credit: int = 0
    shares_accepted: int = 0
    shares_rejected: int = 0
    difficulty: int = MIN_DIFFICULTY
    last_submit_ms: int = 0


class MobilePool:
    """Coordinates mobile miners and assembles blocks from accumulated shares."""

    def __init__(
        self,
        target_seconds: float = 3.0,
        block_weight_threshold: int = BLOCK_WEIGHT_THRESHOLD,
        issuer: Optional[TicketIssuer] = None,
    ):
        self.issuer = issuer or TicketIssuer(target_seconds=target_seconds)
        self.block_weight_threshold = block_weight_threshold
        self._lock = threading.RLock()
        self._accounts: Dict[str, MinerAccount] = {}
        self._open_tickets: Dict[str, WorkTicket] = {}
        self._consumed_tickets: set[str] = set()
        self._recent_shares: Deque[ShareRecord] = deque(maxlen=500)
        self._pending_weight = 0
        self._blocks_assembled = 0
        self._recent_solve_ms: Deque[int] = deque(maxlen=20)

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
        """Issue a ticket, adapting difficulty to observed solve times."""
        with self._lock:
            account = self.register(miner, tier)
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
            if not isinstance(nonce, int) or nonce < 0:
                return reject("invalid nonce")
            if not share_is_valid(ticket.seed, nonce, ticket.difficulty):
                return reject("share does not meet target")

            # 4. Credit
            weight = ticket.share_weight()
            account.credit += weight
            account.shares_accepted += 1
            account.difficulty = ticket.difficulty
            account.last_submit_ms = now
            self._consumed_tickets.add(ticket.ticket_id)
            self._open_tickets.pop(ticket.ticket_id, None)
            self._pending_weight += weight

            if elapsed_ms is not None and elapsed_ms >= 0:
                self._recent_solve_ms.append(int(elapsed_ms))

            record = ShareRecord(
                miner=ticket.miner,
                ticket_id=ticket.ticket_id,
                difficulty=ticket.difficulty,
                tier=ticket.tier,
                nonce=nonce,
                weight=weight,
                accepted_at_ms=now,
                credited=True,
                reason="accepted",
            )
            self._recent_shares.append(record)

            # 5. Block assembly
            if self._pending_weight >= self.block_weight_threshold:
                self._pending_weight = 0
                self._blocks_assembled += 1
                record.reason = "accepted (block assembled)"

            return record

    # ---------- reporting ----------

    def status(self) -> dict:
        with self._lock:
            total_credit = sum(a.credit for a in self._accounts.values())
            by_tier: Dict[int, int] = {}
            for account in self._accounts.values():
                by_tier[account.tier] = by_tier.get(account.tier, 0) + 1
            return {
                "miners": len(self._accounts),
                "miners_by_tier": by_tier,
                "shares_accepted": sum(a.shares_accepted for a in self._accounts.values()),
                "shares_rejected": sum(a.shares_rejected for a in self._accounts.values()),
                "total_credit": total_credit,
                "pending_block_weight": self._pending_weight,
                "block_weight_threshold": self.block_weight_threshold,
                "blocks_assembled": self._blocks_assembled,
                "open_tickets": len(self._open_tickets),
            }

    def leaderboard(self, limit: int = 10) -> List[dict]:
        with self._lock:
            ranked = sorted(self._accounts.values(), key=lambda a: a.credit, reverse=True)
            return [
                {
                    "miner": a.address,
                    "tier": a.tier,
                    "credit": a.credit,
                    "shares_accepted": a.shares_accepted,
                    "shares_rejected": a.shares_rejected,
                    "difficulty": a.difficulty,
                }
                for a in ranked[:limit]
            ]

    def recent_shares(self, limit: int = 10) -> List[dict]:
        with self._lock:
            items = list(self._recent_shares)[-limit:]
            return [
                {
                    "miner": r.miner,
                    "difficulty": r.difficulty,
                    "weight": r.weight,
                    "credited": r.credited,
                    "reason": r.reason,
                }
                for r in items
            ]
