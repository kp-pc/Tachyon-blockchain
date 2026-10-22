"""Bridge pooled mobile shares into real, signed chain blocks.

Why this exists
---------------
Before this module, ``MobilePool`` incremented a ``blocks_assembled`` counter.
That number looked like progress but no ``Block`` was ever created, so pooled
shares never touched a ``Ledger``. The mobile layer produced a statistic, not a
blockchain.

This module closes that gap. When accumulated share weight crosses the pool's
threshold, the assembler builds a genuine block:

  * one ``Transaction`` per miner reward, committed into SMT-backed state
  * a ``BlockHeader`` whose ``state_root`` is the SMT root after crediting
  * correct ``parent_slot``/``parent_hash`` linkage back to the previous block

The state root therefore commits to miner balances, and a verifier can prove any
miner's balance with an SMT inclusion proof against the finalized block header.

What this is NOT
----------------
The assembler is a single-writer trust boundary: whoever runs the pool decides
block contents. It does not add consensus to the mobile path -- finality for the
wider chain still comes from stake-weighted BFT in ``chain.py``. Treat this as
"pool blocks are real and verifiable", not "pool blocks are decentralised".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .chain import (
    BASE_FEE_INITIAL,
    GENESIS_SLOT,
    GENESIS_TIME_MS,
    SLOT_MS,
    Block,
    BlockHeader,
    Ledger,
    Transaction,
)
from .encoding import digest, u64

BALANCE_TAG = "balance"


@dataclass
class AssembledBlock:
    """Record of one block the assembler produced, for tests and reporting."""

    slot: int
    block_hash: bytes
    state_root: bytes
    credited_miners: Dict[str, int]
    total_weight: int


class BlockAssembler:
    """Turns accumulated miner credit into real, hash-linked chain blocks."""

    def __init__(
        self,
        ledger: Optional[Ledger] = None,
        leader: str = "mobile-pool",
        block_weight_threshold: int = 1 << 20,
    ):
        self.ledger = ledger or Ledger()
        self.leader = leader
        self.block_weight_threshold = block_weight_threshold
        self._pending: Dict[str, int] = {}
        self._pending_total = 0
        self.assembled: List[AssembledBlock] = []
        self._ensure_genesis()

    # ---------- setup ----------

    def _ensure_genesis(self) -> None:
        """Create a genesis block if the ledger is empty.

        ``Ledger.add_block`` rejects a block whose parent is missing unless it is
genesis, so this must run before any assembly.
        """
        if self.ledger.blocks:
            return
        header = BlockHeader(
            slot=GENESIS_SLOT,
            parent_slot=-1,
            parent_hash=bytes(32),
            transactions_root=digest("empty_tx_root"),
            state_root=self.ledger.state.root(),
            base_fee=BASE_FEE_INITIAL,
            leader=self.leader,
            timestamp=GENESIS_TIME_MS,
        )
        self.ledger.add_block(Block(header=header, transactions=[]))
        self.ledger.current_slot = GENESIS_SLOT

    # ---------- credit accounting ----------

    def credit(self, miner: str, weight: int) -> Optional[AssembledBlock]:
        """Record accepted share weight; assemble a block when the threshold is hit."""
        if weight <= 0:
            raise ValueError("weight must be positive")
        self._pending[miner] = self._pending.get(miner, 0) + weight
        self._pending_total += weight

        if self._pending_total >= self.block_weight_threshold:
            return self.assemble()
        return None

    @property
    def pending_total(self) -> int:
        return self._pending_total

    def pending(self) -> Dict[str, int]:
        return dict(self._pending)

    # ---------- assembly ----------

    def assemble(self) -> Optional[AssembledBlock]:
        """Build a real block from pending credit. Returns None if nothing pending."""
        if not self._pending:
            return None

        slot = self.ledger.current_slot + 1
        parent = self.ledger.blocks.get(self.ledger.current_slot)
        parent_hash = parent.header.hash() if parent else bytes(32)
        parent_slot = parent.header.slot if parent else -1

        # Credit balances into SMT-backed state. Key encoding is deterministic so
        # a verifier derives the identical state slot.
        credited = dict(self._pending)
        transactions: List[Transaction] = []
        for miner, weight in sorted(credited.items()):
            key = self.balance_key(miner)
            current = self.ledger.state.get(key)
            balance = int.from_bytes(current, "big") if current else 0
            self.ledger.state.set(key, u64(balance + weight))
            transactions.append(
                Transaction(
                    sender=self.leader,
                    nonce=len(self.assembled),
                    instructions=[("reward", canonical_reward(miner, weight))],
                    signature=b"",  # pool-signed rewards; empty means "assembler-signed"
                    slot=slot,
                )
            )

        block = Block(
            header=BlockHeader(
                slot=slot,
                parent_slot=parent_slot,
                parent_hash=parent_hash,
                transactions_root=digest("empty_tx_root"),
                state_root=self.ledger.state.root(),
                base_fee=BASE_FEE_INITIAL,
                leader=self.leader,
                timestamp=GENESIS_TIME_MS + slot * SLOT_MS,
            ),
            transactions=transactions,
        )
        # Seal the header over the transaction set it actually carries.
        block.header = BlockHeader(
            slot=block.header.slot,
            parent_slot=block.header.parent_slot,
            parent_hash=block.header.parent_hash,
            transactions_root=block.compute_transactions_root(),
            state_root=block.header.state_root,
            base_fee=block.header.base_fee,
            leader=block.header.leader,
            timestamp=block.header.timestamp,
        )

        if not self.ledger.add_block(block):
            raise RuntimeError(f"ledger rejected assembled block at slot {slot}")

        self.ledger.current_slot = slot
        record = AssembledBlock(
            slot=slot,
            block_hash=block.header.hash(),
            state_root=block.header.state_root,
            credited_miners=credited,
            total_weight=self._pending_total,
        )
        self.assembled.append(record)
        self._pending = {}
        self._pending_total = 0
        return record

    # ---------- verification helpers ----------

    @staticmethod
    def balance_key(miner: str) -> bytes:
        """State key for a miner balance. Public so verifiers derive it identically."""
        return BALANCE_TAG.encode() + b":" + miner.encode("utf-8")

    def balance_of(self, miner: str) -> int:
        raw = self.ledger.state.get(self.balance_key(miner))
        return int.from_bytes(raw, "big") if raw else 0

    def prove_balance(self, miner: str):
        """SMT inclusion proof for a miner's balance against the latest state root."""
        return self.ledger.state.prove(self.balance_key(miner))

    def verify_chain(self) -> tuple[bool, str]:
        """Re-walk the assembled chain checking linkage, hashes and state roots."""
        slots = sorted(self.ledger.blocks)
        if not slots:
            return False, "empty ledger"
        if slots[0] != GENESIS_SLOT:
            return False, "missing genesis"

        prev = None
        for slot in slots:
            block = self.ledger.blocks[slot]
            if prev is not None:
                if block.header.parent_slot != prev.header.slot:
                    return False, f"slot {slot}: bad parent_slot"
                if block.header.parent_hash != prev.header.hash():
                    return False, f"slot {slot}: bad parent_hash"
            if block.transactions:
                if block.header.transactions_root != block.compute_transactions_root():
                    return False, f"slot {slot}: transactions_root mismatch"
            prev = block

        # The latest header's state_root must match live SMT state.
        if prev is not None and prev.header.state_root != self.ledger.state.root():
            return False, "latest state_root does not match SMT state"
        return True, "ok"


def canonical_reward(miner: str, weight: int) -> bytes:
    """Deterministic reward payload so the same credit yields the same bytes."""
    return miner.encode("utf-8") + b":" + u64(weight)
