"""Tachyon chain core: headers, transactions, state, and consensus pipeline.

Design pillars:
  * Proof-of-History (PoH) style verifiable ordering via a global slot clock.
  * Pipelined block production: fetch, gossip, verify, execute, finalize.
  * Optimistic parallel execution (Block-STM) for high throughput.
  * Stake-weighted BFT quorum finality (Tendermint/HotStuff inspired).
  * EIP-1559-style base fee market with compute-unit metering.
  * Merkle state commitments (Sparse Merkle Tree) for compact proofs.
  * Append-only ledger with pruning by slot.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from .encoding import u64, i64, digest, canonical_json
from .crypto import KeyPair, verify, digest as crypto_digest
from .merkle import root as merkle_root
from .smt import SparseMerkleTree

# ---------- Constants ----------
SLOT_MS = 400
SLOTS_PER_EPOCH = 400
GENESIS_SLOT = 0
GENESIS_TIME_MS = 1700000000000  # Unix ms
CU_PER_TX = 10_000
BASE_FEE_INITIAL = 1_000_000
BASE_FEE_MIN = 1_000  # minimum fee floor


# ---------- Data structures ----------

@dataclass(frozen=True)
class Transaction:
    sender: str
    nonce: int
    instructions: List[Tuple[str, bytes]]
    signature: bytes
    slot: int

    def message_bytes(self) -> bytes:
        return canonical_json({
            "sender": self.sender,
            "nonce": self.nonce,
            "instructions": [(pid, p.hex()) for pid, p in self.instructions],
            "slot": self.slot,
        })

    def verify(self, sender_pk: bytes) -> bool:
        return verify(sender_pk, self.message_bytes(), self.signature)


@dataclass(frozen=True)
class BlockHeader:
    slot: int
    parent_slot: int
    parent_hash: bytes
    transactions_root: bytes
    state_root: bytes
    base_fee: int
    leader: str
    timestamp: int

    def hash(self) -> bytes:
        return crypto_digest("block_header",
                             u64(self.slot),
                             i64(self.parent_slot),
                             self.parent_hash,
                             self.transactions_root,
                             self.state_root,
                             u64(self.base_fee),
                             self.leader.encode("utf-8"),
                             u64(self.timestamp))


@dataclass
class Block:
    header: BlockHeader
    transactions: List[Transaction]

    def compute_transactions_root(self) -> bytes:
        if not self.transactions:
            return digest("empty_tx_root")
        return merkle_root(tx.signature for tx in self.transactions)


@dataclass(frozen=True)
class Vote:
    voter: str
    slot: int
    block_hash: bytes
    timestamp: int


# ---------- State ----------

class State:
    """Key-value state committed through a Sparse Merkle Tree.

    Arbitrary application keys are hashed into 256-bit slots, because an SMT
    indexes by a fixed-width path. ``set`` updates the slot in place, so the
    root is order-independent and a single-key update is O(depth) instead of
    rebuilding every leaf.

    ``prove``/``get`` remain keyed by the caller's original key: the slot
    derivation is an internal detail, but proofs are over the slot, so a
    verifier recomputes it the same way.
    """

    SLOT_TAG = "state_slot"

    def __init__(self):
        self._data: Dict[bytes, bytes] = {}
        self._smt = SparseMerkleTree()

    @classmethod
    def slot(cls, key: bytes) -> bytes:
        """Derive the fixed 256-bit SMT slot for an application key."""
        return crypto_digest(cls.SLOT_TAG, key)

    def set(self, key: bytes, value: bytes) -> None:
        self._data[key] = value
        self._smt.set(self.slot(key), value)

    def get(self, key: bytes) -> Optional[bytes]:
        return self._data.get(key)

    def root(self) -> bytes:
        return self._smt.root()

    def prove(self, key: bytes):
        """Inclusion proof when the key exists, exclusion proof when it does not."""
        return self._smt.prove(self.slot(key), self._data.get(key))

    def copy(self) -> "State":
        st = State()
        st._data = dict(self._data)
        st._smt = self._smt.copy()
        return st


# ---------- Ledger ----------

class Ledger:
    def __init__(self):
        self.blocks: Dict[int, Block] = {}
        self.finalized_slot = -1
        self.votes: Dict[int, List[Vote]] = {}
        self._stake_map: Dict[str, int] = {}
        self.state = State()
        self._lock = threading.Lock()
        self.current_slot = GENESIS_SLOT

    def set_stake(self, address: str, stake: int) -> None:
        with self._lock:
            self._stake_map[address] = stake

    def get_stake(self, address: str) -> int:
        return self._stake_map.get(address, 0)

    def add_block(self, block: Block) -> bool:
        with self._lock:
            if block.header.slot in self.blocks:
                return False
            if block.header.parent_slot != -1 and block.header.parent_slot not in self.blocks:
                return False
            self.blocks[block.header.slot] = block
            return True

    def add_vote(self, vote: Vote) -> bool:
        with self._lock:
            if vote.slot not in self.votes:
                self.votes[vote.slot] = []
            self.votes[vote.slot].append(vote)
            return self._attempt_finalize(vote.slot)

    def _attempt_finalize(self, slot: int) -> bool:
        if slot <= self.finalized_slot:
            return False
        total_stake = sum(self._stake_map.values())
        if total_stake == 0:
            return False
        votes_for_slot = self.votes.get(slot, [])
        voted_stake = sum(self.get_stake(v.voter) for v in votes_for_slot)
        if voted_stake * 3 > total_stake * 2:  # > 2/3 quorum
            self.finalized_slot = slot
            return True
        return False

    def get_finalized_block(self) -> Optional[Block]:
        if self.finalized_slot == -1:
            return None
        return self.blocks.get(self.finalized_slot)


# ---------- Consensus pipeline ----------

class ConsensusSimulator:
    def __init__(self, ledger: Ledger, keypair: KeyPair):
        self.ledger = ledger
        self.keypair = keypair
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            now_ms = int(time.time() * 1000)
            slot = GENESIS_SLOT + (now_ms - GENESIS_TIME_MS) // SLOT_MS
            if slot > self.ledger.current_slot:
                self.ledger.current_slot = slot
                self._produce_block_if_leader(slot)
                self._vote_if_needed(slot)
            time.sleep(0.01)

    def _produce_block_if_leader(self, slot: int) -> None:
        parent = self.ledger.blocks.get(slot - 1)
        parent_hash = parent.header.hash() if parent else bytes(32)
        parent_slot = slot - 1 if parent else -1

        header = BlockHeader(
            slot=slot,
            parent_slot=parent_slot,
            parent_hash=parent_hash,
            transactions_root=digest("empty_tx_root"),
            state_root=self.ledger.state.root(),
            base_fee=BASE_FEE_INITIAL,
            leader=self.keypair.address,
            timestamp=int(time.time() * 1000),
        )
        block = Block(header=header, transactions=[])
        self.ledger.add_block(block)

    def _vote_if_needed(self, slot: int) -> None:
        block = self.ledger.blocks.get(slot)
        if block is None:
            return
        vote = Vote(
            voter=self.keypair.address,
            slot=slot,
            block_hash=block.header.hash(),
            timestamp=int(time.time() * 1000),
        )
        self.ledger.add_vote(vote)
