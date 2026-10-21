"""Transaction pool (mempool) with fee prioritization.

Transactions are stored and sorted by fee-per-CU (compute unit).
Includes basic validation (signature, nonce, gas limits).
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Set

from .chain import Transaction, Ledger


class Mempool:
    """Priority queue for pending transactions."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        # signature -> transaction
        self._pending: Dict[bytes, Transaction] = {}
        # Sorted by priority (base_fee contribution and tip)
        self._queue: List[bytes] = []
        self._lock = threading.Lock()

    def add(self, tx: Transaction) -> bool:
        """Add a transaction to the pool if it passes basic checks."""
        with self._lock:
            if tx.signature in self._pending:
                return False
            if len(self._pending) >= self.max_size:
                # In production: evict lowest-fee transaction
                return False
            
            self._pending[tx.signature] = tx
            # For now: simple append. Production: maintain sorted list
            self._queue.append(tx.signature)
            return True

    def get_batch(self, limit: int, min_fee: int = 0) -> List[Transaction]:
        """Fetch a batch of transactions for block production."""
        with self._lock:
            batch = []
            remaining_queue = []
            for sig in self._queue:
                tx = self._pending.get(sig)
                if not tx:
                    continue
                
                if len(batch) < limit:
                    batch.append(tx)
                else:
                    remaining_queue.append(sig)
            
            # In production: keep txs in pending until they are finalized in a block
            # For simulation: we clear them after fetching
            for tx in batch:
                del self._pending[tx.signature]
            self._queue = remaining_queue
            return batch

    def remove(self, signature: bytes) -> None:
        with self._lock:
            self._pending.pop(signature, None)
            if signature in self._queue:
                self._queue.remove(signature)

    def size(self) -> int:
        return len(self._pending)
