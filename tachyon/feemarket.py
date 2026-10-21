"""EIP-1559-style fee market with compute-unit metering.

Tachyon uses a base fee that adjusts per slot based on how full the block was.
"""

from __future__ import annotations

from .chain import Block, Ledger, BASE_FEE_INITIAL, BASE_FEE_MIN, SLOTS_PER_EPOCH


class FeeMarket:
    """Adjusts base fee each epoch based on block utilization."""

    def __init__(self, initial_fee: int = BASE_FEE_INITIAL):
        self.base_fee = initial_fee
        self.max_change_pct = 0.10  # 10% max change per adjustment
        self.target_utilization = 0.5  # 50% full target

    def adjust(self, ledger: Ledger, slot: int) -> int:
        """Calculate base fee for the next epoch."""
        if slot < SLOTS_PER_EPOCH:
            return BASE_FEE_INITIAL

        recent_slots = list(range(max(0, slot - SLOTS_PER_EPOCH), slot))
        if not recent_slots:
            return self.base_fee

        total_txs = 0
        total_capacity = 0
        for s in recent_slots:
            block = ledger.blocks.get(s)
            if block:
                total_txs += len(block.transactions)
                total_capacity += 1  # simplified: 1 tx per capacity unit

        if total_capacity == 0:
            return self.base_fee

        utilization = total_txs / total_capacity
        if utilization > self.target_utilization:
            # Too full -> increase fee
            increase = min(
                self.base_fee * self.max_change_pct,
                (utilization - self.target_utilization) * self.base_fee,
            )
            self.base_fee += int(increase)
        else:
            # Underused -> decrease fee
            decrease = min(
                self.base_fee * self.max_change_pct,
                (self.target_utilization - utilization) * self.base_fee,
            )
            self.base_fee = max(BASE_FEE_MIN, self.base_fee - int(decrease))

        return self.base_fee
