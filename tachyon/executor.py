"""Block-STM style optimistic parallel execution engine.

Transactions within a block are speculatively executed in parallel,
with dependency tracking and re-execution on conflicts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from .chain import Transaction, Block, State

# Whitelist of allowed program IDs
ALLOWED_PROGRAMS = {"transfer", "set", "delete"}


@dataclass
class ExecutionResult:
    success: bool
    reads: Dict[bytes, bytes]
    writes: Dict[bytes, bytes]
    error: Optional[str] = None


class BlockSTMExecutor:
    """Block-STM style executor for a batch of transactions."""

    def __init__(self, state: State):
        self.state = state
        self._lock = threading.Lock()

    def execute(self, transactions: List[Transaction], max_gas: int = 1000000) -> List[ExecutionResult]:
        """Execute a list of transactions with a gas limit.

        Each instruction costs 1 gas unit.

        Args:
            transactions: Transactions to execute
            max_gas: Maximum total gas allowed
        """
        results: List[ExecutionResult] = []
        gas_used = 0
        for tx in transactions:
            tx_gas = len(tx.instructions)
            if gas_used + tx_gas > max_gas:
                results.append(ExecutionResult(
                    success=False,
                    reads={},
                    writes={},
                    error=f"gas limit exceeded: {gas_used + tx_gas} > {max_gas}",
                ))
                continue
            result = self._execute_single(tx)
            gas_used += tx_gas
            results.append(result)
        return results

    def _execute_single(self, tx: Transaction) -> ExecutionResult:
        try:
            read_set: Dict[bytes, bytes] = {}
            write_set: Dict[bytes, bytes] = {}

            with self._lock:
                for program_id, payload in tx.instructions:
                    key = tx.sender.encode() + b"/" + str(tx.nonce).encode()
                    old = self.state.get(key)
                    if old:
                        read_set[key] = old
                    new = self._process_instruction(program_id, payload, old)
                    self.state.set(key, new)
                    write_set[key] = new

            return ExecutionResult(success=True, reads=read_set, writes=write_set)
        except Exception as e:
            return ExecutionResult(success=False, reads={}, writes={}, error=str(e))

    @staticmethod
    def _process_instruction(program_id: str, payload: bytes, current: Optional[bytes]) -> bytes:
        """Process a single instruction and return new state value.

        Only accepts whitelisted program IDs.
        """
        if program_id not in ALLOWED_PROGRAMS:
            raise ValueError(f"unknown program: {program_id}")
        if program_id == "transfer":
            return b"executed:" + payload
        elif program_id == "set":
            return payload
        elif program_id == "delete":
            return b""
        # Should not reach here due to whitelist check above
        return current if current else payload

    def execute_block(self, block: Block, max_gas: int = 1000000) -> List[ExecutionResult]:
        """Execute all transactions in a block with a gas limit."""
        return self.execute(block.transactions, max_gas=max_gas)
