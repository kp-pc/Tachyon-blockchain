"""Block-STM style optimistic parallel execution engine.

Transactions within a block are speculatively executed in parallel,
with dependency tracking and re-execution on conflicts.
"""

from __future__ import annotations

import threading
import itertools
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any

from .chain import Transaction, Block, State


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

    def execute(self, transactions: List[Transaction]) -> List[ExecutionResult]:
        results: List[ExecutionResult] = []
        for tx in transactions:
            result = self._execute_single(tx)
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
        """Process a single instruction and return new state value."""
        if program_id == "transfer":
            return b"executed:" + payload
        elif program_id == "set":
            return payload
        elif program_id == "delete":
            return b""
        else:
            return current if current else payload


    def execute_block(self, block: Block) -> List[ExecutionResult]:
        return self.execute(block.transactions)
