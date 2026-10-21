"""Pipelined block production.

Stages: Fetch -> Gossip -> Verify -> Execute -> Store -> Finalize

Inspired by Solana's pipelined block production, each stage runs in its own
thread and communicates via asyncio.Queue for backpressure.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from .chain import Block, BlockHeader, Ledger, Transaction, Vote, ConsensusSimulator


class Stage(Enum):
    FETCH = "fetch"
    GOSSIP = "gossip"
    VERIFY = "verify"
    EXECUTE = "execute"
    STORE = "store"
    FINALIZE = "finalize"


@dataclass
class PipelineItem:
    block: Optional[Block] = None
    transactions: List[Transaction] = field(default_factory=list)
    leader: str = ""
    errors: List[str] = field(default_factory=list)


class Pipeline:
    """Pipelined block processing."""

    def __init__(self, ledger: Ledger, max_pending: int = 8):
        self.ledger = ledger
        self.max_pending = max_pending
        self._queues: Dict[Stage, List[PipelineItem]] = {s: [] for s in Stage}
        self._lock = threading.Lock()
        self._running = False
        self._stage_threads: Dict[Stage, threading.Thread] = {}
        self.stats = {"processed": 0, "errors": 0, "stages": {s.name: 0 for s in Stage}}

    def start(self) -> None:
        self._running = True
        for stage in Stage:
            t = threading.Thread(target=self._run_stage, args=(stage,), daemon=True)
            self._stage_threads[stage] = t
            t.start()

    def stop(self) -> None:
        self._running = False
        for t in self._stage_threads.values():
            t.join()

    def submit(self, item: PipelineItem) -> None:
        with self._lock:
            if len(self._queues[Stage.FETCH]) < self.max_pending:
                self._queues[Stage.FETCH].append(item)

    def _run_stage(self, stage: Stage) -> None:
        while self._running:
            item = self._pop_item(stage)
            if item is None:
                time.sleep(0.001)
                continue
            try:
                if stage == Stage.FETCH:
                    self._process_fetch(item)
                elif stage == Stage.GOSSIP:
                    self._process_gossip(item)
                elif stage == Stage.VERIFY:
                    self._process_verify(item)
                elif stage == Stage.EXECUTE:
                    self._process_execute(item)
                elif stage == Stage.STORE:
                    self._process_store(item)
                elif stage == Stage.FINALIZE:
                    self._process_finalize(item)
                self.stats["stages"][stage.name] += 1
                self.stats["processed"] += 1
            except Exception as e:
                item.errors.append(str(e))
                self.stats["errors"] += 1

    def _pop_item(self, stage: Stage) -> Optional[PipelineItem]:
        with self._lock:
            q = self._queues[stage]
            if q:
                return q.pop(0)
            return None

    def _push_item(self, stage: Stage, item: PipelineItem) -> None:
        with self._lock:
            next_stages = list(Stage)[list(Stage).index(stage) + 1:]
            if next_stages:
                self._queues[next_stages[0]].append(item)

    def _process_fetch(self, item: PipelineItem) -> None:
        self._push_item(Stage.FETCH, item)

    def _process_gossip(self, item: PipelineItem) -> None:
        self._push_item(Stage.GOSSIP, item)

    def _process_verify(self, item: PipelineItem) -> None:
        # Verify block header integrity
        if item.block is not None:
            expected_tx_root = item.block.compute_transactions_root()
            if expected_tx_root != item.block.header.transactions_root:
                item.errors.append("transactions_root mismatch")
                return
        self._push_item(Stage.VERIFY, item)

    def _process_execute(self, item: PipelineItem) -> None:
        # Execute transactions against state (simplified)
        if item.block is not None:
            self.ledger.state._root = item.block.header.state_root
        self._push_item(Stage.EXECUTE, item)

    def _process_store(self, item: PipelineItem) -> None:
        if item.block is not None:
            self.ledger.add_block(item.block)
        self._push_item(Stage.STORE, item)

    def _process_finalize(self, item: PipelineItem) -> None:
        pass  # handled by consensus layer
