"""Append-only ledger storage with persistence."""

from __future__ import annotations

import json
import os
import threading
from typing import Dict, List, Optional, Any

from .chain import Block, BlockHeader, Transaction, Vote
from .encoding import canonical_json, digest


class LedgerStorage:
    """Persists ledger blocks and votes to disk."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._block_file = os.path.join(path, "blocks.ldb")
        self._vote_file = os.path.join(path, "votes.ldb")
        self._state_file = os.path.join(path, "state.json")
        os.makedirs(path, exist_ok=True)

    def append_block(self, block: Block) -> None:
        with self._lock:
            with open(self._block_file, "ab") as f:
                f.write(canonical_json(self._block_to_dict(block)) + b"\n")

    def append_vote(self, vote: Vote) -> None:
        with self._lock:
            with open(self._vote_file, "ab") as f:
                f.write(canonical_json({"voter": vote.voter, "slot": vote.slot, "block_hash": vote.block_hash.hex(), "timestamp": vote.timestamp}) + b"\n")

    @staticmethod
    def _block_to_dict(block: Block) -> Dict[str, Any]:
        return {
            "slot": block.header.slot,
            "parent_slot": block.header.parent_slot,
            "parent_hash": block.header.parent_hash.hex(),
            "transactions_root": block.header.transactions_root.hex(),
            "state_root": block.header.state_root.hex(),
            "base_fee": block.header.base_fee,
            "leader": block.header.leader,
            "timestamp": block.header.timestamp,
            "transactions": [{
                "sender": tx.sender,
                "nonce": tx.nonce,
                "instructions": [[pid, p.hex()] for pid, p in tx.instructions],
                "signature": tx.signature.hex(),
                "slot": tx.slot,
            } for tx in block.transactions],
        }

    def load_all_blocks(self) -> List[Block]:
        if not os.path.exists(self._block_file):
            return []
        blocks = []
        with open(self._block_file, "rb") as f:
            for line in f:
                if line.strip():
                    d = json.loads(line.decode("utf-8"))
                    blocks.append(self._dict_to_block(d))
        return blocks

    @staticmethod
    def _dict_to_block(d: Dict[str, Any]) -> Block:
        header = BlockHeader(
            slot=d["slot"],
            parent_slot=d["parent_slot"],
            parent_hash=bytes.fromhex(d["parent_hash"]),
            transactions_root=bytes.fromhex(d["transactions_root"]),
            state_root=bytes.fromhex(d["state_root"]),
            base_fee=d["base_fee"],
            leader=d["leader"],
            timestamp=d["timestamp"],
        )
        transactions = [
            Transaction(
                sender=t["sender"],
                nonce=t["nonce"],
                instructions=[(i[0], bytes.fromhex(i[1])) for i in t["instructions"]],
                signature=bytes.fromhex(t["signature"]),
                slot=t["slot"],
            )
            for t in d["transactions"]
        ]
        return Block(header=header, transactions=transactions)
