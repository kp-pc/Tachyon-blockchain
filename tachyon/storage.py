"""Append-only ledger storage with persistence and integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
from typing import Dict, List, Optional, Any

from .chain import Block, BlockHeader, Transaction, Vote
from .encoding import canonical_json, digest


class LedgerStorage:
    """Persists ledger blocks and votes to disk with SHA-256 integrity checks."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._block_file = os.path.join(path, "blocks.ldb")
        self._vote_file = os.path.join(path, "votes.ldb")
        self._state_file = os.path.join(path, "state.json")
        os.makedirs(path, exist_ok=True)

    def append_block(self, block: Block) -> None:
        """Write a block to disk with a SHA-256 checksum prefix."""
        with self._lock:
            payload = canonical_json(self._block_to_dict(block))
            checksum = hashlib.sha256(payload).digest()
            # Length-prefix format: [4 bytes checksum length][checksum][payload]
            record = struct.pack('>I', len(checksum)) + checksum + payload + b'\n'
            with open(self._block_file, "ab") as f:
                f.write(record)

    def append_vote(self, vote: Vote) -> None:
        """Write a vote to disk with a SHA-256 checksum prefix."""
        with self._lock:
            payload = canonical_json({
                "voter": vote.voter,
                "slot": vote.slot,
                "block_hash": vote.block_hash.hex(),
                "timestamp": vote.timestamp,
            })
            checksum = hashlib.sha256(payload).digest()
            record = struct.pack('>I', len(checksum)) + checksum + payload + b'\n'
            with open(self._vote_file, "ab") as f:
                f.write(record)

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
        """Load all blocks from disk, skipping corrupted entries with a warning."""
        if not os.path.exists(self._block_file):
            return []
        blocks = []
        with open(self._block_file, "rb") as f:
            while True:
                # Read the 4-byte length prefix for the checksum
                len_bytes = f.read(4)
                if not len_bytes:
                    break  # EOF
                if len(len_bytes) < 4:
                    print(f"WARNING: truncated checksum length prefix at offset {f.tell() - len(len_bytes)}")
                    break

                checksum_len = struct.unpack('>I', len_bytes)[0]
                if checksum_len > 64:  # Sanity check: SHA-256 is 32 bytes
                    print(f"WARNING: implausible checksum length {checksum_len}, skipping rest of file")
                    break

                checksum = f.read(checksum_len)
                if len(checksum) < checksum_len:
                    print(f"WARNING: truncated checksum at offset {f.tell() - len(checksum)}")
                    break

                # Read the rest of the line (JSON payload + newline)
                line = f.readline()
                if not line:
                    print(f"WARNING: truncated payload after checksum at offset {f.tell()}")
                    break

                payload = line.rstrip(b'\n')
                if not payload:
                    continue

                # Verify checksum
                expected = hashlib.sha256(payload).digest()
                if expected != checksum:
                    print(f"WARNING: checksum mismatch at offset {f.tell() - len(line)}, skipping corrupted entry")
                    continue

                try:
                    d = json.loads(payload.decode("utf-8"))
                    blocks.append(self._dict_to_block(d))
                except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError) as exc:
                    print(f"WARNING: failed to parse block entry at offset {f.tell() - len(line)}: {exc}")
                    continue

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
