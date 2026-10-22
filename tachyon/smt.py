"""Sparse Merkle Tree (SMT) with compact inclusion/exclusion proofs."""
from __future__ import annotations
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from .encoding import digest
from .crypto import digest as crypto_digest

SMT_LEAF_TAG = "smt:leaf"
SMT_NODE_TAG = "smt:node"
_EMPTY_LEAF = digest(SMT_LEAF_TAG, b"")
_EMPTY_HASHES = [_EMPTY_LEAF]
for _ in range(256):
    _EMPTY_HASHES.append(digest(SMT_NODE_TAG, _EMPTY_HASHES[-1], _EMPTY_HASHES[-1]))
EMPTY_ROOT = _EMPTY_HASHES[256]

def _validate_key(key: bytes) -> None:
    """SMT keys are fixed 256-bit slots.

    Variable-length keys are rejected rather than coerced: ``int.from_bytes``
    maps b"\x01" and b"\x00\x01" to the same index 1, so accepting mixed
    lengths would let one insert silently overwrite another key's leaf.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"SMT key must be bytes, got {type(key).__name__}")
    if len(key) != 32:
        raise ValueError(f"SMT key must be exactly 32 bytes, got {len(key)}")

def _key_to_path(key: bytes) -> List[int]:
    path = []
    for byte in key:
        for bit in range(7, -1, -1):
            path.append((byte >> bit) & 1)
    return path

def _hash_leaf(key: bytes, value: bytes) -> bytes:
    return digest(SMT_LEAF_TAG, key, value)

def _hash_node(left: bytes, right: bytes) -> bytes:
    return digest(SMT_NODE_TAG, left, right)

@dataclass(frozen=True)
class SMTProof:
    key: bytes
    value: Optional[bytes]
    branch: List[bytes]
    def verify(self, root: bytes) -> bool:
        if self.value is None: current = _EMPTY_LEAF
        else: current = _hash_leaf(self.key, self.value)
        path = _key_to_path(self.key)
        for sibling, bit in zip(self.branch, reversed(path)):
            if bit == 0: current = _hash_node(current, sibling)
            else: current = _hash_node(sibling, current)
        return current == root

class SparseMerkleTree:
    def __init__(self):
        self._nodes: Dict[Tuple[int, int], bytes] = {}
        self._lock = threading.RLock()
        self._root = EMPTY_ROOT

    def root(self) -> bytes:
        with self._lock: return self._root

    def set(self, key: bytes, value: bytes) -> None:
        _validate_key(key)
        with self._lock:
            idx = int.from_bytes(key, "big")
            leaf_hash = _hash_leaf(key, value) if value else _EMPTY_LEAF
            self._nodes[(0, idx)] = leaf_hash
            curr_idx = idx
            curr_hash = leaf_hash
            for level in range(1, 257):
                sibling_idx = curr_idx ^ 1
                sibling_hash = self._nodes.get((level-1, sibling_idx), _EMPTY_HASHES[level-1])
                if curr_idx % 2 == 0: curr_hash = _hash_node(curr_hash, sibling_hash)
                else: curr_hash = _hash_node(sibling_hash, curr_hash)
                curr_idx //= 2
                self._nodes[(level, curr_idx)] = curr_hash
            self._root = curr_hash

    def copy(self) -> "SparseMerkleTree":
        with self._lock:
            clone = SparseMerkleTree()
            clone._nodes = dict(self._nodes)
            clone._root = self._root
            return clone

    def prove(self, key: bytes, value: Optional[bytes]) -> SMTProof:
        _validate_key(key)
        with self._lock:
            idx = int.from_bytes(key, "big")
            branch = []
            curr_idx = idx
            for level in range(0, 256):
                sibling_idx = curr_idx ^ 1
                branch.append(self._nodes.get((level, sibling_idx), _EMPTY_HASHES[level]))
                curr_idx //= 2
            return SMTProof(key, value, branch)
