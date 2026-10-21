"""Binary Merkle trees with inclusion proofs.

Leaves are domain separated from internal nodes, and the tree is padded to a
power of two using a fixed empty-leaf constant. The published root also binds
the number of leaves, so trees of different sizes can never collide.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .encoding import digest, sha256, u64

_EMPTY_LEAF = digest("merkle:leaf", b"")
_ROOT_TAG = "merkle:root"


def leaf_hash(data: bytes) -> bytes:
    return digest("merkle:leaf", data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return digest("merkle:node", left, right)


def _layers(leaves: Sequence[bytes]):
    if not leaves:
        raise ValueError("merkle tree requires at least one leaf")
    size = 1 << (len(leaves) - 1).bit_length()
    layer = [leaf_hash(item) for item in leaves]
    layer.extend([_EMPTY_LEAF] * (size - len(layer)))
    layers = [layer]
    while len(layer) > 1:
        layer = [
            _node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)
        ]
        layers.append(layer)
    return layers


def root(leaves: Iterable[bytes]) -> bytes:
    items = list(leaves)
    if not items:
        return digest("merkle:empty")
    top = _layers(items)[-1][0]
    return digest(_ROOT_TAG, u64(len(items)), top)


def proof(leaves: Sequence[bytes], index: int) -> dict:
    items = list(leaves)
    if not 0 <= index < len(items):
        raise IndexError("leaf index out of range")
    layers = _layers(items)
    path = []
    idx = index
    for layer in layers[:-1]:
        sibling = idx ^ 1
        path.append(["right" if idx % 2 == 0 else "left", layer[sibling].hex()])
        idx //= 2
    return {
        "index": index,
        "num_leaves": len(items),
        "leaf": items[index].hex(),
        "path": path,
    }


def verify_proof(expected_root: bytes, item: bytes, inclusion: dict) -> bool:
    try:
        index = int(inclusion["index"])
        num_leaves = int(inclusion["num_leaves"])
        path = inclusion["path"]
        if not 0 <= index < num_leaves or num_leaves < 1:
            return False
        if bytes.fromhex(inclusion["leaf"]) != item:
            return False
        current = leaf_hash(item)
        for side, sibling_hex in path:
            sibling = bytes.fromhex(sibling_hex)
            if side == "right":
                current = _node_hash(current, sibling)
            elif side == "left":
                current = _node_hash(sibling, current)
            else:
                return False
        return digest(_ROOT_TAG, u64(num_leaves), current) == expected_root
    except (KeyError, TypeError, ValueError):
        return False
