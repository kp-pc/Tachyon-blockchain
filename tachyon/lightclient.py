"""Light-client balance proofs: verify a balance without trusting the node.

Why this exists
---------------
Before the SMT was actually wired into state, a phone had to *trust* the pool
operator for its balance. Now that state commits through a real Sparse Merkle
Tree, a client can verify a balance against a block header's ``state_root``
using only the header and a small proof -- no node trust required.

How a client verifies
---------------------
1. Obtain a block header (``state_root``) from any source, ideally one already
   accepted by consensus.
2. Ask any node for a balance proof. The node is untrusted: it can lie, but it
   cannot produce a proof that verifies against the header unless the value is
   in the committed state.
3. Recompute the leaf and fold the branch up to a root; accept only if the
   computed root equals the header's ``state_root``.

What is committed
-----------------
State keys are hashed into 256-bit SMT slots, so a verifier must derive the same
slot:

    key  = b"balance:" + address.encode()
    slot = sha256(domain + b"state_slot" + key)
    leaf = sha256(domain + b"smt:leaf" + slot + value)
    node = sha256(domain + b"smt:node" + left + right)

with ``domain = b"tachyon:v1:"``. Values are the balance as a big-endian u64.

The JavaScript verifier embedded in the phone client implements exactly these
four lines; ``tests/test_lightclient.py`` cross-checks it against this module.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .chain import State
from .encoding import digest, u64
from .smt import _hash_leaf, _hash_node, _key_to_path, _EMPTY_LEAF

BALANCE_TAG = "balance"


def balance_key(address: str) -> bytes:
    """Application state key for a miner balance."""
    return BALANCE_TAG.encode() + b":" + address.encode("utf-8")


def balance_slot(address: str) -> bytes:
    """256-bit SMT slot the balance is committed at."""
    return State.slot(balance_key(address))


def encode_balance(amount: int) -> bytes:
    """Commit a balance as a fixed-width big-endian u64."""
    if amount < 0:
        raise ValueError("balance cannot be negative")
    return u64(amount)


def decode_balance(value: Optional[bytes]) -> int:
    return int.from_bytes(value, "big") if value else 0


def proof_to_dict(proof) -> dict:
    """Serialise an SMTProof for the wire. ``value=None`` means exclusion."""
    return {
        "slot": proof.key.hex(),
        "value": proof.value.hex() if proof.value is not None else None,
        "branch": [sibling.hex() for sibling in proof.branch],
    }


def proof_from_dict(data: dict):
    """Parse a wire proof, rejecting anything structurally wrong."""
    if not isinstance(data, dict):
        raise ValueError("proof must be an object")
    slot_hex = data.get("slot")
    if not isinstance(slot_hex, str):
        raise ValueError("proof.slot must be a hex string")
    slot = bytes.fromhex(slot_hex)
    if len(slot) != 32:
        raise ValueError(f"proof.slot must be 32 bytes, got {len(slot)}")

    raw_value = data.get("value")
    if raw_value is None:
        value = None
    elif isinstance(raw_value, str):
        value = bytes.fromhex(raw_value)
    else:
        raise ValueError("proof.value must be a hex string or null")

    raw_branch = data.get("branch")
    if not isinstance(raw_branch, list) or len(raw_branch) != 256:
        raise ValueError("proof.branch must be a list of 256 hex strings")
    branch = []
    for i, item in enumerate(raw_branch):
        if not isinstance(item, str):
            raise ValueError(f"proof.branch[{i}] must be a hex string")
        sibling = bytes.fromhex(item)
        if len(sibling) != 32:
            raise ValueError(f"proof.branch[{i}] must be 32 bytes")
        branch.append(sibling)

    from .smt import SMTProof

    return SMTProof(key=slot, value=value, branch=branch)


def verify_balance_proof(
    address: str,
    proof_data: dict,
    state_root: bytes,
) -> Tuple[bool, str, Optional[int]]:
    """Verify a balance proof against a state root.

    Returns ``(ok, reason, balance)``. On success ``balance`` is the committed
    amount (0 for a valid exclusion proof). The proof is rejected if it is for a
    different address than requested, so a node cannot substitute a proof for a
    richer account.
    """
    try:
        proof = proof_from_dict(proof_data)
    except (ValueError, TypeError) as exc:
        return False, f"malformed proof: {exc}", None

    expected_slot = balance_slot(address)
    if proof.key != expected_slot:
        return False, "proof is for a different state slot", None

    if not proof.verify(state_root):
        return False, "proof does not fold to the given state root", None

    return True, "ok", decode_balance(proof.value)


def latest_state_root(ledger) -> Optional[bytes]:
    """State root of the highest block, which should equal live SMT state."""
    if not ledger.blocks:
        return None
    return ledger.blocks[max(ledger.blocks)].header.state_root


def build_balance_proof(state: State, address: str) -> dict:
    """Produce the wire proof a node would serve for an address."""
    return proof_to_dict(state.prove(balance_key(address)))
