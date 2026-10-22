"""Regression tests for SMT state commitment and pooled-share block assembly.

Run directly (no pytest dependency):

    python tests/test_mobile_chain.py

These cover the two places where the chain previously *claimed* more than it
did: the state root was a plain Merkle root (SMT was dead code), and the mobile
pool incremented a block counter without ever creating a Block. Both are now
real, so both are now tested.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tachyon.chain import GENESIS_SLOT, BlockHeader, Ledger
from tachyon.mobile_chain import BlockAssembler
from tachyon.mobile_pool import MobilePool
from tachyon.mobile_protocol import find_share
from tachyon.smt import EMPTY_ROOT, SparseMerkleTree

PASSED = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ok  {name}")


def _slot(byte: int) -> bytes:
    """A valid 32-byte SMT key."""
    return bytes([0] * 31 + [byte])


def test_smt() -> None:
    print("\n[smt]")

    # The original bug: int.from_bytes maps b"\\x01" and b"\\x00\\x01" to the
    # same index, so a variable-length key silently overwrote another leaf.
    tree = SparseMerkleTree()
    for bad in (b"\x01", b"\x00\x01", b"", b"\x01" * 33):
        try:
            tree.set(bad, b"X")
            check(f"short key {len(bad)} bytes rejected", False)
        except ValueError:
            check(f"short key {len(bad)} bytes rejected", True)

    try:
        tree.set("not-bytes", b"X")
        check("non-bytes key rejected", False)
    except TypeError:
        check("non-bytes key rejected", True)

    # Inclusion and exclusion proofs
    tree.set(_slot(1), b"hello")
    check("inclusion proof verifies", tree.prove(_slot(1), b"hello").verify(tree.root()))
    check("exclusion proof verifies", tree.prove(_slot(2), None).verify(tree.root()))
    check(
        "exclusion proof fails against a foreign root",
        not tree.prove(_slot(2), None).verify(EMPTY_ROOT),
    )

    # Order independence across several keys
    keys = [_slot(i) for i in range(1, 6)]
    a, b = SparseMerkleTree(), SparseMerkleTree()
    for k in keys:
        a.set(k, b"v")
    for k in reversed(keys):
        b.set(k, b"v")
    check("root is insertion-order independent", a.root() == b.root())

    # Update invalidates the stale proof
    before = a.root()
    a.set(_slot(1), b"updated")
    check("update changes the root", a.root() != before)
    check("new value proof verifies", a.prove(_slot(1), b"updated").verify(a.root()))
    check("old root rejects the new proof", not a.prove(_slot(1), b"updated").verify(before))

    # copy() isolation
    clone = a.copy()
    clone.set(_slot(9), b"only-in-clone")
    check("copy diverges from the original", clone.root() != a.root())
    check("prove accepts no value for a missing key", clone.prove(_slot(9), None) is not None)


def test_state_commitment() -> None:
    print("\n[state]")
    from tachyon.chain import State

    # State must commit through the SMT, not a plain Merkle root: a single-key
    # update must not require rebuilding every leaf, and slots must be distinct.
    fresh = State()
    check("empty state root equals SMT EMPTY_ROOT", fresh.root() == EMPTY_ROOT)

    sa, sb = State.slot(b"\x01"), State.slot(b"\x00\x01")
    check("formerly-colliding application keys map to distinct slots", sa != sb)
    check("slots are 32 bytes", len(sa) == 32 and len(sb) == 32)

    mixed = State()
    mixed.set(b"\x01", b"A")
    mixed.set(b"\x00\x01", b"B")
    check("both colliding keys coexist", mixed.get(b"\x01") == b"A" and mixed.get(b"\x00\x01") == b"B")
    check(
        "both colliding keys are provable",
        mixed.prove(b"\x01").verify(mixed.root()) and mixed.prove(b"\x00\x01").verify(mixed.root()),
    )

    one, two = State(), State()
    for k, v in ((b"a", b"1"), (b"b", b"2")):
        one.set(k, v)
    for k, v in ((b"b", b"2"), (b"a", b"1")):
        two.set(k, v)
    check("state root is order independent", one.root() == two.root())

    check("inclusion proof through State", one.prove(b"a").verify(one.root()))
    check("exclusion proof through State", one.prove(b"missing").verify(one.root()))

    copy = one.copy()
    copy.set(b"a", b"changed")
    check("State.copy isolates SMT state", copy.root() != one.root() and one.get(b"a") == b"1")


def test_assembler() -> None:
    print("\n[assembler]")
    asm = BlockAssembler(block_weight_threshold=1000)

    check("genesis block exists", sorted(asm.ledger.blocks) == [GENESIS_SLOT])

    check("sub-threshold credit returns None", asm.credit("phone-1", 500) is None)
    check("sub-threshold credit accumulates", asm.pending_total == 500)

    record = asm.credit("phone-2", 600)
    check("threshold crossing assembles a block", record is not None)
    check("assembled block lands in the ledger", sorted(asm.ledger.blocks) == [0, 1])
    assert record is not None
    block1 = asm.ledger.blocks[1]
    check("block carries one transaction per credited miner", len(block1.transactions) == 2)
    check("block links to genesis via parent_slot", block1.header.parent_slot == 0)
    check("header hash is deterministic", block1.header.hash() == block1.header.hash())
    check(
        "transactions_root commits to the transactions",
        block1.header.transactions_root == block1.compute_transactions_root(),
    )

    check("balances credited to state", asm.balance_of("phone-1") == 500 and asm.balance_of("phone-2") == 600)
    check("header state_root matches live SMT root", block1.header.state_root == asm.ledger.state.root())
    check(
        "balance proofs verify against the block state_root",
        asm.prove_balance("phone-1").verify(block1.header.state_root)
        and asm.prove_balance("phone-2").verify(block1.header.state_root),
    )

    ok, reason = asm.verify_chain()
    check("verify_chain accepts the assembled chain", ok, reason)

    h1 = block1.header.hash()
    record2 = asm.credit("phone-1", 1200)
    check("second block assembles", record2 is not None and record2.slot == 2)
    block2 = asm.ledger.blocks[2]
    check("second block links to the first", block2.header.parent_slot == 1 and block2.header.parent_hash == h1)
    check("balance accumulates across blocks", asm.balance_of("phone-1") == 1700)
    check("latest state_root still matches", block2.header.state_root == asm.ledger.state.root())
    check("verify_chain accepts three blocks", asm.verify_chain()[0])

    # Tamper detection on both fields the header commits to
    tampered = BlockAssembler(block_weight_threshold=1000)
    tampered.credit("m", 1000)
    tampered.credit("m", 1000)
    bad_parent = tampered.ledger.blocks[2]
    bad_parent.header = type(bad_parent.header)(**{**bad_parent.header.__dict__, "parent_hash": bytes(32)})
    ok, reason = tampered.verify_chain()
    check("verify_chain detects a broken parent_hash", not ok and "parent_hash" in reason, reason)

    tampered2 = BlockAssembler(block_weight_threshold=1000)
    tampered2.credit("m", 1000)
    bad_tx = tampered2.ledger.blocks[1]
    bad_tx.header = type(bad_tx.header)(**{**bad_tx.header.__dict__, "transactions_root": bytes(32)})
    ok, reason = tampered2.verify_chain()
    check("verify_chain detects a broken transactions_root", not ok and "transactions_root" in reason, reason)


def test_pool_produces_blocks() -> None:
    print("\n[pool -> chain]")
    asm = BlockAssembler(block_weight_threshold=0)
    pool = MobilePool(target_seconds=0.2, block_weight_threshold=1 << 15, assembler=asm)
    pool.register("arm-phone", 1)

    produced = 0
    for _ in range(4):
        ticket = pool.request_ticket("arm-phone", 1, hashes_per_second=150_000)
        solved = find_share(ticket.seed, ticket.difficulty, max_hashes=30_000_000)
        check("ticket is solvable", solved is not None)
        record = pool.submit_share(ticket.to_dict(), solved[0], elapsed_ms=100)
        check("share is credited", record.credited, record.reason)
        if record.block_hash is not None:
            produced += 1

    check("shares produced real blocks", produced > 0)
    check("assembler holds assembled blocks", len(asm.assembled) == produced)
    check(
        "ledger holds genesis plus assembled blocks",
        sorted(asm.ledger.blocks) == list(range(produced + 1)),
    )
    ok, reason = asm.verify_chain()
    check("pool-produced chain verifies", ok, reason)

    status = pool.status()
    check("status reports real block count", status["real_blocks"] == produced, str(status))
    check("status exposes the last block hash", status["last_block_hash"] is not None)

    # The chain balance must agree with pool credit: no double counting.
    credit = pool.leaderboard()[0]["credit"]
    check("chain balance equals pool credit", asm.balance_of("arm-phone") == credit)

    latest = asm.ledger.blocks[asm.ledger.current_slot]
    check("miner balance is provable against the latest block", asm.prove_balance("arm-phone").verify(latest.header.state_root))


def main() -> int:
    print("=" * 58)
    print("  TACHYON SMT + BLOCK ASSEMBLY TESTS")
    print("=" * 58)
    test_smt()
    test_state_commitment()
    test_assembler()
    test_pool_produces_blocks()
    print("\n" + "=" * 58)
    print(f"  ALL {len(PASSED)} CHECKS PASSED")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
