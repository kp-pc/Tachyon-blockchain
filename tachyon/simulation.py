"""Enhanced Multi-node simulation for Tachyon blockchain."""
from __future__ import annotations
import sys, os, time, json
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tachyon.chain import Ledger, BlockHeader, Block, Transaction, Vote, BASE_FEE_INITIAL, SLOT_MS, GENESIS_SLOT, GENESIS_TIME_MS
from tachyon.crypto import KeyPair
from tachyon.encoding import digest
from tachyon.smt import SparseMerkleTree
from tachyon.election import LeaderElection
from tachyon.mempool import Mempool
from tachyon.feemarket import FeeMarket
from tachyon.mobile import FairPlayEngine
from tachyon.pow import ComputeTier, find_block_nonce


def simulation(duration_blocks: int = 10, num_validators: int = 4) -> dict:
    """Run a Tachyon blockchain simulation and return results."""
    results = {
        "num_validators": num_validators,
        "duration_blocks": duration_blocks,
        "blocks_produced": 0,
        "blocks_finalized": 0,
        "finalized_slot": -1,
        "state_root": "",
        "fee_history": [BASE_FEE_INITIAL],
        "validation_errors": [],
        "performance": {},
        "mobile_miner_success": False,
        "mobile_mining_time": None
    }

    # Setup
    ledger = Ledger()
    validators = [KeyPair.generate() for _ in range(num_validators)]
    for kp in validators:
        ledger.set_stake(kp.address, 1_000_000)

    smt = SparseMerkleTree()
    value_store = {}
    election = LeaderElection([kp.address for kp in validators])
    mempool = Mempool()
    fee_market = FeeMarket()
    fair_play = FairPlayEngine()

    # Register mobile and server participants
    fair_play.register("mobile-user", ComputeTier.MOBILE_ARM)
    fair_play.register("server-node", ComputeTier.SERVER)

    # Genesis
    leader_kp = validators[0]
    genesis_header = BlockHeader(
        slot=GENESIS_SLOT, parent_slot=-1, parent_hash=bytes(32),
        transactions_root=digest("empty_tx_root"),
        state_root=smt.root(), base_fee=BASE_FEE_INITIAL,
        leader=leader_kp.address, timestamp=GENESIS_TIME_MS)
    genesis_block = Block(header=genesis_header, transactions=[])
    ledger.add_block(genesis_block)

    # Vote on genesis
    for kp in validators:
        ledger.add_vote(Vote(kp.address, GENESIS_SLOT, genesis_header.hash(), GENESIS_TIME_MS))

    # Block production
    t_start = time.perf_counter()
    tx_count = 0

    for slot_idx in range(1, duration_blocks + 1):
        slot = GENESIS_SLOT + slot_idx
        leader_addr = election.get_leader(slot)
        leader_kp = next(kp for kp in validators if kp.address == leader_addr)

        # Add transactions to mempool
        for i in range(3):
            sender = validators[(slot_idx + i) % num_validators]
            tx_msg = Transaction(sender=sender.address, nonce=slot*10+i,
                                 instructions=[("transfer", b"data")], signature=b"", slot=slot)
            tx = Transaction(sender=tx_msg.sender, nonce=tx_msg.nonce,
                             instructions=tx_msg.instructions,
                             signature=sender.sign(tx_msg.message_bytes()), slot=slot)
            mempool.add(tx)
            tx_count += 1

        # Fetch batch
        txs = mempool.get_batch(10)

        # Execute & update SMT
        batch_updates = {}
        for tx in txs:
            key = digest("balance", tx.sender.encode())
            curr = int.from_bytes(value_store.get(key, b"\x00"), "big")
            val = (curr + 100).to_bytes(8, "big")
            batch_updates[key] = val
            value_store[key] = val
        for k, v in batch_updates.items():
            smt.set(k, v)

        parent = ledger.blocks.get(slot - 1)
        header = BlockHeader(
            slot=slot, parent_slot=slot - 1,
            parent_hash=parent.header.hash() if parent else bytes(32),
            transactions_root=digest("empty_tx_root"),
            state_root=smt.root(), base_fee=fee_market.adjust(ledger, slot),
            leader=leader_kp.address, timestamp=GENESIS_TIME_MS + (slot * SLOT_MS))
        block = Block(header=header, transactions=txs)
        ledger.add_block(block)

        for kp in validators:
            ledger.add_vote(Vote(kp.address, slot, header.hash(), header.timestamp))

        results["fee_history"].append(header.base_fee)
        results["blocks_produced"] = slot

    # Mobile mining test
    print(f"Running mobile block discovery (PoW-Lite)...")
    t_mobile_start = time.perf_counter()
    try:
        mobile_nonce = fair_play.mine_for_mobile(b"mobile-test", "mobile-user")
        mobile_time = time.perf_counter() - t_mobile_start
        results["mobile_miner_success"] = True
        results["mobile_mining_time"] = mobile_time
        print(f"Mobile miner found block in {mobile_time:.2f}s")
    except ValueError:
        results["mobile_miner_success"] = False
        print("Mobile mining failed or timed out")

    # Results
    t_elapsed = time.perf_counter() - t_start
    results["performance"] = {
        "total_time_sec": round(t_elapsed, 4),
        "blocks_per_sec": round(duration_blocks / t_elapsed, 2) if t_elapsed > 0 else 0,
        "txs_per_sec": round(tx_count / t_elapsed, 2) if t_elapsed > 0 else 0,
    }
    results["blocks_finalized"] = ledger.finalized_slot + 1
    results["finalized_slot"] = ledger.finalized_slot
    results["state_root"] = smt.root().hex()[:16]
    results["total_blocks_in_ledger"] = len(ledger.blocks)
    results["total_votes_cast"] = sum(len(v) for v in ledger.votes.values())

    # Integrity check
    errors = []
    for slot in sorted(ledger.blocks.keys()):
        block = ledger.blocks[slot]
        if slot > GENESIS_SLOT:
            parent_block = ledger.blocks.get(slot - 1)
            if parent_block and block.header.parent_hash != parent_block.header.hash():
                errors.append(f"Slot {slot}: parent hash mismatch")
    results["errors"] = errors
    results["chain_integrity_ok"] = len(errors) == 0

    return results


def run_benchmark() -> None:
    """Run the simulation with different sizes and report results."""
    print("=" * 60)
    print("  TACHYON - From-Scratch Blockchain Simulation")
    print("=" * 60)

    configs = [
        (5, 4, "Small (5 blocks, 4 validators)"),
        (10, 4, "Medium (10 blocks, 4 validators)"),
        (20, 8, "Larger (20 blocks, 8 validators)"),
    ]

    for blocks, validators, label in configs:
        print(f"\n{'─' * 50}")
        print(f"  Test: {label}")
        print(f"{'─' * 50}")

        res = simulation(duration_blocks=blocks, num_validators=validators)

        print(f"  Blocks produced : {res['blocks_produced']}")
        print(f"  Blocks finalized : {res['blocks_finalized']}")
        print(f"  Finalized slot   : {res['finalized_slot']}")
        print(f"  Chain integrity  : {'✓' if res['chain_integrity_ok'] else '✗ FAIL'}")
        print(f"  Mobile mining    : {'✓' if res['mobile_miner_success'] else '✗'} (took {res['mobile_mining_time']:.2f}s)" if res['mobile_miner_success'] else "  Mobile mining    : ✗ Failed")
        print(f"  Performance      : {res['performance']}")
        print(f"  Errors           : {res['errors']}")

        if res["errors"]:
            print("  ❌ INTEGRITY ERRORS DETECTED!")
        else:
            print("  ✅ All checks passed")

    print(f"\n{'=' * 60}")
    print("  Simulation Complete")
    print("=" * 60)


if __name__ == "__main__":
    run_benchmark()
