"""End-to-end multi-validator simulation for Tachyon.

Exercises: Ed25519 keys, SMT state, leader election, mempool, fee market,
stake-weighted BFT finality, chain integrity checks and fair-play PoW tiers.
"""
from __future__ import annotations

import os
import sys
import time
import json

if __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tachyon.chain import (
    Ledger, BlockHeader, Block, Transaction, Vote,
    BASE_FEE_INITIAL, SLOT_MS, GENESIS_SLOT, GENESIS_TIME_MS,
)
from tachyon.crypto import KeyPair
from tachyon.encoding import digest
from tachyon.smt import SparseMerkleTree
from tachyon.election import LeaderElection
from tachyon.mempool import Mempool
from tachyon.feemarket import FeeMarket
from tachyon.mobile import FairPlayEngine
from tachyon.pow import ComputeTier


def simulation(duration_blocks: int = 10, num_validators: int = 4, fair_play_rounds: int = 3) -> dict:
    results = {
        "num_validators": num_validators,
        "duration_blocks": duration_blocks,
        "blocks_produced": 0,
        "blocks_finalized": 0,
        "finalized_slot": -1,
        "state_root": "",
        "fee_history": [BASE_FEE_INITIAL],
        "errors": [],
        "chain_integrity_ok": False,
        "performance": {},
        "fair_play": [],
    }

    ledger = Ledger()
    validators = [KeyPair.generate() for _ in range(num_validators)]
    for kp in validators:
        ledger.set_stake(kp.address, 1_000_000)

    smt = SparseMerkleTree()
    value_store: dict = {}
    election = LeaderElection([kp.address for kp in validators])
    mempool = Mempool()
    fee_market = FeeMarket()

    # Genesis
    genesis_header = BlockHeader(
        slot=GENESIS_SLOT, parent_slot=-1, parent_hash=bytes(32),
        transactions_root=digest("empty_tx_root"), state_root=smt.root(),
        base_fee=BASE_FEE_INITIAL, leader=validators[0].address,
        timestamp=GENESIS_TIME_MS,
    )
    ledger.add_block(Block(header=genesis_header, transactions=[]))
    for kp in validators:
        ledger.add_vote(Vote(kp.address, GENESIS_SLOT, genesis_header.hash(), GENESIS_TIME_MS))

    t_start = time.perf_counter()
    tx_count = 0

    for slot_idx in range(1, duration_blocks + 1):
        slot = GENESIS_SLOT + slot_idx
        leader_addr = election.get_leader(slot)
        leader_kp = next(kp for kp in validators if kp.address == leader_addr)

        for i in range(3):
            sender = validators[(slot_idx + i) % num_validators]
            unsigned = Transaction(
                sender=sender.address, nonce=slot * 10 + i,
                instructions=[("transfer", f"s{slot}-t{i}".encode())],
                signature=b"", slot=slot,
            )
            tx = Transaction(
                sender=unsigned.sender, nonce=unsigned.nonce,
                instructions=unsigned.instructions,
                signature=sender.sign(unsigned.message_bytes()), slot=slot,
            )
            if mempool.add(tx):
                tx_count += 1

        txs = mempool.get_batch(10)

        # Execute into SMT state
        for tx in txs:
            key = digest("balance", tx.sender.encode())
            current = int.from_bytes(value_store.get(key, b"\x00"), "big")
            value = (current + 100).to_bytes(8, "big")
            smt.set(key, value)
            value_store[key] = value

        parent = ledger.blocks.get(slot - 1)
        header = BlockHeader(
            slot=slot, parent_slot=slot - 1,
            parent_hash=parent.header.hash() if parent else bytes(32),
            transactions_root=digest("empty_tx_root"),
            state_root=smt.root(),
            base_fee=fee_market.adjust(ledger, slot),
            leader=leader_kp.address,
            timestamp=GENESIS_TIME_MS + (slot * SLOT_MS),
        )
        ledger.add_block(Block(header=header, transactions=txs))
        for kp in validators:
            ledger.add_vote(Vote(kp.address, slot, header.hash(), header.timestamp))

        results["fee_history"].append(header.base_fee)
        results["blocks_produced"] = slot

    t_elapsed = time.perf_counter() - t_start
    results["performance"] = {
        "total_time_sec": round(t_elapsed, 4),
        "blocks_per_sec": round(duration_blocks / t_elapsed, 2) if t_elapsed > 0 else 0.0,
        "txs_per_sec": round(tx_count / t_elapsed, 2) if t_elapsed > 0 else 0.0,
    }
    results["blocks_finalized"] = ledger.finalized_slot + 1
    results["finalized_slot"] = ledger.finalized_slot
    results["state_root"] = smt.root().hex()

    # Integrity checks
    errors = []
    for slot in sorted(ledger.blocks):
        block = ledger.blocks[slot]
        if slot > GENESIS_SLOT:
            parent_block = ledger.blocks.get(slot - 1)
            if parent_block and block.header.parent_hash != parent_block.header.hash():
                errors.append(f"slot {slot}: parent hash mismatch")
        if block.header.transactions_root != digest("empty_tx_root"):
            errors.append(f"slot {slot}: unexpected tx root")
    if ledger.finalized_slot != duration_blocks:
        errors.append(f"finality mismatch: {ledger.finalized_slot} != {duration_blocks}")

    # Fair-play PoW demo across tiers
    fair_play = FairPlayEngine()
    fair_play.register_miner("arm-phone", ComputeTier.ARM_MOBILE)
    fair_play.register_miner("x86-server", ComputeTier.X86_SERVER)
    for round_idx in range(fair_play_rounds):
        record = {"round": round_idx}
        for label, address in (("arm", "arm-phone"), ("server", "x86-server")):
            payload = f"fair-{round_idx}-{label}".encode()
            t0 = time.perf_counter()
            nonce = fair_play.mine_for_tier(payload, address)
            elapsed = time.perf_counter() - t0
            tier = fair_play.miners[address].tier
            record[label] = {
                "nonce": nonce,
                "ms": round(elapsed * 1000, 3),
                "difficulty": fair_play.difficulty_engine.get_target_difficulty(tier),
            }
            if nonce is None:
                errors.append(f"fair-play {label} failed round {round_idx}")
            else:
                from tachyon.pow import verify_block_nonce
                if not verify_block_nonce(payload, nonce, tier, fair_play.difficulty_engine):
                    errors.append(f"fair-play {label} invalid nonce round {round_idx}")
        results["fair_play"].append(record)

    quorum_votes = ["arm-phone", "x86-server", "arm-phone", "x86-server"]
    results["fair_quorum_ok"] = fair_play.check_quorum(quorum_votes)
    results["fair_quorum_broken_ok"] = fair_play.check_quorum(["x86-server"] * 4)
    if not results["fair_quorum_ok"] or results["fair_quorum_broken_ok"]:
        errors.append("tier quorum enforcement incorrect")

    results["errors"] = errors
    results["chain_integrity_ok"] = not errors
    return results


def run_benchmark() -> None:
    print("=" * 62)
    print("  TACHYON - From-Scratch Blockchain Simulation")
    print("=" * 62)
    for blocks, validators, label in (
        (5, 4, "Small (5 blocks, 4 validators)"),
        (10, 4, "Medium (10 blocks, 4 validators)"),
        (20, 8, "Larger (20 blocks, 8 validators)"),
    ):
        print(f"\n{'-' * 52}\n  {label}\n{'-' * 52}")
        res = simulation(duration_blocks=blocks, num_validators=validators)
        print(f"  Blocks produced  : {res['blocks_produced']}")
        print(f"  Blocks finalized : {res['blocks_finalized']}")
        print(f"  Finalized slot   : {res['finalized_slot']}")
        print(f"  State root       : {res['state_root'][:16]}...")
        print(f"  Fee history      : {res['fee_history'][:5]}")
        print(f"  Fair quorum      : pass={res['fair_quorum_ok']} reject={not res['fair_quorum_broken_ok']}")
        print(f"  Fair-play (ms)   : {[(r['arm']['ms'], r['server']['ms']) for r in res['fair_play']]}")
        print(f"  Throughput       : {res['performance']}")
        print(f"  Integrity        : {'PASS' if res['chain_integrity_ok'] else 'FAIL'}")
        if res["errors"]:
            print(f"  Errors           : {res['errors']}")
    print(f"\n{'=' * 62}\n  Simulation Complete\n{'=' * 62}")


if __name__ == "__main__":
    run_benchmark()
