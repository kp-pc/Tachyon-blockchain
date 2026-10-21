"""Enhanced Multi-node simulation for Tachyon blockchain.

Integrates SMT for state commitments, Round-Robin leader election,
and Mempool with fee prioritization.
"""

from __future__ import annotations

import sys
import os
import time
import json
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tachyon.chain import (
    Ledger, BlockHeader, Block, Transaction, Vote, State,
    BASE_FEE_INITIAL, SLOT_MS, GENESIS_SLOT, GENESIS_TIME_MS
)
from tachyon.crypto import KeyPair
from tachyon.encoding import digest
from tachyon.smt import SparseMerkleTree
from tachyon.election import LeaderElection
from tachyon.mempool import Mempool
from tachyon.feemarket import FeeMarket


def run_enhanced_simulation(duration_blocks: int = 10, num_validators: int = 4) -> dict:
    print(f"--- Starting Enhanced Simulation ({duration_blocks} blocks, {num_validators} validators) ---")
    
    # 1. Setup validators and ledger
    ledger = Ledger()
    validators: List[KeyPair] = [KeyPair.generate() for _ in range(num_validators)]
    for kp in validators:
        ledger.set_stake(kp.address, 1_000_000)

    # 2. Setup modules
    smt = SparseMerkleTree()
    value_store = {}  # Backup for SMT proofs
    election = LeaderElection([kp.address for kp in validators])
    mempool = Mempool()
    fee_market = FeeMarket()

    # 3. Genesis
    leader_kp = validators[0]
    genesis_header = BlockHeader(
        slot=GENESIS_SLOT,
        parent_slot=-1,
        parent_hash=bytes(32),
        transactions_root=digest("empty_tx_root"),
        state_root=smt.root(),
        base_fee=BASE_FEE_INITIAL,
        leader=leader_kp.address,
        timestamp=GENESIS_TIME_MS,
    )
    genesis_block = Block(header=genesis_header, transactions=[])
    ledger.add_block(genesis_block)
    
    for kp in validators:
        ledger.add_vote(Vote(kp.address, GENESIS_SLOT, genesis_header.hash(), GENESIS_TIME_MS))

    # 4. Simulation Loop
    start_time = time.perf_counter()
    tx_count = 0
    
    for slot in range(1, duration_blocks + 1):
        # Get leader for this slot
        leader_addr = election.get_leader(slot)
        leader_kp = next(kp for kp in validators if kp.address == leader_addr)
        
        # Simulate incoming transactions to mempool
        for i in range(5):
            sender = validators[(slot + i) % num_validators]
            tx = Transaction(
                sender=sender.address,
                nonce=slot * 10 + i,
                instructions=[("transfer", f"val-{slot}-{i}".encode())],
                signature=b"", slot=slot
            )
            # Real signature
            tx = Transaction(
                sender=tx.sender, nonce=tx.nonce, instructions=tx.instructions,
                signature=sender.sign(tx.message_bytes()), slot=slot
            )
            mempool.add(tx)
            tx_count += 1

        # Leader fetches from mempool and produces block
        txs = mempool.get_batch(10)
        
        # Execute transactions and update SMT
        batch_updates = {}
        for tx in txs:
            key = digest("balance", tx.sender.encode())
            curr_bal = int.from_bytes(value_store.get(key, b"\x00"), "big")
            new_bal = curr_bal + 100
            val = new_bal.to_bytes(8, "big")
            batch_updates[key] = val
            value_store[key] = val
        
        smt.batch_update(batch_updates, value_store) if hasattr(smt, 'batch_update') else [smt.set(k, v) for k, v in batch_updates.items()]

        parent = ledger.blocks.get(slot - 1)
        header = BlockHeader(
            slot=slot,
            parent_slot=slot - 1,
            parent_hash=parent.header.hash() if parent else bytes(32),
            transactions_root=merkle_root([tx.signature for tx in txs]) if txs else digest("empty_tx_root"),
            state_root=smt.root(),
            base_fee=fee_market.adjust(ledger, slot),
            leader=leader_kp.address,
            timestamp=GENESIS_TIME_MS + (slot * SLOT_MS),
        )
        block = Block(header=header, transactions=txs)
        ledger.add_block(block)

        # Validators vote
        for kp in validators:
            ledger.add_vote(Vote(kp.address, slot, header.hash(), header.timestamp))

    elapsed = time.perf_counter() - start_time
    
    return {
        "blocks": duration_blocks,
        "txs": tx_count,
        "finalized": ledger.finalized_slot,
        "state_root": smt.root().hex()[:16],
        "tps": round(tx_count / elapsed, 2) if elapsed > 0 else 0,
        "bps": round(duration_blocks / elapsed, 2) if elapsed > 0 else 0,
    }

from tachyon.merkle import root as merkle_root

if __name__ == "__main__":
    res = run_enhanced_simulation(20, 4)
    print(json.dumps(res, indent=2))
