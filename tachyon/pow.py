"""ARM-optimized Proof-of-Work with Dynamic Fair Play Difficulty.

This module implements a hardware tier system to ensure that small (ARM) and
big (X86) miners have an equal playing field.
"""
from __future__ import annotations
import time
from enum import Enum
from typing import Dict
from .crypto import digest

class ComputeTier(Enum):
    ARM_MOBILE = 1
    ARM_LAPTOP = 2
    X86_DESKTOP = 4
    X86_SERVER = 8

class DifficultyEngine:
    def __init__(self, base_difficulty: int = 8):
        self.base_difficulty = base_difficulty
        # 'Fair Play' factor: higher tiers get higher difficulty so their 
        # speed advantage doesn't result in a 100% win rate in every block.
        self.tier_multipliers: Dict[ComputeTier, int] = {
            ComputeTier.ARM_MOBILE: 1,    # Easiest target
            ComputeTier.ARM_LAPTOP: 2,   
            ComputeTier.X86_DESKTOP: 4,   
            ComputeTier.X86_SERVER: 8     # Hardest target
        }

    def get_target_difficulty(self, tier: ComputeTier) -> int:
        # We add a scaled amount to the base difficulty based on the tier.
        return self.base_difficulty + (self.tier_multipliers[tier] - 1) * 2

    def verify_block(self, payload: bytes, nonce: int, tier: ComputeTier) -> bool:
        target_diff = self.get_target_difficulty(tier)
        h = digest("tachyon-pow", payload, nonce.to_bytes(4, 'big'))
        threshold = (1 << (256 - target_diff))
        return int.from_bytes(h, 'big') < threshold

def find_fair_block_nonce(payload: bytes, tier: ComputeTier, engine: DifficultyEngine) -> int:
    nonce = 0
    target_diff = engine.get_target_difficulty(tier)
    threshold = (1 << (256 - target_diff))
    while True:
        h = digest("tachyon-pow", payload, nonce.to_bytes(4, 'big'))
        if int.from_bytes(h, 'big') < threshold:
            return nonce
        nonce += 1

def simulate_fair_mining(payload: bytes, rounds: int = 5) -> None:
    engine = DifficultyEngine()
    print(f"--- Fair Play Mining Simulation ---")
    print(f"[INFO] ARM Mobile Target: {engine.get_target_difficulty(ComputeTier.ARM_MOBILE)}")
    print(f"[INFO] X86 Server Target: {engine.get_target_difficulty(ComputeTier.X86_SERVER)}")
    print()
    for r in range(rounds):
        t0 = time.perf_counter()
        arm_nonce = find_fair_block_nonce(payload + f"-arm-{r}".encode(), ComputeTier.ARM_MOBILE, engine)
        arm_time = time.perf_counter() - t0
        
        t0 = time.perf_counter()
        srv_nonce = find_fair_block_nonce(payload + f"-srv-{r}".encode(), ComputeTier.X86_SERVER, engine)
        srv_time = time.perf_counter() - t0
        
        print(f"Round {r}: ARM Phone ({arm_time*1000:.2f}ms) vs Server ({srv_time*1000:.2f}ms)")
        
if __name__ == "__main__":
    simulate_fair_mining(b"tachyon_genesis", rounds=3)
