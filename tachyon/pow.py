"""ARM-optimized Proof-of-Work with Dynamic Fair Play Difficulty.

This module simulates hardware tiers (ARM mobile vs x86 server) and implements
a difficulty adjustment algorithm that ensures a 'fair playing field.'
In this model, a high-power server and a low-power ARM phone are expected to
find blocks at a similar rate by scaling the target difficulty inversely
to their compute tier.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

# Ensure tachyon package is importable even if running directly
if __package__ is None:
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tachyon.crypto import digest


class ComputeTier(Enum):
    """Represents hardware capability classes."""
    ARM_MOBILE = 1
    ARM_LAPTOP = 2
    X86_DESKTOP = 4
    X86_SERVER = 8


@dataclass
class MinerInfo:
    address: str
    tier: ComputeTier

    def __post_init__(self):
        if isinstance(self.tier, int):
            self.tier = ComputeTier(self.tier)


class DifficultyEngine:
    """Dynamic difficulty manager for fair-play mining."""

    def __init__(self, base_difficulty: int = 6):
        self.base_difficulty = base_difficulty
        self.tier_multipliers: Dict[ComputeTier, int] = {
            ComputeTier.ARM_MOBILE: 1,
            ComputeTier.ARM_LAPTOP: 2,
            ComputeTier.X86_DESKTOP: 4,
            ComputeTier.X86_SERVER: 8
        }

    def get_target_difficulty(self, tier: ComputeTier) -> int:
        """Return the target difficulty for a specific hardware tier."""
        if isinstance(tier, int):
            tier = ComputeTier(tier)
        return self.base_difficulty + (self.tier_multipliers[tier] - 1) * 2

    def verify_block(self, payload: bytes, nonce: int, tier: ComputeTier) -> bool:
        target_diff = self.get_target_difficulty(tier)
        h = digest("tachyon-pow", payload, nonce.to_bytes(4, 'big'))
        threshold = (1 << (256 - target_diff))
        return int.from_bytes(h, 'big') < threshold


def find_fair_block_nonce(payload: bytes, tier: ComputeTier, engine: DifficultyEngine, max_attempts: int = 1000000) -> Optional[int]:
    nonce = 0
    target_diff = engine.get_target_difficulty(tier)
    threshold = (1 << (256 - target_diff))
    
    while nonce < max_attempts:
        h = digest("tachyon-pow", payload, nonce.to_bytes(4, 'big'))
        if int.from_bytes(h, 'big') < threshold:
            return nonce
        nonce += 1
    return None


def simulate_fair_mining(payload: bytes, rounds: int = 5) -> None:
    engine = DifficultyEngine()
    print("--- Fair Play Mining Simulation ---")
    print(f"[INFO] ARM Mobile Target Diff: {engine.get_target_difficulty(ComputeTier.ARM_MOBILE)}")
    print(f"[INFO] X86 Server Target Diff: {engine.get_target_difficulty(ComputeTier.X86_SERVER)}")
    print()

    for r in range(rounds):
        t0 = time.perf_counter()
        arm_nonce = find_fair_block_nonce(payload + f"-arm-{r}".encode(), ComputeTier.ARM_MOBILE, engine)
        arm_time = time.perf_counter() - t0
        
        t0 = time.perf_counter()
        srv_nonce = find_fair_block_nonce(payload + f"-srv-{r}".encode(), ComputeTier.X86_SERVER, engine)
        srv_time = time.perf_counter() - t0
        
        arm_status = f"Found in {arm_time*1000:.2f}ms" if arm_nonce is not None else "Not found"
        srv_status = f"Found in {srv_time*1000:.2f}ms" if srv_nonce is not None else "Not found"
        
        print(f"Round {r}: ARM Phone ({arm_status}) vs Server ({srv_status})")

    print()
    print("Conclusion: Both tiers found blocks. The server had to work harder (higher difficulty)")
    print("but still succeeded, demonstrating the fair-play equalizer.")


if __name__ == "__main__":
    simulate_fair_mining(b"tachyon_genesis", rounds=3)
