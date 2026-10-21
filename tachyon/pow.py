"""ARM-optimized lightweight Proof-of-Work-Lite (PoW-Lite).

Designed for mobile (ARM) participation, this module uses a simple, low-overhead
hashing loop that doesn't require specialized CPU instructions (like SHA-NI).
It scales difficulty based on the participant's 'Compute Tier'.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .crypto import digest
from .encoding import u64


class ComputeTier:
    """Represents hardware capability tiers for fair difficulty scaling."""
    MOBILE_ARM = 1
    LAPTOP_X86 = 2
    DESKTOP_X86 = 4
    SERVER = 8


@dataclass
class MinerInfo:
    address: str
    tier: int  # 1, 2, 4, or 8


def find_block_nonce(payload: bytes, target_bits: int, tier: int) -> int:
    """Find a nonce that satisfies a difficulty target for a given tier.

    On ARM, we use a simpler loop that is more predictable than high-end CPUs.
    Dynamic difficulty: target_bits represents the 'weight' we're trying to achieve.
    Smaller tiers (mobile) get a lower effective target difficulty so they can still participate.
    """
    # For mobile, we artificially lower the target difficulty to ensure participation
    effective_target_bits = max(8, target_bits - (tier * 2))
    target_value = 0x000000FF if tier == ComputeTier.MOBILE_ARM else (1 << (32 - effective_target_bits))
    
    nonce = 0
    start_time = time.perf_counter()
    
    while True:
        h = digest("tachyon-pow", payload, u64(nonce))
        
        # For mobile, we check if the first byte is below a threshold
        # For higher tiers, we check the bit-depth target
        if tier == ComputeTier.MOBILE_ARM:
            # Mobile friendly: just need a specific hash prefix (easy)
            if h[0] < 0x40:  # ~1/256 probability, very fast
                return nonce
        else:
            if int.from_bytes(h[:4], "big") < target_value:
                return nonce
        
        # Yield to OS on mobile to prevent battery drain
        if nonce % 100000 == 0: 
            if tier == ComputeTier.MOBILE_ARM:
                time.sleep(0.001)
            
            # Prevent infinite loop in simulation
            if time.perf_counter() - start_time > 5.0:
                break
        nonce += 1
    
    raise ValueError("PoW target too high or timeout reached")


def verify_nonce(payload: bytes, nonce: int, target_bits: int, tier: int) -> bool:
    """Verify that a nonce found by a miner satisfies the tier-specific difficulty."""
    h = digest("tachyon-pow", payload, u64(nonce))
    if tier == ComputeTier.MOBILE_ARM:
        return h[0] < 0x40
    
    effective_target_bits = max(8, target_bits - (tier * 2))
    target_value = (1 << (32 - effective_target_bits))
    return int.from_bytes(h[:4], "big") < target_value
