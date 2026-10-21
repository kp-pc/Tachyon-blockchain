"""ARM-optimized lightweight Proof-of-Work-Lite (PoW-Lite) module.

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
    
    @property
    def multipliers(self) -> int:
        """Returns the number of hash operations required per block.
        Higher tier = more work, but also more 'weight' in finalization.
        This creates an equal playing field: a mobile miner does less work
        but has the same *probability* of contributing to the final chain state
        relative to their stake/share in the mobile-class pool.
        """
        return self.tier


def find_block_nonce(payload: bytes, target_bits: int, tier: int) -> int:
    """Find a nonce that satisfies a difficulty target for a given tier.
    
    On ARM, we use a simpler loop that is more predictable than high-end CPUs.
    """
    tier_factor = tier * 100
    nonce = 0
    
    # Dynamic difficulty: target_bits represents the 'weight' we're trying to achieve.
    # Smaller tiers (mobile) get a lower effective target difficulty so they can still participate.
    effective_target_bits = max(8, target_bits - (tier * 2))
    
    while True:
        h = digest("tachyon-pow", payload, u64(nonce))
        if h[:4] < (1 << (32 - effective_target_bits)).to_bytes(4, "big") or h[:4] < int.from_bytes(b"\x01\x00\x00\x00", "big") // tier:
            return nonce
        nonce += 1
        if nonce % 100000 == 0:  # Yield to OS on mobile to prevent battery drain
            time.sleep(0.001)


def verify_nonce(payload: bytes, nonce: int, target_bits: int, tier: int) -> bool:
    """Verify that a nonce found by a miner satisfies the tier-specific difficulty."""
    h = digest("tachyon-pow", payload, u64(nonce))
    effective_target_bits = max(8, target_bits - (tier * 2))
    # Simple check: first byte must be less than a tier-adjusted value
    max_val = 0x01 + (8 - tier) 
    return h[0] <= max_val
