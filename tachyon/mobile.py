"""Mobile-first consensus layer for Tachyon.

Implements 'Fair Play' by separating the attestation duty into tiers.
"""
from __future__ import annotations

from typing import List, Dict
from .pow import MinerInfo, ComputeTier


class FairPlayEngine:
    """Manages the consensus participation of diverse hardware tiers."""

    def __init__(self):
        self.miners: Dict[str, MinerInfo] = {}
        self.tier_quorum = {ComputeTier.MOBILE_ARM: 0.2, ComputeTier.LAPTOP_X86: 0.3, ComputeTier.DESKTOP_X86: 0.3, ComputeTier.SERVER: 0.2}

    def register_miner(self, address: str, tier: int) -> None:
        self.miners[address] = MinerInfo(address, tier)

    def check_quorum(self, votes: List[str]) -> bool:
        """Check if a set of votes reaches a fair-play quorum.
        
        A quorum is achieved when each tier has contributed its 'share' of the 
        total work as defined in self.tier_quorum.
        """
        tier_votes = {1: 0, 2: 0, 4: 0, 8: 0}
        total_votes = len(votes)
        if total_votes == 0:
            return False
        
        for address in votes:
            miner = self.miners.get(address)
            if miner:
                tier_votes[miner.tier] += 1
        
        for tier, required_share in self.tier_quorum.items():
            if tier_votes[tier] / total_votes < required_share:
                return False
        return True
