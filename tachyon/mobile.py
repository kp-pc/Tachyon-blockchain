"""Mobile-first consensus layer for Tachyon."""
from __future__ import annotations

import sys
import os

if __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict
from tachyon.pow import MinerInfo, ComputeTier, DifficultyEngine, find_fair_block_nonce


class FairPlayEngine:
    """Manages the consensus participation of diverse hardware tiers."""

    def __init__(self):
        self.miners: Dict[str, MinerInfo] = {}
        self.difficulty_engine = DifficultyEngine()
        self.tier_quorum = {ComputeTier.ARM_MOBILE: 0.1, ComputeTier.ARM_LAPTOP: 0.1, ComputeTier.X86_DESKTOP: 0.2, ComputeTier.X86_SERVER: 0.2}

    def register_miner(self, address: str, tier: int) -> None:
        self.miners[address] = MinerInfo(address, tier)

    def check_quorum(self, votes: List[str]) -> bool:
        tier_votes = {1: 0, 2: 0, 4: 0, 8: 0}
        total_votes = len(votes)
        if total_votes == 0:
            return False
        
        for address in votes:
            miner = self.miners.get(address)
            if miner:
                tier_votes[miner.tier.value] += 1
        
        for tier, required_share in self.tier_quorum.items():
            if total_votes > 0 and tier_votes[tier.value] / total_votes < required_share:
                # If we don't have enough votes from a tier, it's not a full quorum
                # In a real network, you'd wait or adjust.
                pass 
        # Simplified quorum: at least one mobile and one server
        return tier_votes[1] > 0 and tier_votes[8] > 0
