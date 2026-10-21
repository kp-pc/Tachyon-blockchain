"""Mobile-first consensus layer for Tachyon.

Fair-play rule: if a hardware tier has at least one registered miner, that tier
must contribute at least its configured share of votes before quorum is granted.
Tiers with no registered miners are skipped so small test networks still work.
"""
from __future__ import annotations

import sys
import os

if __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from tachyon.pow import ComputeTier, DifficultyEngine, MinerInfo


DEFAULT_TIER_QUORUM: Dict[ComputeTier, float] = {
    ComputeTier.ARM_MOBILE: 0.10,
    ComputeTier.ARM_LAPTOP: 0.10,
    ComputeTier.X86_DESKTOP: 0.10,
    ComputeTier.X86_SERVER: 0.10,
}


class FairPlayEngine:
    """Tracks miner hardware tiers and enforces tier-balanced quorum."""

    def __init__(self, tier_quorum: Dict[ComputeTier, float] | None = None):
        self.miners: Dict[str, MinerInfo] = {}
        self.difficulty_engine = DifficultyEngine()
        self.tier_quorum = dict(tier_quorum or DEFAULT_TIER_QUORUM)

    def register_miner(self, address: str, tier: int | ComputeTier) -> None:
        self.miners[address] = MinerInfo(address=address, tier=tier)

    # Backwards compatible alias
    register = register_miner

    def miners_by_tier(self) -> Dict[ComputeTier, List[str]]:
        groups: Dict[ComputeTier, List[str]] = {t: [] for t in ComputeTier}
        for address, info in self.miners.items():
            groups[info.tier].append(address)
        return groups

    def check_quorum(self, votes: List[str]) -> bool:
        total = len(votes)
        if total == 0:
            return False

        groups = self.miners_by_tier()
        counts: Dict[ComputeTier, int] = {t: 0 for t in ComputeTier}
        valid = 0
        for address in votes:
            info = self.miners.get(address)
            if info is None:
                continue
            counts[info.tier] += 1
            valid += 1

        if valid == 0:
            return False

        for tier, required in self.tier_quorum.items():
            if not groups[tier]:
                continue  # no miners in this tier -> cannot require its share
            if counts[tier] / valid < required:
                return False
        return True

    def mine_for_tier(self, payload: bytes, address: str, max_attempts: int = 2_000_000):
        info = self.miners.get(address)
        tier = info.tier if info else ComputeTier.ARM_MOBILE
        from tachyon.pow import find_fair_block_nonce
        return find_fair_block_nonce(payload, tier, self.difficulty_engine, max_attempts)
