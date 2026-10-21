"""Leader election mechanisms for Tachyon validators.

Supports simple Round-Robin and placeholder for VRF-based election.
Leaders are assigned to slots based on the validator list and epoch stake weights.
"""

from __future__ import annotations

from typing import List, Optional, Tuple


class LeaderElection:
    """Assigns a leader to each slot."""

    def __init__(self, validators: List[str]):
        self.validators = sorted(validators)

    def get_leader(self, slot: int) -> str:
        """Get leader for a given slot using round-robin."""
        if not self.validators:
            return ""
        return self.validators[slot % len(self.validators)]


class StakeWeightedElection:
    """Assigns leader based on stake distribution (weighted round-robin)."""

    def __init__(self, validator_stakes: List[Tuple[str, int]]):
        # Sort by address for determinism
        self.stakes = sorted(validator_stakes, key=lambda x: x[0])
        self.total_stake = sum(s for _, s in self.stakes)
        self._build_schedule()

    def _build_schedule(self):
        self.schedule = []
        if self.total_stake == 0:
            return
        # Simple weighted round-robin scheduling
        # In production, this would be a more sophisticated VRF or weighted random
        for addr, stake in self.stakes:
            # Give each validator slots proportional to stake
            num_slots = max(1, int((stake / self.total_stake) * 100))
            self.schedule.extend([addr] * num_slots)

    def get_leader(self, slot: int) -> str:
        if not self.schedule:
            return ""
        return self.schedule[slot % len(self.schedule)]
