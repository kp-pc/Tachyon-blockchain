"""Leader election mechanisms for Tachyon validators.

Supports simple Round-Robin and VRF-based election.
Leaders are assigned to slots based on the validator list and epoch stake weights.
"""

from __future__ import annotations

import math
from typing import List, Optional, Tuple

from .crypto import public_key_from_seed, sign, verify


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
            num_slots = max(1, math.ceil((stake / self.total_stake) * 100))
            self.schedule.extend([addr] * num_slots)

    def get_leader(self, slot: int) -> str:
        if not self.schedule:
            return ""
        return self.schedule[slot % len(self.schedule)]


class VRFElection:
    """Verifiable Random Function election using Ed25519.

    Each validator produces a VRF output deterministically from their
    private seed and the slot. The output is provably random and verifiable
    by anyone with the validator's public key.
    """

    def __init__(self, validator_seeds: dict[str, bytes]):
        """
        Args:
            validator_seeds: mapping of validator address -> 32-byte Ed25519 seed
        """
        self._seeds = validator_seeds
        self._public_keys = {
            addr: public_key_from_seed(seed)
            for addr, seed in validator_seeds.items()
        }

    def get_vrf_output(self, validator: str, slot: int) -> bytes:
        """Deterministically derive a VRF output for a validator at a slot."""
        seed = self._seeds.get(validator)
        if seed is None:
            raise ValueError(f"unknown validator: {validator}")
        # Domain-separated VRF: sign the slot with the validator's seed
        return sign(seed, slot.to_bytes(8, "big"))

    def verify_vrf_output(self, validator: str, slot: int, vrf_output: bytes) -> bool:
        """Verify a VRF output against the validator's public key."""
        public_key = self._public_keys.get(validator)
        if public_key is None:
            return False
        return verify(public_key, slot.to_bytes(8, "big"), vrf_output)

    def _vrf_to_index(self, vrf_output: bytes, modulus: int) -> int:
        """Map a VRF output uniformly to [0, modulus)."""
        if modulus <= 0:
            return 0
        return int.from_bytes(vrf_output, "big") % modulus

    def get_leader(self, slot: int, validators: list[str]) -> str:
        """Select a leader for a slot using VRF-based weighted selection.

        Each validator produces a VRF output for the slot. The validator
        whose VRF output maps to the smallest hash value wins.
        """
        if not validators:
            return ""

        best_validator = ""
        best_value = None

        for validator in validators:
            try:
                vrf = self.get_vrf_output(validator, slot)
            except ValueError:
                continue
            value = int.from_bytes(vrf, "big")
            if best_value is None or value < best_value:
                best_value = value
                best_validator = validator

        return best_validator
