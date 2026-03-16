# copy into submission.zip
from collections.abc import Mapping
from typing import Any, Optional

from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.attacks.baselines.attacker_goexplore import (
    AttackAlgorithm as BaselineAttackAlgorithm,
)


class AttackAlgorithm(AttackAlgorithmBase):
    """Submission wrapper around the baseline Go-Explore attacker."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(config)
        self._baseline = BaselineAttackAlgorithm(config=self.config)

    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        return self._baseline.run(env, config)
