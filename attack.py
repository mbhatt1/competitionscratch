# copy into submission.zip
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.attacks.baselines.attacker_goexplore import (
    AttackAlgorithm as BaselineAttackAlgorithm,
)


class AttackAlgorithm(AttackAlgorithmBase):
    """Submission wrapper around the baseline Go-Explore attacker."""

    def __init__(self, config=None):
        super().__init__(config)
        self._baseline = BaselineAttackAlgorithm(config=self.config)

    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        findings = self._baseline.run(env, {"seconds": config.seconds, "steps": config.steps})
        return [
            AttackCandidate(user_messages=tuple(finding.get("user_messages", [])))
            for finding in findings
            if finding.get("user_messages")
        ]
