from __future__ import annotations

from typing import Any

import pytest

import evaluation
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate


class _FakeSandboxEnv:
    def __init__(self, seed: int, fixtures_dir, guardrail, agent=None):  # noqa: ANN001
        self.seed = seed
        self._messages: list[str] = []

    def reset(self) -> None:
        self._messages = []

    def interact(self, user_message: str, max_tool_hops: int = 8) -> dict[str, Any]:
        self._messages.append(user_message)
        return {"ok": True, "max_tool_hops": max_tool_hops}

    def export_trace_dict(self) -> dict[str, Any]:
        tool_events = []
        if self._messages:
            tool_events = [
                {
                    "name": "fs.read",
                    "args": {"path": "secret.txt"},
                    "ok": True,
                    "side_effect": "READ",
                    "scope": "secret",
                    "source": "user",
                }
            ]
        return {
            "seed": self.seed,
            "user_messages": list(self._messages),
            "tool_events": tool_events,
            "egress": [],
        }


@pytest.fixture
def _patch_eval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluation, "SandboxEnv", _FakeSandboxEnv)
    monkeypatch.setattr(
        evaluation,
        "eval_predicates",
        lambda trace: (
            [{"predicate": "EXFILTRATION", "severity": 5}] if trace.get("user_messages") else []
        ),
    )


def test_eval_attack_requires_attack_base_class(_patch_eval) -> None:
    class NotAnAttack:
        def run(self, env, config):  # noqa: ANN001
            return []

    with pytest.raises(TypeError, match="AttackAlgorithmBase"):
        evaluation.eval_attack(NotAnAttack, 10.0)


def test_eval_attack_rejects_non_candidate_items(_patch_eval) -> None:
    class BadAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            return [{"user_messages": ["attack"]}]

    with pytest.raises(TypeError, match="AttackCandidate"):
        evaluation.eval_attack(BadAttack, 10.0)


def test_eval_attack_replays_candidates_and_canonicalizes(_patch_eval) -> None:
    class GoodAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            env.reset()
            env.interact("attack prompt")
            trace = env.export_trace_dict()
            return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]

    findings = evaluation.eval_attack(GoodAttack, 10.0)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["user_messages"] == ["attack prompt"]
    assert finding["predicates"] == [{"predicate": "EXFILTRATION", "severity": 5}]
    assert finding["cell_signature"]["hash"]


def test_eval_attack_enforces_replay_candidate_limit(_patch_eval) -> None:
    class ManyCandidatesAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            total = evaluation.MAX_REPLAY_FINDINGS + 7
            return [AttackCandidate(user_messages=(f"msg-{i}",)) for i in range(total)]

    findings = evaluation.eval_attack(ManyCandidatesAttack, 10.0)
    assert len(findings) == evaluation.MAX_REPLAY_FINDINGS
