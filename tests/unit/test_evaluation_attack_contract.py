from __future__ import annotations

from typing import Any

import pytest

from aicomp_sdk.agents import build_agent_factory
from aicomp_sdk import evaluation_core
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env_api import MAX_USER_MESSAGE_CHARS


class _FakeSandboxEnv:
    def __init__(  # noqa: ANN001
        self,
        seed: int,
        fixtures_dir,
        guardrail,
        agent=None,
    ):
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
    monkeypatch.setattr(
        evaluation_core,
        "build_attack_env",
        lambda **kwargs: _FakeSandboxEnv(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
        ),
    )
    monkeypatch.setattr(
        evaluation_core,
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
        evaluation_core.eval_attack(
            NotAnAttack,
            10.0,
            build_agent_factory("deterministic"),
            env_selection="sandbox",
        )


def test_eval_attack_rejects_non_candidate_items(_patch_eval) -> None:
    class BadAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            return [{"user_messages": ["attack"]}]

    with pytest.raises(TypeError, match="AttackCandidate"):
        evaluation_core.eval_attack(
            BadAttack,
            10.0,
            build_agent_factory("deterministic"),
            env_selection="sandbox",
        )


def test_eval_attack_replays_candidates_and_canonicalizes(_patch_eval) -> None:
    class GoodAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            env.reset()
            env.interact("attack prompt")
            trace = env.export_trace_dict()
            return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]

    findings = evaluation_core.eval_attack(
        GoodAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["user_messages"] == ["attack prompt"]
    assert finding["predicates"] == [{"predicate": "EXFILTRATION", "severity": 5}]
    assert finding["cell_signature"]["hash"]


def test_eval_attack_enforces_replay_candidate_limit(_patch_eval) -> None:
    class ManyCandidatesAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            total = evaluation_core.MAX_REPLAY_FINDINGS + 7
            return [AttackCandidate(user_messages=(f"msg-{i}",)) for i in range(total)]

    findings = evaluation_core.eval_attack(
        ManyCandidatesAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )
    assert len(findings) == evaluation_core.MAX_REPLAY_FINDINGS


def test_eval_attack_rejects_oversized_candidate_message(_patch_eval) -> None:
    class OversizedAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            long_message = "x" * (MAX_USER_MESSAGE_CHARS + 1)
            return [AttackCandidate(user_messages=(long_message,))]

    with pytest.raises(ValueError, match="max length"):
        evaluation_core.eval_attack(
            OversizedAttack,
            10.0,
            build_agent_factory("deterministic"),
            env_selection="sandbox",
        )


def test_attack_run_config_uses_max_steps_only() -> None:
    config = AttackRunConfig(time_budget_s=1.0, max_steps=7)

    assert config.max_steps == 7

    with pytest.raises(TypeError, match="max_iterations"):
        AttackRunConfig(time_budget_s=1.0, max_iterations=7)  # type: ignore[call-arg]
