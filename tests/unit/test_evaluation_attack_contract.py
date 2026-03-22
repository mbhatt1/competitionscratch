from __future__ import annotations

from typing import Any

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core
from aicomp_sdk.agents import build_agent_factory
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.api import MAX_USER_MESSAGE_CHARS, EnvInteractionResult
from aicomp_sdk.guardrails.base import GuardrailBase


class _FakeSandboxEnv:
    def __init__(  # noqa: ANN001
        self,
        seed: int,
        fixtures_dir,
        guardrail,
        agent=None,
        max_tool_hops: int = 8,
    ):
        del fixtures_dir, guardrail, agent
        self.seed = seed
        self.default_max_tool_hops = max_tool_hops
        self._messages: list[str] = []
        self.interaction_hops: list[int] = []

    def reset(self) -> None:
        self._messages = []

    def interact(self, user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult:
        resolved_max_tool_hops = self.default_max_tool_hops if max_tool_hops is None else max_tool_hops
        self.interaction_hops.append(resolved_max_tool_hops)
        self._messages.append(user_message)
        return EnvInteractionResult(
            seed=self.seed,
            total_tool_events=1 if self._messages else 0,
            tool_events_added=1,
            agent_turns=1,
            successful_tool_calls=1,
        )

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
            max_tool_hops=kwargs.get("max_tool_hops", 8),
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
    assert finding["trace"] == {
        "seed": 123,
        "user_messages": ["attack prompt"],
        "tool_events": [
            {
                "name": "fs.read",
                "args": {"path": "secret.txt"},
                "ok": True,
                "side_effect": "READ",
                "scope": "secret",
                "source": "user",
            }
        ],
        "egress": [],
    }
    assert finding["predicates"] == [{"predicate": "EXFILTRATION", "severity": 5}]
    assert finding["cell_signature"] == cell_signature(
        finding["trace"]["tool_events"],
        egress_data=finding["trace"]["egress"],
        user_messages=finding["trace"]["user_messages"],
    )
    assert finding["score_cell_signature"] == cell_signature(finding["trace"]["tool_events"])


def test_eval_attack_scores_same_trace_different_prompts_as_one_scoring_cell(_patch_eval) -> None:
    class TwoPromptAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del env, config
            return [
                AttackCandidate(user_messages=("attack prompt one",)),
                AttackCandidate(user_messages=("attack prompt two",)),
            ]

    findings = evaluation_core.eval_attack(
        TwoPromptAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert len(findings) == 2
    assert len({finding["cell_signature"]["hash"] for finding in findings}) == 2
    assert len({finding["score_cell_signature"]["hash"] for finding in findings}) == 1

    summary = evaluation_core.summarize_attack_findings(findings)

    assert summary["findings_count"] == 2
    assert summary["unique_cells"] == 1
    assert summary["unique_canonical_cells"] == 2


def test_eval_attack_uses_replayed_candidate_messages_not_run_env_state(_patch_eval) -> None:
    class DivergentAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            env.reset()
            env.interact("priming prompt")
            return [AttackCandidate(user_messages=("replay prompt",))]

    findings = evaluation_core.eval_attack(
        DivergentAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["user_messages"] == ["replay prompt"]
    assert finding["trace"]["user_messages"] == ["replay prompt"]


def test_eval_attack_builds_fresh_env_for_run_and_each_replay(monkeypatch) -> None:
    build_calls: list[_FakeSandboxEnv] = []

    def fake_build_attack_env(**kwargs: Any) -> _FakeSandboxEnv:
        env = _FakeSandboxEnv(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
            max_tool_hops=kwargs.get("max_tool_hops", 8),
        )
        build_calls.append(env)
        return env

    monkeypatch.setattr(evaluation_core, "build_attack_env", fake_build_attack_env)
    monkeypatch.setattr(
        evaluation_core,
        "eval_predicates",
        lambda trace: (
            [{"predicate": "EXFILTRATION", "severity": 5}] if trace.get("user_messages") else []
        ),
    )

    class TwoCandidatesAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            return [
                AttackCandidate(user_messages=("msg-1",)),
                AttackCandidate(user_messages=("msg-2",)),
            ]

    findings = evaluation_core.eval_attack(
        TwoCandidatesAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert [finding["user_messages"] for finding in findings] == [["msg-1"], ["msg-2"]]
    assert len(build_calls) == 3
    assert len({id(env) for env in build_calls}) == 3


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


def test_eval_attack_applies_redteam_run_options(monkeypatch: pytest.MonkeyPatch) -> None:
    build_calls: list[dict[str, Any]] = []
    guardrail_instances: list[object] = []

    class _FakeGuardrail(GuardrailBase):
        pass

    def fake_guardrail_factory() -> _FakeGuardrail:
        guardrail = _FakeGuardrail()
        guardrail_instances.append(guardrail)
        return guardrail

    def fake_build_attack_env(**kwargs: Any) -> _FakeSandboxEnv:
        build_calls.append(kwargs)
        return _FakeSandboxEnv(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
            max_tool_hops=kwargs.get("max_tool_hops", 8),
        )

    monkeypatch.setattr(evaluation_core, "build_attack_env", fake_build_attack_env)
    monkeypatch.setattr(
        evaluation_core,
        "eval_predicates",
        lambda trace: (
            [{"predicate": "EXFILTRATION", "severity": 5}] if trace.get("user_messages") else []
        ),
    )

    class ConfigurableAttack(AttackAlgorithmBase):
        def __init__(self, config=None):  # noqa: ANN001
            super().__init__(config)
            self.seen_config = dict(self.config)
            self.seen_run_config: AttackRunConfig | None = None

        def run(self, env, config):  # noqa: ANN001
            self.seen_run_config = config
            assert self.seen_config == {"max_turns": 6, "branch_batch": 8}
            assert config == AttackRunConfig(time_budget_s=30.0, max_steps=100, max_tool_hops=5)
            return [AttackCandidate(user_messages=("attack prompt",))]

    options = evaluation_core.RedteamRunOptions(
        run_config=AttackRunConfig(time_budget_s=30.0, max_steps=100, max_tool_hops=5),
        attack_config={"max_turns": 6, "branch_batch": 8},
        seed=42,
        guardrail_factory=fake_guardrail_factory,
    )

    findings = evaluation_core.eval_attack(
        ConfigurableAttack,
        999.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
        options=options,
    )

    assert [finding["user_messages"] for finding in findings] == [["attack prompt"]]
    assert [call["seed"] for call in build_calls] == [42, 42]
    assert [call["max_tool_hops"] for call in build_calls] == [5, 5]
    assert [call["guardrail"] for call in build_calls] == guardrail_instances


def test_eval_attack_defaults_to_legacy_hop_cap_for_generation_and_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built_envs: list[_FakeSandboxEnv] = []

    def fake_build_attack_env(**kwargs: Any) -> _FakeSandboxEnv:
        env = _FakeSandboxEnv(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
            max_tool_hops=kwargs.get("max_tool_hops", 8),
        )
        built_envs.append(env)
        return env

    monkeypatch.setattr(evaluation_core, "build_attack_env", fake_build_attack_env)
    monkeypatch.setattr(
        evaluation_core,
        "eval_predicates",
        lambda trace: (
            [{"predicate": "EXFILTRATION", "severity": 5}] if trace.get("user_messages") else []
        ),
    )

    class DefaultHopAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            assert config.max_tool_hops == evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS
            env.reset()
            env.interact("attack prompt")
            trace = env.export_trace_dict()
            return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]

    findings = evaluation_core.eval_attack(
        DefaultHopAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert [finding["user_messages"] for finding in findings] == [["attack prompt"]]
    assert [env.default_max_tool_hops for env in built_envs] == [
        evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS,
        evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS,
    ]
    assert built_envs[0].interaction_hops == [evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS]
    assert built_envs[1].interaction_hops == [evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS]
    assert evaluation_core.EVALUATION_DEFAULT_MAX_TOOL_HOPS == 4


def test_attack_run_config_uses_max_steps_only() -> None:
    config = AttackRunConfig(time_budget_s=1.0, max_steps=7)

    assert config.max_steps == 7

    with pytest.raises(TypeError, match="max_iterations"):
        AttackRunConfig(time_budget_s=1.0, max_iterations=7)  # type: ignore[call-arg]
