from __future__ import annotations

import gc
import importlib
import json
import time
import weakref
from types import SimpleNamespace
from typing import Any

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core
from aicomp_sdk.agents import build_agent_factory
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.api import MAX_USER_MESSAGE_CHARS, EnvInteractionResult
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks import HookRegistry


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

    def reset(self) -> Any:
        self._messages = []

    def interact(self, user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult:
        resolved_max_tool_hops = (
            self.default_max_tool_hops if max_tool_hops is None else max_tool_hops
        )
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


def _fake_eval_predicates(trace: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"predicate": "EXFILTRATION", "severity": 5}] if trace.get("user_messages") else []


def _patch_fake_eval(
    monkeypatch: pytest.MonkeyPatch,
    *,
    env_factory: type[_FakeSandboxEnv] = _FakeSandboxEnv,
) -> None:
    monkeypatch.setattr(
        evaluation_core,
        "build_attack_env",
        lambda **kwargs: env_factory(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
            max_tool_hops=kwargs.get("max_tool_hops", 8),
        ),
    )
    monkeypatch.setattr(
        evaluation_core,
        "eval_predicates",
        _fake_eval_predicates,
    )


@pytest.fixture
def _patch_eval(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fake_eval(monkeypatch)


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


def test_eval_attack_times_out_attack_generation(_patch_eval) -> None:
    class SlowAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del env, config
            time.sleep(0.05)
            return []

    with pytest.raises(TimeoutError, match="attack generation exceeded"):
        evaluation_core.eval_attack(
            SlowAttack,
            0.01,
            build_agent_factory("deterministic"),
            env_selection="sandbox",
        )


def test_eval_attack_discards_partial_findings_when_replay_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowReplayEnv(_FakeSandboxEnv):
        def interact(
            self,
            user_message: str,
            max_tool_hops: int | None = None,
        ) -> EnvInteractionResult:
            if user_message == "slow attack prompt":
                time.sleep(0.05)
            return super().interact(user_message, max_tool_hops)

    _patch_fake_eval(monkeypatch, env_factory=SlowReplayEnv)

    class DirectCandidateAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del env, config
            return [
                AttackCandidate(user_messages=("fast attack prompt",)),
                AttackCandidate(user_messages=("slow attack prompt",)),
            ]

    with pytest.raises(TimeoutError, match="attack replay exceeded"):
        evaluation_core.eval_attack(
            DirectCandidateAttack,
            0.01,
            build_agent_factory("deterministic"),
            env_selection="sandbox",
        )


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
    monkeypatch.setattr(evaluation_core, "eval_predicates", _fake_eval_predicates)

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


@pytest.mark.parametrize("env_selection", ["sandbox", "gym"])
def test_eval_attack_builds_fresh_default_hook_registries_for_generation_and_replay(
    monkeypatch: pytest.MonkeyPatch,
    env_selection: str,
) -> None:
    built_registries: list[HookRegistry] = []

    def fake_build_attack_env(**kwargs: Any) -> _FakeSandboxEnv:
        built_registries.append(kwargs["hook_registry"])
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
        lambda trace: [{"predicate": "EXFILTRATION", "severity": 5}],
    )

    class ReadReadmeAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del config
            env.reset()
            env.interact("read file readme.txt")
            trace = env.export_trace_dict()
            return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]

    findings = evaluation_core.eval_attack(
        ReadReadmeAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection=env_selection,
    )

    assert len(findings) == 1
    assert findings[0]["user_messages"] == ["read file readme.txt"]
    assert len(built_registries) == 2
    assert all(isinstance(registry, HookRegistry) for registry in built_registries)
    assert len({id(registry) for registry in built_registries}) == 2


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


def test_eval_attack_uses_opaque_env_for_attack_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner_snapshot_refs: list[weakref.ReferenceType[object]] = []

    class _SnapshotMarker:
        __slots__ = ("messages", "trace", "__weakref__")

        def __init__(self, *, messages: list[str], trace: str) -> None:
            self.messages = messages
            self.trace = trace

    class _InspectableFakeEnv(_FakeSandboxEnv):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.trace = "raw-trace"
            self.tools = "raw-tools"
            self.guardrail = GuardrailBase()

        def reset(self) -> tuple[dict[str, Any], dict[str, Any]]:
            super().reset()
            return (
                {
                    "trace_summary_json": json.dumps(
                        {"recent_errors": ["denied:suspicious", "confirm_required:review"]}
                    )
                },
                {
                    "trace": {
                        "seed": self.seed,
                        "user_messages": [],
                        "tool_events": [
                            {
                                "name": "fs.read",
                                "args": {"path": "secret.txt"},
                                "ok": False,
                                "output": "",
                                "side_effect": "READ",
                                "scope": "secret",
                                "source": "user",
                                "error": "denied:suspicious",
                            }
                        ],
                        "egress": [],
                    }
                },
            )

        def snapshot(self) -> _SnapshotMarker:
            snapshot = _SnapshotMarker(messages=list(self._messages), trace=self.trace)
            inner_snapshot_refs.append(weakref.ref(snapshot))
            return snapshot

        def restore(self, snapshot: _SnapshotMarker) -> None:
            self._messages = list(snapshot.messages)

    _patch_fake_eval(monkeypatch, env_factory=_InspectableFakeEnv)

    class IntrospectiveAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del config
            assert not hasattr(env, "guardrail")
            assert not hasattr(env, "trace")
            assert not hasattr(env, "tools")
            assert not hasattr(env, "_inner")
            assert not hasattr(env, "_snapshots")
            opaque_module = importlib.import_module("aicomp_sdk.core.env.opaque")
            assert not hasattr(opaque_module, "_get_opaque_attack_env_state")
            assert "guardrail" not in dir(env)
            assert "trace" not in dir(env)
            assert "_inner" not in dir(env)
            with pytest.raises(AttributeError):
                object.__getattribute__(env, "_inner")
            with pytest.raises(AttributeError):
                object.__getattribute__(env, "_snapshots")
            with pytest.raises(TypeError):
                vars(env)

            observation, info = env.reset()
            summary = json.loads(observation["trace_summary_json"])
            assert summary["recent_errors"] == ["denied", "confirm_required"]
            assert info["trace"]["tool_events"][0]["error"] == "denied"

            snapshot = env.snapshot()
            with pytest.raises(TypeError):
                env.restore({"messages": []})
            with pytest.raises(ValueError, match="Unknown opaque snapshot token"):
                env.restore(type(snapshot)())
            env.restore(snapshot)
            del snapshot
            gc.collect()
            assert [snapshot_ref() for snapshot_ref in inner_snapshot_refs] == [None]
            return [AttackCandidate(user_messages=("attack prompt",))]

    findings = evaluation_core.eval_attack(
        IntrospectiveAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
    )

    assert [finding["user_messages"] for finding in findings] == [["attack prompt"]]


def test_eval_attack_applies_attack_eval_options(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(evaluation_core, "eval_predicates", _fake_eval_predicates)

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

    options = evaluation_core.AttackEvalOptions(
        run_config=AttackRunConfig(time_budget_s=30.0, max_steps=100, max_tool_hops=5),
        attack_config={"max_turns": 6, "branch_batch": 8},
        env_seed=42,
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
    assert all(isinstance(call["hook_registry"], HookRegistry) for call in build_calls)
    assert len({id(call["hook_registry"]) for call in build_calls}) == 2


def test_eval_attack_isolates_authoritative_config_from_attacker_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built_envs: list[_FakeSandboxEnv] = []
    deadlines: list[tuple[str, float]] = []
    attacker_run_configs: list[AttackRunConfig] = []

    def fake_build_attack_env(**kwargs: Any) -> _FakeSandboxEnv:
        env = _FakeSandboxEnv(
            seed=kwargs["seed"],
            fixtures_dir=kwargs["fixtures_dir"],
            guardrail=kwargs["guardrail"],
            max_tool_hops=kwargs.get("max_tool_hops", 8),
        )
        built_envs.append(env)
        return env

    def fake_run_until_deadline(operation, *, deadline_s: float, phase: str):  # noqa: ANN001
        deadlines.append((phase, deadline_s))
        return operation()

    monkeypatch.setattr(evaluation_core, "build_attack_env", fake_build_attack_env)
    monkeypatch.setattr(evaluation_core, "eval_predicates", _fake_eval_predicates)
    monkeypatch.setattr(evaluation_core, "_run_until_deadline", fake_run_until_deadline)
    monkeypatch.setattr(evaluation_core.time, "monotonic", lambda: 10.0)

    options = evaluation_core.AttackEvalOptions(
        run_config=AttackRunConfig(time_budget_s=30.0, max_steps=100, max_tool_hops=5),
    )

    class MutatingAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del env
            attacker_run_configs.append(config)
            assert config is not options.run_config
            object.__setattr__(config, "time_budget_s", 999.0)
            object.__setattr__(config, "max_steps", 1)
            object.__setattr__(config, "max_tool_hops", 1)
            object.__setattr__(options.run_config, "time_budget_s", 777.0)
            object.__setattr__(options.run_config, "max_steps", 2)
            object.__setattr__(options.run_config, "max_tool_hops", 2)
            return [AttackCandidate(user_messages=("attack prompt",))]

    findings = evaluation_core.eval_attack(
        MutatingAttack,
        999.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
        options=options,
    )

    assert [finding["user_messages"] for finding in findings] == [["attack prompt"]]
    assert options.run_config == AttackRunConfig(
        time_budget_s=777.0,
        max_steps=2,
        max_tool_hops=2,
    )
    assert attacker_run_configs == [
        AttackRunConfig(time_budget_s=999.0, max_steps=1, max_tool_hops=1)
    ]
    assert [env.default_max_tool_hops for env in built_envs] == [5, 5]
    assert built_envs[1].interaction_hops == [5]
    assert deadlines == [
        ("attack generation", 40.0),
        ("attack replay", 40.0),
    ]


def test_eval_attack_prefers_explicit_options_over_env_guardrail_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, "missing_guardrail")
    _patch_fake_eval(monkeypatch)

    class ConfiguredAttack(AttackAlgorithmBase):
        def run(self, env, config):  # noqa: ANN001
            del env, config
            return [AttackCandidate(user_messages=("attack prompt",))]

    findings = evaluation_core.eval_attack(
        ConfiguredAttack,
        10.0,
        build_agent_factory("deterministic"),
        env_selection="sandbox",
        options=evaluation_core.AttackEvalOptions(
            run_config=AttackRunConfig(time_budget_s=30.0),
            guardrail_factory=GuardrailBase,
        ),
    )

    assert [finding["user_messages"] for finding in findings] == [["attack prompt"]]


def test_eval_attack_keeps_redteam_run_options_alias() -> None:
    options = evaluation_core.RedteamRunOptions(
        run_config=AttackRunConfig(time_budget_s=30.0),
    )

    assert isinstance(options, evaluation_core.AttackEvalOptions)


def test_resolve_attack_guardrail_spec_defaults_to_optimal_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, raising=False)

    spec = evaluation_core.resolve_attack_guardrail_spec()

    assert spec.id == evaluation_core.DEFAULT_ATTACK_GUARDRAIL_ID
    assert spec.guardrail_factory is evaluation_core.OptimalGuardrail


def test_resolve_attack_guardrail_spec_does_not_load_unselected_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenEntryPoint:
        name = "broken_guardrail"

        def load(self) -> None:
            raise RuntimeError("should not load")

    monkeypatch.setattr(
        evaluation_core,
        "entry_points",
        lambda *, group: [_BrokenEntryPoint()],
    )
    monkeypatch.delenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, raising=False)

    spec = evaluation_core.resolve_attack_guardrail_spec()

    assert spec.id == evaluation_core.DEFAULT_ATTACK_GUARDRAIL_ID
    assert spec.guardrail_factory is evaluation_core.OptimalGuardrail


def test_resolve_attack_guardrail_spec_uses_registered_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PrivateGuardrail(GuardrailBase):
        pass

    spec = evaluation_core.AttackGuardrailSpec(
        id="private_test",
        version="2026.03.30",
        guardrail_factory=_PrivateGuardrail,
    )
    evaluation_core.register_attack_guardrail_spec(spec)
    monkeypatch.setenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, "private_test")

    resolved_spec = evaluation_core.resolve_attack_guardrail_spec()

    assert resolved_spec == spec


def test_resolve_attack_guardrail_spec_uses_entry_point_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _EntryPointGuardrail(GuardrailBase):
        pass

    class _FakeEntryPoint:
        name = "entrypoint_test"
        dist = SimpleNamespace(version="2.5.0")

        def load(self) -> type[_EntryPointGuardrail]:
            return _EntryPointGuardrail

    monkeypatch.setattr(
        evaluation_core,
        "entry_points",
        lambda *, group: [_FakeEntryPoint()],
    )
    monkeypatch.setenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, "entrypoint_test")

    resolved_spec = evaluation_core.resolve_attack_guardrail_spec()

    assert resolved_spec == evaluation_core.AttackGuardrailSpec(
        id="entrypoint_test",
        version="2.5.0",
        guardrail_factory=_EntryPointGuardrail,
    )


def test_resolve_attack_guardrail_spec_rejects_unknown_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(evaluation_core.ATTACK_GUARDRAIL_ENV_VAR, "missing_guardrail")

    with pytest.raises(ValueError, match="Unsupported attack guardrail id: missing_guardrail"):
        evaluation_core.resolve_attack_guardrail_spec()


def test_project_attack_trace_dict_preserves_score_cell_signature() -> None:
    raw_tool_events = [
        {
            "name": "fs.read",
            "args": {"path": "secret.txt"},
            "ok": False,
            "output": "",
            "side_effect": "READ",
            "scope": "secret",
            "source": "user",
            "error": "denied:suspicious reason",
        },
        {
            "name": "email.send",
            "args": {"to": "a@example.com"},
            "ok": False,
            "output": "",
            "side_effect": "SHARE",
            "scope": "external",
            "source": "user",
            "error": "confirm_required:needs review",
        },
    ]
    redacted_tool_events = [
        {**raw_tool_events[0], "error": "denied"},
        {**raw_tool_events[1], "error": "confirm_required"},
    ]

    assert cell_signature(raw_tool_events) == cell_signature(redacted_tool_events)


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
