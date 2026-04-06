from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import aicomp_sdk.evaluation.ops as evaluation_ops
from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.diagnostics import EvaluatorVerbosity, RunDiagnostics
from aicomp_sdk.evaluation.runner import (
    ResolvedAgentConfig,
    evaluate_defense,
    evaluate_dual,
    evaluate_redteam,
)
from aicomp_sdk.evaluation.tracks import EvaluationTrack
from aicomp_sdk.hooks import HookRegistry


def _attack_summary(
    *,
    score: float,
    score_raw: float,
    findings_count: int,
    unique_cells: int,
) -> dict[str, float | int]:
    return {
        "score": score,
        "score_raw": score_raw,
        "findings_count": findings_count,
        "unique_cells": unique_cells,
    }


def test_evaluate_redteam_uses_internal_diagnostics_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_eval_attack(*args: Any, **kwargs: Any) -> list[Any]:
        del args
        captured["output_controller"] = kwargs["output_controller"]
        captured["options"] = kwargs["options"]
        return []

    monkeypatch.setattr(evaluation_ops, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(
            score=12.0,
            score_raw=3.0,
            findings_count=2,
            unique_cells=2,
        ),
    )

    execution = evaluate_redteam(
        object,
        budget_s=10.0,
        agent_selection=AgentSelection.DETERMINISTIC,
        env_selection=EnvSelection.SANDBOX,
    )

    assert execution.track is EvaluationTrack.REDTEAM
    assert execution.agent == ResolvedAgentConfig(
        selection=AgentSelection.DETERMINISTIC,
        label="deterministic",
    )
    assert execution.final_score == 12.0
    assert captured["output_controller"] is not None
    assert captured["options"].run_config.time_budget_s == 10.0


def test_evaluate_redteam_reports_custom_agent_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def agent_factory() -> object:
        return object()

    monkeypatch.setattr(evaluation_ops, "eval_attack", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(
            score=1.0,
            score_raw=1.0,
            findings_count=1,
            unique_cells=1,
        ),
    )

    execution = evaluate_redteam(
        object,
        budget_s=10.0,
        agent_factory=agent_factory,
        agent_label="local_test_agent",
    )

    assert execution.agent == ResolvedAgentConfig(
        selection=None,
        label="local_test_agent",
    )


def test_evaluate_redteam_rejects_agent_label_without_custom_factory() -> None:
    with pytest.raises(ValueError, match="agent_label is only supported"):
        evaluate_redteam(
            object,
            budget_s=10.0,
            agent_label="misleading",
        )


def test_evaluate_redteam_rejects_custom_factory_with_explicit_agent_selection() -> None:
    with pytest.raises(ValueError, match="agent_selection is only supported"):
        evaluate_redteam(
            object,
            budget_s=10.0,
            agent_selection=AgentSelection.DETERMINISTIC,
            agent_factory=lambda: object(),
        )


def test_evaluate_defense_emits_one_canonical_framework_event_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evaluation_ops,
        "eval_defense",
        lambda *args, **kwargs: {
            "breach_count": 1,
            "false_positives": 2,
            "benign_trials": 4,
        },
    )
    monkeypatch.setattr("aicomp_sdk.scoring.score_defense", lambda report: 750.0)

    event_log_file = tmp_path / "framework.jsonl"
    with RunDiagnostics(
        EvaluatorVerbosity.SUMMARY,
        event_log_file=event_log_file,
    ) as diagnostics:
        execution = evaluate_defense(
            object,
            budget_s=10.0,
            agent_selection=AgentSelection.DETERMINISTIC,
            diagnostics=diagnostics,
        )

    assert execution.defense is not None
    event_payloads = [
        json.loads(line) for line in event_log_file.read_text(encoding="utf-8").splitlines()
    ]
    assert event_payloads[-1]["message"] == "Defense evaluation complete."
    assert event_payloads[-1]["fields"] == {
        "breach_count": 1,
        "false_positives": 2,
        "score": 750.0,
    }


def test_evaluate_dual_threads_explicit_scorer_specs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_attack_options: list[evaluation_ops.AttackEvalOptions] = []
    captured_defense_options: list[evaluation_ops.DefenseRunOptions] = []

    def fake_eval_attack(*args: Any, **kwargs: Any) -> list[Any]:
        del args
        captured_attack_options.append(kwargs["options"])
        return []

    def fake_eval_defense(*args: Any, **kwargs: Any) -> dict[str, int]:
        del args
        captured_defense_options.append(kwargs["options"])
        return {"breach_count": 0, "false_positives": 0, "benign_trials": 1}

    monkeypatch.setattr(evaluation_ops, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation_ops, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(
            score=10.0,
            score_raw=3.0,
            findings_count=1,
            unique_cells=1,
        ),
    )
    monkeypatch.setattr("aicomp_sdk.scoring.score_defense", lambda report: 800.0)
    monkeypatch.setattr(
        "aicomp_sdk.scoring.get_score_breakdown",
        lambda attack_findings, defense_report: {"attack_mode": "normalized"},
    )

    attack_guardrail_spec = evaluation_ops.AttackGuardrailSpec(
        id="private_guardrail",
        version="7",
        guardrail_factory=object,
    )
    defense_hook_spec = evaluation_ops.DefenseHookSpec(
        id="private_hooks",
        version="9",
        hook_registry_factory=HookRegistry,
    )

    execution = evaluate_dual(
        object,
        object,
        budget_s=10.0,
        agent_factory=lambda: object(),
        agent_label="custom",
        attack_guardrail_spec=attack_guardrail_spec,
        defense_hook_spec=defense_hook_spec,
        attack_config={"beam_width": 4},
        guardrail_challenge_config={"max_findings": 5},
    )

    assert execution.attack is not None
    assert execution.defense is not None
    assert execution.attack.guardrail_id == "private_guardrail"
    assert execution.attack.guardrail_version == "7"
    assert execution.defense.hook_id == "private_hooks"
    assert execution.defense.hook_version == "9"
    assert captured_attack_options[0].attack_config == {"beam_width": 4}
    assert captured_defense_options[0].guardrail_challenge_config == {"max_findings": 5}
    assert captured_defense_options[0].guardrail_challenge_env_seed == 123
