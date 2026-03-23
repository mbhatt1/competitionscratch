from __future__ import annotations

from aicomp_sdk.evaluation.budget_policy import (
    DEFAULT_ATTACK_BUDGET_S,
    DEFAULT_CLI_TOTAL_BUDGET_S,
    DEFAULT_DEFENSE_BUDGET_S,
    DEFAULT_DUAL_TOTAL_BUDGET_S,
    resolve_budget_plan,
    resolve_standalone_budget_plan,
)
from aicomp_sdk.evaluation.tracks import EvaluationTrack


def test_resolve_standalone_budget_plan_uses_shared_track_defaults() -> None:
    redteam = resolve_standalone_budget_plan(EvaluationTrack.REDTEAM, total_budget_s=None)
    defense = resolve_standalone_budget_plan(EvaluationTrack.DEFENSE, total_budget_s=None)
    dual = resolve_standalone_budget_plan(EvaluationTrack.DUAL, total_budget_s=None)

    assert redteam.total_budget_s == DEFAULT_ATTACK_BUDGET_S
    assert redteam.attack_budget_s == DEFAULT_ATTACK_BUDGET_S
    assert redteam.defense_budget_s == 0.0

    assert defense.total_budget_s == DEFAULT_DEFENSE_BUDGET_S
    assert defense.attack_budget_s == 0.0
    assert defense.defense_budget_s == DEFAULT_DEFENSE_BUDGET_S

    assert dual.total_budget_s == DEFAULT_DUAL_TOTAL_BUDGET_S
    assert dual.attack_budget_s == DEFAULT_ATTACK_BUDGET_S
    assert dual.defense_budget_s == DEFAULT_DEFENSE_BUDGET_S


def test_resolve_budget_plan_splits_explicit_dual_total_evenly() -> None:
    plan = resolve_budget_plan(EvaluationTrack.DUAL, total_budget_s=10.0)

    assert plan.total_budget_s == 10.0
    assert plan.attack_budget_s == 5.0
    assert plan.defense_budget_s == 5.0
def test_cli_default_total_matches_named_dual_total_budget() -> None:
    assert DEFAULT_CLI_TOTAL_BUDGET_S == DEFAULT_DUAL_TOTAL_BUDGET_S
