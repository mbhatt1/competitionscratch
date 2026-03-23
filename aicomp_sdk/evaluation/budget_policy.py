from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from aicomp_sdk.evaluation.tracks import EvaluationTrack

DEFAULT_ATTACK_BUDGET_S: Final[float] = 1800.0
DEFAULT_DEFENSE_BUDGET_S: Final[float] = 1800.0
DEFAULT_DUAL_TOTAL_BUDGET_S: Final[float] = DEFAULT_ATTACK_BUDGET_S + DEFAULT_DEFENSE_BUDGET_S
DEFAULT_CLI_TOTAL_BUDGET_S: Final[float] = DEFAULT_DUAL_TOTAL_BUDGET_S


@dataclass(frozen=True, slots=True)
class EvaluationBudgetPlan:
    total_budget_s: float
    attack_budget_s: float
    defense_budget_s: float


def resolve_budget_plan(
    track: EvaluationTrack,
    *,
    total_budget_s: float,
) -> EvaluationBudgetPlan:
    if track is EvaluationTrack.REDTEAM:
        return EvaluationBudgetPlan(
            total_budget_s=total_budget_s,
            attack_budget_s=total_budget_s,
            defense_budget_s=0.0,
        )
    if track is EvaluationTrack.DEFENSE:
        return EvaluationBudgetPlan(
            total_budget_s=total_budget_s,
            attack_budget_s=0.0,
            defense_budget_s=total_budget_s,
        )
    if track is EvaluationTrack.DUAL:
        half_budget_s = total_budget_s / 2.0
        return EvaluationBudgetPlan(
            total_budget_s=total_budget_s,
            attack_budget_s=half_budget_s,
            defense_budget_s=half_budget_s,
        )

    raise AssertionError(f"Unhandled evaluation track: {track}")


def resolve_standalone_budget_plan(
    track: EvaluationTrack,
    *,
    total_budget_s: float | None,
) -> EvaluationBudgetPlan:
    if total_budget_s is None:
        if track is EvaluationTrack.REDTEAM:
            total_budget_s = DEFAULT_ATTACK_BUDGET_S
        elif track is EvaluationTrack.DEFENSE:
            total_budget_s = DEFAULT_DEFENSE_BUDGET_S
        else:
            total_budget_s = DEFAULT_DUAL_TOTAL_BUDGET_S

    return resolve_budget_plan(track, total_budget_s=total_budget_s)
