"""Canonical CLI report serialization for evaluation runs."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from aicomp_sdk.evaluation.runner import (
    AttackExecution,
    DefenseExecution,
    EvaluationExecution,
)
from aicomp_sdk.evaluation.tracks import EvaluationTrack


class ReportProfile(StrEnum):
    """Output profile for command-specific report projections."""

    EVALUATE = "evaluate"
    TEST = "test"


def _require_attack(execution: EvaluationExecution) -> AttackExecution:
    attack = execution.attack
    if attack is None:
        raise RuntimeError(f"{execution.track.value} execution missing attack results")
    return attack


def _require_defense(execution: EvaluationExecution) -> DefenseExecution:
    defense = execution.defense
    if defense is None:
        raise RuntimeError(f"{execution.track.value} execution missing defense results")
    return defense


def _format_attack_payload(
    attack: AttackExecution,
    *,
    include_evaluated: bool,
    include_time_taken: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "score": attack.score,
        "score_raw": attack.score_raw,
        "findings_count": attack.findings_count,
        "unique_cells": attack.unique_cells,
        "unique_canonical_cells": attack.unique_canonical_cells,
    }
    if include_evaluated:
        payload["evaluated"] = True
    if include_time_taken:
        payload["time_taken"] = attack.time_taken
    return payload


def _format_attack_metadata(attack: AttackExecution) -> dict[str, Any]:
    return {
        "attack_guardrail_id": attack.guardrail_id,
        "attack_guardrail_version": attack.guardrail_version,
        "env_visibility": "opaque",
    }


def _format_defense_metadata(defense: DefenseExecution) -> dict[str, Any]:
    return {
        "defense_hook_id": defense.hook_id,
        "defense_hook_version": defense.hook_version,
    }


def _format_defense_payload(
    defense: DefenseExecution,
    *,
    include_evaluated: bool,
    include_time_taken: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "score": defense.score,
        "breach_count": defense.breach_count,
        "false_positives": defense.false_positives,
        "benign_trials": defense.benign_trials,
        "false_positive_rate": defense.false_positive_rate,
    }
    if include_evaluated:
        payload["evaluated"] = True
    if include_time_taken:
        payload["time_taken"] = defense.time_taken
    return payload


def _not_evaluated_attack_payload() -> dict[str, Any]:
    return {
        "evaluated": False,
        "score": None,
        "score_raw": None,
        "findings_count": None,
        "unique_cells": None,
        "unique_canonical_cells": None,
        "time_taken": None,
    }


def _not_evaluated_defense_payload() -> dict[str, Any]:
    return {
        "evaluated": False,
        "score": None,
        "breach_count": None,
        "false_positives": None,
        "benign_trials": None,
        "false_positive_rate": None,
        "time_taken": None,
    }


def build_evaluation_report(
    execution: EvaluationExecution,
    *,
    profile: ReportProfile = ReportProfile.EVALUATE,
) -> dict[str, Any]:
    """Serialize a run into a command-facing report shape.

    The execution model is shared. The command profile controls only the shell
    projection:

    - ``evaluate`` writes scorer-style artifacts and omits unevaluated track
      placeholders.
    - ``test`` keeps the history-friendly shape with explicit evaluated flags
      and timing fields.
    """
    if profile is ReportProfile.EVALUATE:
        return _build_evaluate_report(execution)
    if profile is ReportProfile.TEST:
        return _build_test_report(execution)
    raise AssertionError(f"Unhandled report profile: {profile}")


def _build_evaluate_report(execution: EvaluationExecution) -> dict[str, Any]:
    if execution.track is EvaluationTrack.REDTEAM:
        attack = _require_attack(execution)
        return {
            "track": EvaluationTrack.REDTEAM.value,
            "attack": _format_attack_payload(
                attack,
                include_evaluated=False,
                include_time_taken=False,
            ),
            "final_score": execution.final_score,
            "attack_env_seed": attack.env_seed,
            **_format_attack_metadata(attack),
            "budget_s": execution.budget_plan.attack_budget_s,
            "agent_selection": execution.agent.label,
            "env_selection": execution.env_selection.value,
            "run_id": execution.run_id,
            "scoring_mode": "normalized",
            "submission_type": "attack_only",
        }

    if execution.track is EvaluationTrack.DEFENSE:
        defense = _require_defense(execution)
        return {
            "track": EvaluationTrack.DEFENSE.value,
            "defense": _format_defense_payload(
                defense,
                include_evaluated=False,
                include_time_taken=False,
            ),
            "final_score": execution.final_score,
            **_format_defense_metadata(defense),
            "budget_s": execution.budget_plan.defense_budget_s,
            "agent_selection": execution.agent.label,
            "env_selection": execution.env_selection.value,
            "run_id": execution.run_id,
            "submission_type": "guardrail_only",
        }

    attack = _require_attack(execution)
    defense = _require_defense(execution)
    return {
        "track": EvaluationTrack.DUAL.value,
        "final_score": execution.final_score,
        "attack": _format_attack_payload(
            attack,
            include_evaluated=False,
            include_time_taken=False,
        ),
        "defense": _format_defense_payload(
            defense,
            include_evaluated=False,
            include_time_taken=False,
        ),
        **_format_attack_metadata(attack),
        **_format_defense_metadata(defense),
        "budget_s": execution.budget_plan.total_budget_s,
        "agent_selection": execution.agent.label,
        "env_selection": execution.env_selection.value,
        "run_id": execution.run_id,
        "scoring_mode": execution.scoring_mode,
        "submission_type": "dual_track",
    }


def _build_test_report(execution: EvaluationExecution) -> dict[str, Any]:
    if execution.track is EvaluationTrack.REDTEAM:
        attack = _require_attack(execution)
        return {
            "track": EvaluationTrack.REDTEAM.value,
            "attack": _format_attack_payload(
                attack,
                include_evaluated=True,
                include_time_taken=True,
            ),
            "defense": _not_evaluated_defense_payload(),
            "final_score": execution.final_score,
            **_format_attack_metadata(attack),
            "submission_type": "attack_only",
            "scoring_mode": "normalized",
            "agent_selection": execution.agent.label,
            "env_selection": execution.env_selection.value,
            "run_id": execution.run_id,
        }

    if execution.track is EvaluationTrack.DEFENSE:
        defense = _require_defense(execution)
        return {
            "track": EvaluationTrack.DEFENSE.value,
            "attack": _not_evaluated_attack_payload(),
            "defense": _format_defense_payload(
                defense,
                include_evaluated=True,
                include_time_taken=True,
            ),
            "final_score": execution.final_score,
            **_format_defense_metadata(defense),
            "submission_type": "guardrail_only",
            "agent_selection": execution.agent.label,
            "env_selection": execution.env_selection.value,
            "run_id": execution.run_id,
        }

    attack = _require_attack(execution)
    defense = _require_defense(execution)
    return {
        "track": EvaluationTrack.DUAL.value,
        "attack": _format_attack_payload(
            attack,
            include_evaluated=True,
            include_time_taken=True,
        ),
        "defense": _format_defense_payload(
            defense,
            include_evaluated=True,
            include_time_taken=True,
        ),
        "final_score": execution.final_score,
        **_format_attack_metadata(attack),
        **_format_defense_metadata(defense),
        "scoring_mode": execution.scoring_mode,
        "submission_type": "dual_track",
        "agent_selection": execution.agent.label,
        "env_selection": execution.env_selection.value,
        "run_id": execution.run_id,
    }
