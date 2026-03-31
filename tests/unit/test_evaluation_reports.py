from __future__ import annotations

from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.budget_policy import EvaluationBudgetPlan
from aicomp_sdk.evaluation.reports import ReportProfile, build_evaluation_report
from aicomp_sdk.evaluation.runner import AttackExecution, DefenseExecution, EvaluationExecution
from aicomp_sdk.evaluation.tracks import EvaluationTrack


def _execution(
    *,
    track: EvaluationTrack,
    attack: AttackExecution | None = None,
    defense: DefenseExecution | None = None,
    final_score: float = 0.0,
    scoring_mode: str | None = "normalized",
) -> EvaluationExecution:
    return EvaluationExecution(
        track=track,
        budget_plan=EvaluationBudgetPlan(
            total_budget_s=60.0,
            attack_budget_s=30.0 if track is EvaluationTrack.DUAL else 60.0,
            defense_budget_s=30.0 if track is EvaluationTrack.DUAL else 60.0,
        ),
        agent_selection=AgentSelection.DETERMINISTIC,
        env_selection=EnvSelection.SANDBOX,
        run_id="run-123",
        attack=attack,
        defense=defense,
        final_score=final_score,
        scoring_mode=scoring_mode,
    )


def _attack_execution() -> AttackExecution:
    return AttackExecution(
        findings=[],
        score=12.5,
        score_raw=4.0,
        findings_count=2,
        unique_cells=2,
        unique_canonical_cells=3,
        time_taken=0.1,
        guardrail_id="optimal_public",
        guardrail_version="1",
    )


def _defense_execution() -> DefenseExecution:
    return DefenseExecution(
        report={"breach_count": 1, "false_positives": 0, "benign_trials": 7},
        score=875.0,
        breach_count=1,
        false_positives=0,
        benign_trials=7,
        false_positive_rate=0.0,
        time_taken=0.2,
    )


def test_build_evaluation_report_shares_canonical_scores_across_profiles() -> None:
    execution = _execution(
        track=EvaluationTrack.DUAL,
        attack=_attack_execution(),
        defense=_defense_execution(),
        final_score=887.5,
    )

    evaluate_report = build_evaluation_report(execution, profile=ReportProfile.EVALUATE)
    test_report = build_evaluation_report(execution, profile=ReportProfile.TEST)

    assert evaluate_report["track"] == test_report["track"] == "dual"
    assert evaluate_report["final_score"] == test_report["final_score"] == 887.5
    assert evaluate_report["submission_type"] == test_report["submission_type"] == "dual_track"
    assert evaluate_report["attack"]["score"] == test_report["attack"]["score"] == 12.5
    assert (
        evaluate_report["attack"]["unique_canonical_cells"]
        == test_report["attack"]["unique_canonical_cells"]
        == 3
    )
    assert evaluate_report["defense"]["score"] == test_report["defense"]["score"] == 875.0
    assert evaluate_report["scoring_mode"] == test_report["scoring_mode"] == "normalized"


def test_build_evaluation_report_evaluate_profile_omits_history_placeholders() -> None:
    execution = _execution(
        track=EvaluationTrack.REDTEAM,
        attack=_attack_execution(),
        final_score=12.5,
    )

    report = build_evaluation_report(execution, profile=ReportProfile.EVALUATE)

    assert "defense" not in report
    assert "evaluated" not in report["attack"]
    assert "time_taken" not in report["attack"]
    assert report["budget_s"] == 60.0
    assert report["attack_seed"] == 123
    assert report["attack_guardrail_id"] == "optimal_public"
    assert report["attack_guardrail_version"] == "1"
    assert report["env_visibility"] == "opaque"


def test_build_evaluation_report_test_profile_keeps_history_friendly_shape() -> None:
    execution = _execution(
        track=EvaluationTrack.DEFENSE,
        defense=_defense_execution(),
        final_score=875.0,
        scoring_mode=None,
    )

    report = build_evaluation_report(execution, profile=ReportProfile.TEST)

    assert report["attack"]["evaluated"] is False
    assert report["attack"]["score"] is None
    assert report["defense"]["evaluated"] is True
    assert report["defense"]["time_taken"] == 0.2
    assert report["final_score"] == 875.0
