"""Full-run evaluation orchestration for CLI shells."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from aicomp_sdk.agents import (
    AgentFactory,
    AgentSelection,
    JsonlAgentDebugSink,
    build_agent_factory,
)
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.budget_policy import EvaluationBudgetPlan
from aicomp_sdk.evaluation.diagnostics import EventKind, RunDiagnostics
from aicomp_sdk.evaluation.tracks import EvaluationTrack

if TYPE_CHECKING:
    from aicomp_sdk.evaluation.ops import DefenseRunOptions, ValidatedAttackFinding


@dataclass(frozen=True, slots=True)
class AttackExecution:
    findings: list[ValidatedAttackFinding]
    score: float
    score_raw: float
    findings_count: int
    unique_cells: int
    unique_canonical_cells: int
    time_taken: float


@dataclass(frozen=True, slots=True)
class DefenseExecution:
    report: dict[str, Any]
    score: float
    breach_count: int
    false_positives: int
    benign_trials: int
    false_positive_rate: float
    time_taken: float


@dataclass(frozen=True, slots=True)
class EvaluationExecution:
    track: EvaluationTrack
    budget_plan: EvaluationBudgetPlan
    agent_selection: AgentSelection
    env_selection: EnvSelection
    run_id: str
    attack: AttackExecution | None
    defense: DefenseExecution | None
    final_score: float
    scoring_mode: str | None = None


def resolve_agent_factory(
    agent_selection: AgentSelection,
    *,
    agent_debug_jsonl: Path | None = None,
    output_controller: RunDiagnostics | None = None,
    agent_factory: AgentFactory | None = None,
) -> AgentFactory:
    """Return a run-scoped agent factory, threading agent debug sinks when requested."""
    if agent_factory is not None:
        return agent_factory

    debug_sink = None
    if agent_debug_jsonl is not None:
        if output_controller is not None:
            debug_sink = output_controller.make_agent_debug_sink(agent_debug_jsonl)
        else:
            debug_sink = JsonlAgentDebugSink(agent_debug_jsonl)
    return build_agent_factory(agent_selection, debug_sink=debug_sink)


def _record_framework_phase_event(
    output_controller: RunDiagnostics,
    *,
    phase: str,
    kind: EventKind,
    message: str,
    **fields: object,
) -> None:
    output_controller.record_event(
        level="info",
        event=kind,
        message=message,
        phase=phase,
        kind=kind,
        fields=fields,
        render=False,
    )


def _execute_attack(
    *,
    attack_cls: type[Any],
    attack_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Path | None,
    output_controller: RunDiagnostics,
    phase: str,
    capture_label: str,
) -> AttackExecution:
    from aicomp_sdk.evaluation.ops import eval_attack, summarize_attack_findings

    started_at = time.time()
    with output_controller.phase(phase).capture_stdio(capture_label):
        findings = eval_attack(
            attack_cls,
            attack_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=output_controller,
        )
    elapsed_s = time.time() - started_at
    summary = summarize_attack_findings(findings)
    return AttackExecution(
        findings=findings,
        score=summary["score"],
        score_raw=summary["score_raw"],
        findings_count=summary["findings_count"],
        unique_cells=summary["unique_cells"],
        unique_canonical_cells=summary.get("unique_canonical_cells", summary["unique_cells"]),
        time_taken=elapsed_s,
    )


def _execute_defense(
    *,
    guardrail_cls: type[Any],
    defense_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Path | None,
    output_controller: RunDiagnostics,
    phase: str,
    capture_label: str,
    defense_options: DefenseRunOptions | None = None,
) -> DefenseExecution:
    from aicomp_sdk.evaluation.ops import eval_defense
    from aicomp_sdk.scoring import score_defense

    started_at = time.time()
    with output_controller.phase(phase).capture_stdio(capture_label):
        report = eval_defense(
            guardrail_cls,
            defense_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=output_controller,
            options=defense_options,
        )
    elapsed_s = time.time() - started_at
    score = score_defense(report)
    breach_count = report.get("breach_count", 0)
    false_positives = report.get("false_positives", 0)
    benign_trials = report.get("benign_trials", 7)
    return DefenseExecution(
        report=report,
        score=score,
        breach_count=breach_count,
        false_positives=false_positives,
        benign_trials=benign_trials,
        false_positive_rate=false_positives / max(1, benign_trials),
        time_taken=elapsed_s,
    )


def execute_evaluation(
    *,
    track: EvaluationTrack,
    budget_plan: EvaluationBudgetPlan,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    output_controller: RunDiagnostics,
    attack_cls: type[Any] | None = None,
    guardrail_cls: type[Any] | None = None,
    fixtures_dir: Path | None = None,
    agent_debug_jsonl: Path | None = None,
    agent_factory: AgentFactory | None = None,
    defense_options: DefenseRunOptions | None = None,
    event_style: Literal["evaluate", "test"] = "test",
) -> EvaluationExecution:
    """Execute one evaluation run for the selected track."""
    from aicomp_sdk.scoring import get_score_breakdown

    resolved_agent_factory = resolve_agent_factory(
        agent_selection,
        agent_debug_jsonl=agent_debug_jsonl,
        output_controller=output_controller,
        agent_factory=agent_factory,
    )

    if track is EvaluationTrack.REDTEAM:
        if attack_cls is None:
            raise ValueError("Red-team evaluation requires attack_cls.")
        _record_framework_phase_event(
            output_controller,
            phase="redteam_evaluation",
            kind="phase_start",
            message=(
                "Running attack generation and replay..."
                if event_style == "evaluate"
                else "Running red-team evaluation..."
            ),
            attack_budget_s=budget_plan.attack_budget_s,
            track=track.value,
        )
        attack = _execute_attack(
            attack_cls=attack_cls,
            attack_budget_s=budget_plan.attack_budget_s,
            agent_factory=resolved_agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=output_controller,
            phase="redteam_evaluation",
            capture_label="red-team evaluation",
        )
        _record_framework_phase_event(
            output_controller,
            phase="redteam_evaluation",
            kind="phase_end",
            message=(
                "Attack evaluation complete. Summarizing results..."
                if event_style == "evaluate"
                else "Red-team evaluation complete."
            ),
            findings_count=attack.findings_count,
            score=attack.score,
        )
        return EvaluationExecution(
            track=track,
            budget_plan=budget_plan,
            agent_selection=agent_selection,
            env_selection=env_selection,
            run_id=output_controller.run_id,
            attack=attack,
            defense=None,
            final_score=attack.score,
            scoring_mode="normalized",
        )

    if track is EvaluationTrack.DEFENSE:
        if guardrail_cls is None:
            raise ValueError("Defense evaluation requires guardrail_cls.")
        _record_framework_phase_event(
            output_controller,
            phase="defense_evaluation",
            kind="phase_start",
            message=(
                "Running baseline attack against guardrail..."
                if event_style == "evaluate"
                else "Running defense evaluation..."
            ),
            defense_budget_s=budget_plan.defense_budget_s,
            track=track.value,
        )
        defense = _execute_defense(
            guardrail_cls=guardrail_cls,
            defense_budget_s=budget_plan.defense_budget_s,
            agent_factory=resolved_agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=output_controller,
            phase="defense_evaluation",
            capture_label="defense evaluation",
            defense_options=defense_options,
        )
        _record_framework_phase_event(
            output_controller,
            phase="defense_evaluation",
            kind="phase_end",
            message=(
                "Defense evaluation complete. Summarizing results..."
                if event_style == "evaluate"
                else "Defense evaluation complete."
            ),
            **(
                {
                    "breach_count": defense.breach_count,
                    "defense_score": defense.score,
                }
                if event_style == "evaluate"
                else {
                    "breaches": defense.breach_count,
                    "false_positives": defense.false_positives,
                    "score": defense.score,
                }
            ),
        )
        return EvaluationExecution(
            track=track,
            budget_plan=budget_plan,
            agent_selection=agent_selection,
            env_selection=env_selection,
            run_id=output_controller.run_id,
            attack=None,
            defense=defense,
            final_score=defense.score,
        )

    if track is not EvaluationTrack.DUAL:
        raise AssertionError(f"Unhandled evaluation track: {track}")
    if attack_cls is None or guardrail_cls is None:
        raise ValueError("Dual-track evaluation requires both attack_cls and guardrail_cls.")

    _record_framework_phase_event(
        output_controller,
        phase="dual_offense_evaluation",
        kind="phase_start",
        message=(
            "Running offense attack generation and replay..."
            if event_style == "evaluate"
            else "Running attack evaluation..."
        ),
        attack_budget_s=budget_plan.attack_budget_s,
        track=track.value,
    )
    attack = _execute_attack(
        attack_cls=attack_cls,
        attack_budget_s=budget_plan.attack_budget_s,
        agent_factory=resolved_agent_factory,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
        output_controller=output_controller,
        phase="dual_offense_evaluation",
        capture_label="offense evaluation",
    )
    _record_framework_phase_event(
        output_controller,
        phase="dual_offense_evaluation",
        kind="phase_end",
        message=(
            "Offense evaluation complete."
            if event_style == "evaluate"
            else "Attack evaluation complete."
        ),
        findings_count=attack.findings_count,
        score=attack.score,
    )
    _record_framework_phase_event(
        output_controller,
        phase="dual_defense_evaluation",
        kind="phase_start",
        message=(
            "Offense evaluation complete. Running defense evaluation..."
            if event_style == "evaluate"
            else "Running defense evaluation..."
        ),
        **(
            cast(
                dict[str, object],
                {
                    "offense_score": attack.score,
                    "defense_budget_s": budget_plan.defense_budget_s,
                },
            )
            if event_style == "evaluate"
            else cast(
                dict[str, object],
                {
                    "defense_budget_s": budget_plan.defense_budget_s,
                    "track": track.value,
                },
            )
        ),
    )
    defense = _execute_defense(
        guardrail_cls=guardrail_cls,
        defense_budget_s=budget_plan.defense_budget_s,
        agent_factory=resolved_agent_factory,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
        output_controller=output_controller,
        phase="dual_defense_evaluation",
        capture_label="defense evaluation",
        defense_options=defense_options,
    )
    _record_framework_phase_event(
        output_controller,
        phase="dual_defense_evaluation",
        kind="phase_end",
        message=(
            "Defense evaluation complete. Summarizing results..."
            if event_style == "evaluate"
            else "Defense evaluation complete."
        ),
        **(
            {
                "breach_count": defense.breach_count,
                "defense_score": defense.score,
            }
            if event_style == "evaluate"
            else {
                "breaches": defense.breach_count,
                "false_positives": defense.false_positives,
                "score": defense.score,
            }
        ),
    )
    breakdown = get_score_breakdown(attack.findings, defense.report)
    return EvaluationExecution(
        track=track,
        budget_plan=budget_plan,
        agent_selection=agent_selection,
        env_selection=env_selection,
        run_id=output_controller.run_id,
        attack=attack,
        defense=defense,
        final_score=attack.score + defense.score,
        scoring_mode=breakdown["attack_mode"],
    )
