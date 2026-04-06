"""Public evaluation orchestration for CLI-equivalent Python runs."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aicomp_sdk.agents import AgentFactory, AgentSelection, build_agent_factory
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.budget_policy import (
    EvaluationBudgetPlan,
    resolve_budget_plan,
)
from aicomp_sdk.evaluation.diagnostics import (
    EvaluatorVerbosity,
    EventKind,
    RunDiagnostics,
)
from aicomp_sdk.evaluation.tracks import EvaluationTrack

if TYPE_CHECKING:
    from aicomp_sdk.attacks import AttackRunConfig
    from aicomp_sdk.evaluation.ops import (
        AttackEvalOptions,
        AttackGuardrailSpec,
        DefenseHookSpec,
        DefenseRunOptions,
        ValidatedAttackFinding,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedAgentConfig:
    """Run metadata for the concrete agent used by an evaluation."""

    selection: AgentSelection | None
    label: str


@dataclass(frozen=True, slots=True)
class AttackExecution:
    findings: list[ValidatedAttackFinding]
    score: float
    score_raw: float
    findings_count: int
    unique_cells: int
    unique_canonical_cells: int
    time_taken: float
    guardrail_id: str
    guardrail_version: str
    env_seed: int = 123


@dataclass(frozen=True, slots=True)
class DefenseExecution:
    report: dict[str, Any]
    score: float
    breach_count: int
    false_positives: int
    benign_trials: int
    false_positive_rate: float
    time_taken: float
    hook_id: str
    hook_version: str


@dataclass(frozen=True, slots=True)
class EvaluationExecution:
    track: EvaluationTrack
    budget_plan: EvaluationBudgetPlan
    agent: ResolvedAgentConfig
    env_selection: EnvSelection
    run_id: str
    attack: AttackExecution | None
    defense: DefenseExecution | None
    final_score: float
    scoring_mode: str | None = None


def resolve_agent_factory(
    *,
    agent_selection: AgentSelection = AgentSelection.AUTO,
    agent_factory: AgentFactory | None = None,
    agent_label: str | None = None,
    diagnostics: RunDiagnostics | None = None,
) -> tuple[AgentFactory, ResolvedAgentConfig]:
    """Return a run-scoped agent factory plus run metadata."""
    if agent_factory is not None:
        if agent_selection is not AgentSelection.AUTO:
            raise ValueError(
                "agent_selection is only supported for built-in agent selection; "
                "custom agent_factory must leave agent_selection as auto."
            )
        return (
            agent_factory,
            ResolvedAgentConfig(selection=None, label=agent_label or "custom"),
        )

    if agent_label is not None:
        raise ValueError("agent_label is only supported with custom agent_factory.")

    debug_sink = diagnostics.make_agent_debug_sink() if diagnostics is not None else None
    return (
        build_agent_factory(agent_selection, debug_sink=debug_sink),
        ResolvedAgentConfig(selection=agent_selection, label=agent_selection.value),
    )


@contextmanager
def _require_diagnostics(
    diagnostics: RunDiagnostics | None,
) -> Iterator[RunDiagnostics]:
    if diagnostics is not None:
        yield diagnostics
        return

    with RunDiagnostics(EvaluatorVerbosity.SUMMARY) as owned_diagnostics:
        yield owned_diagnostics


def _record_framework_phase_event(
    diagnostics: RunDiagnostics,
    *,
    phase: str,
    kind: EventKind,
    message: str,
    **fields: object,
) -> None:
    diagnostics.record_event(
        level="info",
        event=kind,
        message=message,
        phase=phase,
        kind=kind,
        fields=fields,
        render=False,
    )


def _create_attack_eval_options(
    *,
    attack_budget_s: float,
    attack_guardrail_spec: AttackGuardrailSpec | None,
    attack_run_config: AttackRunConfig | None,
    attack_config: Mapping[str, Any] | None,
    attack_env_seed: int,
) -> tuple[AttackEvalOptions, AttackGuardrailSpec]:
    from aicomp_sdk.attacks import AttackRunConfig
    from aicomp_sdk.evaluation.ops import (
        AttackEvalOptions,
        resolve_attack_guardrail_spec,
    )

    resolved_guardrail_spec = attack_guardrail_spec or resolve_attack_guardrail_spec()
    return (
        AttackEvalOptions(
            run_config=attack_run_config or AttackRunConfig(time_budget_s=attack_budget_s),
            attack_config=dict(attack_config or {}),
            env_seed=attack_env_seed,
            guardrail_factory=resolved_guardrail_spec.guardrail_factory,
        ),
        resolved_guardrail_spec,
    )


def _create_defense_run_options(
    *,
    defense_hook_spec: DefenseHookSpec | None,
    guardrail_challenge_config: Mapping[str, Any] | None,
    guardrail_challenge_run_config: AttackRunConfig | None,
    guardrail_challenge_env_seed: int,
    benign_seed: int,
    benign_prompts: tuple[str, ...] | None,
) -> tuple[DefenseRunOptions, DefenseHookSpec]:
    from aicomp_sdk.evaluation.ops import DefenseRunOptions, resolve_defense_hook_spec

    resolved_hook_spec = defense_hook_spec or resolve_defense_hook_spec()
    return (
        DefenseRunOptions(
            guardrail_challenge_config=dict(guardrail_challenge_config or {}),
            guardrail_challenge_run_config=guardrail_challenge_run_config,
            guardrail_challenge_env_seed=guardrail_challenge_env_seed,
            benign_seed=benign_seed,
            benign_prompts=benign_prompts,
            hook_registry_factory=resolved_hook_spec.hook_registry_factory,
        ),
        resolved_hook_spec,
    )


def _execute_attack(
    *,
    attack_cls: type[Any],
    attack_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Path | None,
    diagnostics: RunDiagnostics,
    phase: str,
    capture_label: str,
    attack_guardrail_spec: AttackGuardrailSpec | None,
    attack_run_config: AttackRunConfig | None,
    attack_config: Mapping[str, Any] | None,
    attack_env_seed: int,
) -> AttackExecution:
    from aicomp_sdk.evaluation.ops import eval_attack, summarize_attack_findings

    options, resolved_guardrail_spec = _create_attack_eval_options(
        attack_budget_s=attack_budget_s,
        attack_guardrail_spec=attack_guardrail_spec,
        attack_run_config=attack_run_config,
        attack_config=attack_config,
        attack_env_seed=attack_env_seed,
    )
    started_at = time.time()
    with diagnostics.phase(phase).capture_stdio(capture_label):
        findings = eval_attack(
            attack_cls,
            attack_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=diagnostics,
            options=options,
        )
    elapsed_s = time.time() - started_at
    summary = summarize_attack_findings(findings)
    return AttackExecution(
        findings=findings,
        score=summary["score"],
        score_raw=summary["score_raw"],
        findings_count=summary["findings_count"],
        unique_cells=summary["unique_cells"],
        unique_canonical_cells=summary.get(
            "unique_canonical_cells",
            summary["unique_cells"],
        ),
        time_taken=elapsed_s,
        guardrail_id=resolved_guardrail_spec.id,
        guardrail_version=resolved_guardrail_spec.version,
        env_seed=attack_env_seed,
    )


def _execute_defense(
    *,
    guardrail_cls: type[Any],
    defense_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Path | None,
    diagnostics: RunDiagnostics,
    phase: str,
    capture_label: str,
    defense_hook_spec: DefenseHookSpec | None,
    guardrail_challenge_config: Mapping[str, Any] | None,
    guardrail_challenge_run_config: AttackRunConfig | None,
    guardrail_challenge_env_seed: int,
    benign_seed: int,
    benign_prompts: tuple[str, ...] | None,
) -> DefenseExecution:
    from aicomp_sdk.evaluation.ops import eval_defense
    from aicomp_sdk.scoring import score_defense

    options, resolved_hook_spec = _create_defense_run_options(
        defense_hook_spec=defense_hook_spec,
        guardrail_challenge_config=guardrail_challenge_config,
        guardrail_challenge_run_config=guardrail_challenge_run_config,
        guardrail_challenge_env_seed=guardrail_challenge_env_seed,
        benign_seed=benign_seed,
        benign_prompts=benign_prompts,
    )
    started_at = time.time()
    with diagnostics.phase(phase).capture_stdio(capture_label):
        report = eval_defense(
            guardrail_cls,
            defense_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            output_controller=diagnostics,
            options=options,
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
        hook_id=resolved_hook_spec.id,
        hook_version=resolved_hook_spec.version,
    )


def evaluate_redteam(
    attack_cls: type[Any],
    *,
    budget_s: float,
    agent_selection: AgentSelection = AgentSelection.AUTO,
    agent_factory: AgentFactory | None = None,
    agent_label: str | None = None,
    env_selection: EnvSelection = EnvSelection.SANDBOX,
    fixtures_dir: Path | None = None,
    attack_guardrail_spec: AttackGuardrailSpec | None = None,
    attack_run_config: AttackRunConfig | None = None,
    attack_config: Mapping[str, Any] | None = None,
    attack_env_seed: int = 123,
    diagnostics: RunDiagnostics | None = None,
) -> EvaluationExecution:
    """Run the scorer-equivalent red-team evaluation harness.

    This is the high-level Python entrypoint for attack-only scripts. It mirrors
    ``aicomp evaluate redteam`` / ``aicomp test redteam``: the submitted attack
    runs against an opaque environment, returned candidates are replayed, and
    scoring uses evaluator-owned traces.

    Use ``agent_selection`` for SDK-managed backends. Use ``agent_factory`` with
    ``agent_label`` when embedding a custom backend; leave ``agent_selection`` as
    ``AgentSelection.AUTO`` in that mode. ``attack_guardrail_spec`` is
    scorer-owned harness configuration, not attack-submission behavior.

    The returned ``EvaluationExecution`` has ``attack`` populated and ``defense``
    set to ``None``.
    """
    budget_plan = resolve_budget_plan(EvaluationTrack.REDTEAM, total_budget_s=budget_s)
    with _require_diagnostics(diagnostics) as active_diagnostics:
        resolved_factory, resolved_agent = resolve_agent_factory(
            agent_selection=agent_selection,
            agent_factory=agent_factory,
            agent_label=agent_label,
            diagnostics=active_diagnostics,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="redteam_evaluation",
            kind="phase_start",
            message="Running red-team evaluation...",
            attack_budget_s=budget_plan.attack_budget_s,
            track=EvaluationTrack.REDTEAM.value,
        )
        attack = _execute_attack(
            attack_cls=attack_cls,
            attack_budget_s=budget_plan.attack_budget_s,
            agent_factory=resolved_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            diagnostics=active_diagnostics,
            phase="redteam_evaluation",
            capture_label="red-team evaluation",
            attack_guardrail_spec=attack_guardrail_spec,
            attack_run_config=attack_run_config,
            attack_config=attack_config,
            attack_env_seed=attack_env_seed,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="redteam_evaluation",
            kind="phase_end",
            message="Red-team evaluation complete.",
            findings_count=attack.findings_count,
            score=attack.score,
        )
        return EvaluationExecution(
            track=EvaluationTrack.REDTEAM,
            budget_plan=budget_plan,
            agent=resolved_agent,
            env_selection=env_selection,
            run_id=active_diagnostics.run_id,
            attack=attack,
            defense=None,
            final_score=attack.score,
            scoring_mode="normalized",
        )


def evaluate_defense(
    guardrail_cls: type[Any],
    *,
    budget_s: float,
    agent_selection: AgentSelection = AgentSelection.AUTO,
    agent_factory: AgentFactory | None = None,
    agent_label: str | None = None,
    env_selection: EnvSelection = EnvSelection.SANDBOX,
    fixtures_dir: Path | None = None,
    defense_hook_spec: DefenseHookSpec | None = None,
    guardrail_challenge_config: Mapping[str, Any] | None = None,
    guardrail_challenge_run_config: AttackRunConfig | None = None,
    guardrail_challenge_env_seed: int = 123,
    benign_seed: int = 999,
    benign_prompts: tuple[str, ...] | None = None,
    diagnostics: RunDiagnostics | None = None,
) -> EvaluationExecution:
    """Run the scorer-equivalent defense evaluation harness.

    This is the high-level Python entrypoint for guardrail-only scripts. It
    mirrors ``aicomp evaluate defense`` / ``aicomp test defense``: the evaluator
    uses a scorer-owned guardrail challenge generator to produce replay
    candidates, replays them against the submitted guardrail, and runs benign
    trials to measure false positives.

    ``defense_hook_spec`` selects scorer-owned compromised-environment fixtures
    for challenge generation, replay, and benign trials. The
    ``guardrail_challenge_*`` parameters tune the evaluator-owned challenge
    generator; they do not configure the submitted guardrail.

    The returned ``EvaluationExecution`` has ``defense`` populated and ``attack``
    set to ``None``.
    """
    budget_plan = resolve_budget_plan(EvaluationTrack.DEFENSE, total_budget_s=budget_s)
    with _require_diagnostics(diagnostics) as active_diagnostics:
        resolved_factory, resolved_agent = resolve_agent_factory(
            agent_selection=agent_selection,
            agent_factory=agent_factory,
            agent_label=agent_label,
            diagnostics=active_diagnostics,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="defense_evaluation",
            kind="phase_start",
            message="Running defense evaluation...",
            defense_budget_s=budget_plan.defense_budget_s,
            track=EvaluationTrack.DEFENSE.value,
        )
        defense = _execute_defense(
            guardrail_cls=guardrail_cls,
            defense_budget_s=budget_plan.defense_budget_s,
            agent_factory=resolved_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            diagnostics=active_diagnostics,
            phase="defense_evaluation",
            capture_label="defense evaluation",
            defense_hook_spec=defense_hook_spec,
            guardrail_challenge_config=guardrail_challenge_config,
            guardrail_challenge_run_config=guardrail_challenge_run_config,
            guardrail_challenge_env_seed=guardrail_challenge_env_seed,
            benign_seed=benign_seed,
            benign_prompts=benign_prompts,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="defense_evaluation",
            kind="phase_end",
            message="Defense evaluation complete.",
            breach_count=defense.breach_count,
            false_positives=defense.false_positives,
            score=defense.score,
        )
        return EvaluationExecution(
            track=EvaluationTrack.DEFENSE,
            budget_plan=budget_plan,
            agent=resolved_agent,
            env_selection=env_selection,
            run_id=active_diagnostics.run_id,
            attack=None,
            defense=defense,
            final_score=defense.score,
        )


def evaluate_dual(
    attack_cls: type[Any],
    guardrail_cls: type[Any],
    *,
    budget_s: float,
    agent_selection: AgentSelection = AgentSelection.AUTO,
    agent_factory: AgentFactory | None = None,
    agent_label: str | None = None,
    env_selection: EnvSelection = EnvSelection.SANDBOX,
    fixtures_dir: Path | None = None,
    attack_guardrail_spec: AttackGuardrailSpec | None = None,
    defense_hook_spec: DefenseHookSpec | None = None,
    attack_run_config: AttackRunConfig | None = None,
    attack_config: Mapping[str, Any] | None = None,
    guardrail_challenge_config: Mapping[str, Any] | None = None,
    guardrail_challenge_run_config: AttackRunConfig | None = None,
    attack_env_seed: int = 123,
    guardrail_challenge_env_seed: int = 123,
    benign_seed: int = 999,
    benign_prompts: tuple[str, ...] | None = None,
    diagnostics: RunDiagnostics | None = None,
) -> EvaluationExecution:
    """Run the scorer-equivalent dual-track evaluation harness.

    This is the high-level Python entrypoint for package dual-track scripts. It
    mirrors ``aicomp evaluate dual`` / ``aicomp test dual`` by running the
    submitted attack in the offense phase, then running the submitted guardrail
    through the scorer-owned guardrail challenge generator in the defense phase.

    ``attack_config`` / ``attack_run_config`` configure the submitted attack.
    ``guardrail_challenge_config`` / ``guardrail_challenge_run_config``
    configure the evaluator-owned defense challenge generator. ``defense_hook_spec``
    selects scorer-owned compromised-environment fixtures for the defense phase.

    The returned ``EvaluationExecution`` has both ``attack`` and ``defense``
    populated, and ``final_score`` is the sum of the attack and defense scores.
    """
    from aicomp_sdk.scoring import get_score_breakdown

    budget_plan = resolve_budget_plan(EvaluationTrack.DUAL, total_budget_s=budget_s)
    with _require_diagnostics(diagnostics) as active_diagnostics:
        resolved_factory, resolved_agent = resolve_agent_factory(
            agent_selection=agent_selection,
            agent_factory=agent_factory,
            agent_label=agent_label,
            diagnostics=active_diagnostics,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="dual_offense_evaluation",
            kind="phase_start",
            message="Running offense evaluation...",
            attack_budget_s=budget_plan.attack_budget_s,
            track=EvaluationTrack.DUAL.value,
        )
        attack = _execute_attack(
            attack_cls=attack_cls,
            attack_budget_s=budget_plan.attack_budget_s,
            agent_factory=resolved_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            diagnostics=active_diagnostics,
            phase="dual_offense_evaluation",
            capture_label="offense evaluation",
            attack_guardrail_spec=attack_guardrail_spec,
            attack_run_config=attack_run_config,
            attack_config=attack_config,
            attack_env_seed=attack_env_seed,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="dual_offense_evaluation",
            kind="phase_end",
            message="Offense evaluation complete.",
            findings_count=attack.findings_count,
            score=attack.score,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="dual_defense_evaluation",
            kind="phase_start",
            message="Running defense evaluation...",
            defense_budget_s=budget_plan.defense_budget_s,
            offense_score=attack.score,
            track=EvaluationTrack.DUAL.value,
        )
        defense = _execute_defense(
            guardrail_cls=guardrail_cls,
            defense_budget_s=budget_plan.defense_budget_s,
            agent_factory=resolved_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
            diagnostics=active_diagnostics,
            phase="dual_defense_evaluation",
            capture_label="defense evaluation",
            defense_hook_spec=defense_hook_spec,
            guardrail_challenge_config=guardrail_challenge_config,
            guardrail_challenge_run_config=guardrail_challenge_run_config,
            guardrail_challenge_env_seed=guardrail_challenge_env_seed,
            benign_seed=benign_seed,
            benign_prompts=benign_prompts,
        )
        _record_framework_phase_event(
            active_diagnostics,
            phase="dual_defense_evaluation",
            kind="phase_end",
            message="Defense evaluation complete.",
            breach_count=defense.breach_count,
            false_positives=defense.false_positives,
            score=defense.score,
        )
        breakdown = get_score_breakdown(attack.findings, defense.report)
        return EvaluationExecution(
            track=EvaluationTrack.DUAL,
            budget_plan=budget_plan,
            agent=resolved_agent,
            env_selection=env_selection,
            run_id=active_diagnostics.run_id,
            attack=attack,
            defense=defense,
            final_score=attack.score + defense.score,
            scoring_mode=breakdown["attack_mode"],
        )
