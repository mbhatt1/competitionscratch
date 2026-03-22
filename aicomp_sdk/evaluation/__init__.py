"""Evaluator subsystem namespace."""

from importlib import import_module
from typing import Final, TYPE_CHECKING, Any

from .budget_policy import (
    DEFAULT_ATTACK_BUDGET_S,
    DEFAULT_CLI_TOTAL_BUDGET_S,
    DEFAULT_DEFENSE_BUDGET_S,
    DEFAULT_DUAL_TOTAL_BUDGET_S,
    EvaluationBudgetPlan,
    resolve_budget_plan,
    resolve_standalone_budget_plan,
)
from .diagnostics import (
    EvaluatorVerbosity,
    FrameworkEvent,
    RunDiagnostics,
    coerce_evaluator_verbosity,
)
from .runner import (
    AttackExecution,
    DefenseExecution,
    EvaluationExecution,
    execute_evaluation,
    resolve_agent_factory,
)
from .reports import ReportProfile, build_evaluation_report
from .tracks import EvaluationTrack

if TYPE_CHECKING:
    from .ops import (
        FIXTURES_ENV_VAR,
        LEGACY_REPO_FIXTURES,
        MAX_REPLAY_FINDINGS,
        MAX_REPLAY_MESSAGES_PER_FINDING,
        PACKAGED_FIXTURES,
        DefenseRunOptions,
    )
    from .ops import RedteamRunOptions as RedteamRunOptions
    from .ops import (
        build_attack_env,
        eval_attack,
        eval_defense,
        resolve_fixtures_dir,
        summarize_attack_findings,
    )
    from .submissions import MAX_SUBMISSION_FILE_BYTES, load_from_zip, load_module_from_file

_OPS_EXPORTS: Final[set[str]] = {
    "DefenseRunOptions",
    "FIXTURES_ENV_VAR",
    "LEGACY_REPO_FIXTURES",
    "MAX_REPLAY_FINDINGS",
    "MAX_REPLAY_MESSAGES_PER_FINDING",
    "PACKAGED_FIXTURES",
    "RedteamRunOptions",
    "build_attack_env",
    "eval_attack",
    "eval_defense",
    "resolve_fixtures_dir",
    "summarize_attack_findings",
}
_SUBMISSION_EXPORTS: Final[set[str]] = {
    "MAX_SUBMISSION_FILE_BYTES",
    "load_from_zip",
    "load_module_from_file",
}

__all__ = [
    "DEFAULT_ATTACK_BUDGET_S",
    "DEFAULT_CLI_TOTAL_BUDGET_S",
    "DEFAULT_DEFENSE_BUDGET_S",
    "DEFAULT_DUAL_TOTAL_BUDGET_S",
    "DefenseRunOptions",
    "FIXTURES_ENV_VAR",
    "LEGACY_REPO_FIXTURES",
    "MAX_REPLAY_FINDINGS",
    "MAX_REPLAY_MESSAGES_PER_FINDING",
    "MAX_SUBMISSION_FILE_BYTES",
    "PACKAGED_FIXTURES",
    "AttackExecution",
    "DefenseExecution",
    "EvaluationBudgetPlan",
    "EvaluationExecution",
    "EvaluationTrack",
    "EvaluatorVerbosity",
    "FrameworkEvent",
    "ReportProfile",
    "RunDiagnostics",
    "build_attack_env",
    "eval_attack",
    "eval_defense",
    "load_from_zip",
    "load_module_from_file",
    "coerce_evaluator_verbosity",
    "execute_evaluation",
    "build_evaluation_report",
    "resolve_agent_factory",
    "resolve_budget_plan",
    "resolve_fixtures_dir",
    "resolve_standalone_budget_plan",
    "summarize_attack_findings",
]


def __getattr__(name: str) -> Any:
    if name in _OPS_EXPORTS:
        module = import_module(".ops", __name__)
        return getattr(module, name)
    if name in _SUBMISSION_EXPORTS:
        module = import_module(".submissions", __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _OPS_EXPORTS | _SUBMISSION_EXPORTS)
