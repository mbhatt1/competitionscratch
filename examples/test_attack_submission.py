#!/usr/bin/env python3
"""Concise attack-only smoke test for an example submission file.

Defaults to the canonical Gymnasium-style attack example so the script mirrors
the public Kaggle-style attack path without importing repo-root submission
files.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import io
import sys
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

DEFAULT_BUDGET_S: Final[float] = 5.0


def _repo_root() -> Path:
    """Return the repository root containing the aicomp_sdk package."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "aicomp_sdk").is_dir():
            return parent
    return current.parent


REPO_ROOT: Final[Path] = _repo_root()
DEFAULT_ATTACK_PATH: Final[Path] = (
    REPO_ROOT / "examples" / "attacks" / "attack_gym_step.py"
)


@dataclass(frozen=True)
class CliArgs:
    submission_path: Path
    budget_s: float
    agent: str


def _ensure_repo_root_on_sys_path(repo_root: Path) -> None:
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as err:
        raise argparse.ArgumentTypeError("must be a number") from err

    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")

    return value


def _parse_args(argv: Optional[Sequence[str]] = None) -> CliArgs:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--submission",
        type=Path,
        default=DEFAULT_ATTACK_PATH,
        help="Path to an example attack submission file.",
    )
    parser.add_argument(
        "--budget-s",
        type=_positive_float,
        default=DEFAULT_BUDGET_S,
        help="Smoke-test attack budget in seconds.",
    )
    parser.add_argument(
        "--agent",
        default="deterministic",
        help="Agent selection for the smoke test.",
    )
    args = parser.parse_args(argv)
    return CliArgs(
        submission_path=args.submission,
        budget_s=args.budget_s,
        agent=args.agent,
    )


def _display_path(path: Path, *, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args()

    submission_path = args.submission_path.resolve()
    if not submission_path.is_file():
        raise SystemExit(f"Submission file not found: {submission_path}.")

    _ensure_repo_root_on_sys_path(REPO_ROOT)

    from aicomp_sdk.agents import build_agent_factory
    from aicomp_sdk.evaluation_core import (
        eval_attack,
        load_module_from_file,
        summarize_attack_findings,
    )

    module = load_module_from_file(submission_path, "examples_attack_submission")
    attack_cls = getattr(module, "AttackAlgorithm", None)
    if attack_cls is None:
        raise SystemExit(f"Missing AttackAlgorithm in {submission_path}")

    # Suppress evaluator stdout so the smoke-test summary remains concise.
    with redirect_stdout(io.StringIO()):
        findings = eval_attack(
            attack_cls,
            args.budget_s,
            agent_factory=build_agent_factory(args.agent),
            env_selection="gym",
        )

    summary = summarize_attack_findings(findings)

    print(f"Attack smoke test: {_display_path(submission_path, repo_root=REPO_ROOT)}")
    print(f"Budget (s):        {args.budget_s:.1f}")
    print(f"Agent:             {args.agent}")
    print(f"Attack score:      {summary['score']:.2f}")
    print(f"Attack raw:        {summary['score_raw']:.2f}")
    print(f"Findings:          {summary['findings_count']}")
    print(f"Unique cells:      {summary['unique_cells']}")
    print(
        "Note: short smoke runs check evaluator compatibility and may yield 0 findings."
    )
    print("For a longer public-contract run, use evaluation_redteam.py with attack.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
