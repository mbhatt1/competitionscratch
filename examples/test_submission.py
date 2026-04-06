#!/usr/bin/env python3
"""Concise dual-track smoke test for example attack and guardrail files.

This script mirrors the current dual-track evaluator at a smoke-test budget by
packaging the selected example files as `attack.py` and `guardrail.py`, loading
them through the same zip-based entrypoints, and printing only the official
summary fields.
"""

from __future__ import annotations

import argparse
import io
import sys
import zipfile
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from aicomp_sdk.agents import AgentSelection

DEFAULT_TOTAL_BUDGET_S = 20.0


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in (current.parent, *current.parents):
        if (parent / "aicomp_sdk").is_dir():
            return parent
    return current.parent


REPO_ROOT = _repo_root()


DEFAULT_ATTACK_PATH = REPO_ROOT / "examples" / "attacks" / "attack.py"
DEFAULT_GUARDRAIL_PATH = REPO_ROOT / "examples" / "guardrails" / "guardrail.py"


def _load_sdk_dependencies():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from aicomp_sdk import EnvSelection
    from aicomp_sdk.evaluation import evaluate_dual
    from aicomp_sdk.evaluation.submissions import load_track_modules
    from aicomp_sdk.evaluation.tracks import EvaluationTrack

    return EnvSelection, EvaluationTrack, evaluate_dual, load_track_modules


def _announce_progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--attack",
        type=Path,
        default=DEFAULT_ATTACK_PATH,
        help="Path to an example attack file.",
    )
    parser.add_argument(
        "--guardrail",
        type=Path,
        default=DEFAULT_GUARDRAIL_PATH,
        help="Path to an example guardrail file.",
    )
    parser.add_argument(
        "--budget-s",
        type=float,
        default=DEFAULT_TOTAL_BUDGET_S,
        help="Total smoke-test budget in seconds; split evenly across offense and defense.",
    )
    parser.add_argument(
        "--agent",
        type=AgentSelection,
        choices=list(AgentSelection),
        default=AgentSelection.DETERMINISTIC,
        help="Agent selection for both halves of the smoke test.",
    )
    return parser.parse_args()


def _create_submission_zip(attack_path: Path, guardrail_path: Path) -> TemporaryDirectory:
    tmp = TemporaryDirectory(prefix="aicomp_examples_")
    zip_path = Path(tmp.name) / "submission.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(attack_path, arcname="attack.py")
        archive.write(guardrail_path, arcname="guardrail.py")
    return tmp


def main() -> int:
    EnvSelection, EvaluationTrack, evaluate_dual, load_track_modules = _load_sdk_dependencies()

    args = _parse_args()
    attack_path = args.attack.resolve()
    guardrail_path = args.guardrail.resolve()
    total_budget_s = float(args.budget_s)

    with ExitStack() as stack:
        submission_tmp = _create_submission_zip(attack_path, guardrail_path)
        stack.enter_context(submission_tmp)
        zip_path = Path(submission_tmp.name) / "submission.zip"

        attack_cls, guardrail_cls = load_track_modules(
            stack,
            zip_path,
            EvaluationTrack.DUAL,
        )

        if attack_cls is None:
            raise SystemExit(f"Missing AttackAlgorithm in {attack_path}")
        if guardrail_cls is None:
            raise SystemExit(f"Missing Guardrail in {guardrail_path}")

        _announce_progress("Running dual-track smoke test...")
        with redirect_stdout(io.StringIO()):
            execution = evaluate_dual(
                attack_cls,
                guardrail_cls,
                budget_s=total_budget_s,
                agent_selection=args.agent,
                env_selection=EnvSelection.SANDBOX,
            )
        _announce_progress("Dual-track smoke test complete. Summarizing results...")

    attack = execution.attack
    defense = execution.defense
    if attack is None or defense is None:
        raise RuntimeError("Dual-track smoke test did not produce both attack and defense results")

    print(
        "Dual-track smoke test: "
        f"{attack_path.relative_to(REPO_ROOT)} + {guardrail_path.relative_to(REPO_ROOT)}"
    )
    print(f"Total budget (s):     {total_budget_s:.1f}")
    print(f"Attack budget (s):    {execution.budget_plan.attack_budget_s:.1f}")
    print(f"Defense budget (s):   {execution.budget_plan.defense_budget_s:.1f}")
    print(f"Agent:                {args.agent}")
    print(
        f"Attack score:         {attack.score:.2f} "
        f"(raw: {attack.score_raw:.2f}, mode: {execution.scoring_mode})"
    )
    print(f"Attack findings:      {attack.findings_count}")
    print(f"Attack unique cells:  {attack.unique_cells}")
    print(f"Defense score:        {defense.score:.2f}")
    print(f"Defense breaches:     {defense.breach_count}")
    print("Defense false positives: " f"{defense.false_positives}/{defense.benign_trials}")
    print(f"Final score:          {execution.final_score:.2f}")
    print("For a longer package dual-track run, use aicomp evaluate dual submission.zip.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
