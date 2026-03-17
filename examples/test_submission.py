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

    from aicomp_sdk.agents import build_agent_factory
    from aicomp_sdk.evaluation_core import (
        eval_attack,
        eval_defense,
        load_from_zip,
        summarize_attack_findings,
    )
    from aicomp_sdk.scoring import get_score_breakdown, score_defense

    return (
        build_agent_factory,
        eval_attack,
        eval_defense,
        load_from_zip,
        summarize_attack_findings,
        get_score_breakdown,
        score_defense,
    )


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
        default="deterministic",
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
    (
        build_agent_factory,
        eval_attack,
        eval_defense,
        load_from_zip,
        summarize_attack_findings,
        get_score_breakdown,
        score_defense,
    ) = _load_sdk_dependencies()

    args = _parse_args()
    attack_path = args.attack.resolve()
    guardrail_path = args.guardrail.resolve()
    total_budget_s = float(args.budget_s)
    offense_budget_s = total_budget_s / 2.0
    defense_budget_s = total_budget_s / 2.0
    agent_factory = build_agent_factory(args.agent)

    with ExitStack() as stack:
        submission_tmp = _create_submission_zip(attack_path, guardrail_path)
        stack.enter_context(submission_tmp)
        zip_path = Path(submission_tmp.name) / "submission.zip"

        attack_mod, attack_tmp = load_from_zip(zip_path, "examples_attack", "attack.py")
        stack.enter_context(attack_tmp)
        guardrail_mod, guardrail_tmp = load_from_zip(zip_path, "examples_guardrail", "guardrail.py")
        stack.enter_context(guardrail_tmp)

        if attack_mod is None or not hasattr(attack_mod, "AttackAlgorithm"):
            raise SystemExit(f"Missing AttackAlgorithm in {attack_path}")
        if guardrail_mod is None or not hasattr(guardrail_mod, "Guardrail"):
            raise SystemExit(f"Missing Guardrail in {guardrail_path}")

        with redirect_stdout(io.StringIO()):
            attack_findings = eval_attack(
                attack_mod.AttackAlgorithm,
                offense_budget_s,
                agent_factory=agent_factory,
                env_selection="sandbox",
            )
            defense_report = eval_defense(
                guardrail_mod.Guardrail,
                defense_budget_s,
                agent_factory=agent_factory,
                env_selection="sandbox",
            )

    attack_summary = summarize_attack_findings(attack_findings)
    defense_score = score_defense(defense_report)
    final_score = attack_summary["score"] + defense_score
    breakdown = get_score_breakdown(attack_findings, defense_report)

    print(
        "Dual-track smoke test: "
        f"{attack_path.relative_to(REPO_ROOT)} + {guardrail_path.relative_to(REPO_ROOT)}"
    )
    print(f"Total budget (s):     {total_budget_s:.1f}")
    print(f"Agent:                {args.agent}")
    print(
        f"Attack score:         {attack_summary['score']:.2f} "
        f"(raw: {attack_summary['score_raw']:.2f}, mode: {breakdown['attack_mode']})"
    )
    print(f"Attack findings:      {attack_summary['findings_count']}")
    print(f"Attack unique cells:  {attack_summary['unique_cells']}")
    print(f"Defense score:        {defense_score:.2f}")
    print(f"Defense breaches:     {defense_report.get('breach_count', 0)}")
    print(
        "Defense false positives: "
        f"{defense_report.get('false_positives', 0)}/{defense_report.get('benign_trials', 0)}"
    )
    print(f"Final score:          {final_score:.2f}")
    print("For a longer package dual-track run, use evaluation.py with submission.zip.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
