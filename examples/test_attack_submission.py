#!/usr/bin/env python3
"""Concise attack-only smoke test for an example submission file.

Defaults to the canonical Gymnasium-style attack example so the script mirrors
the public Kaggle-style attack path without importing repo-root submission
files.
"""

from __future__ import annotations

import argparse
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path


DEFAULT_BUDGET_S = 5.0


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in (current.parent, *current.parents):
        if (parent / "aicomp_sdk").is_dir():
            return parent
    return current.parent


REPO_ROOT = _repo_root()


DEFAULT_ATTACK_PATH = REPO_ROOT / "examples" / "attacks" / "attack_gym_step.py"


def _load_sdk_dependencies():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from aicomp_sdk.agents import build_agent_factory
    from aicomp_sdk.evaluation_core import eval_attack, load_module_from_file, summarize_attack_findings

    return build_agent_factory, eval_attack, load_module_from_file, summarize_attack_findings


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--submission",
        type=Path,
        default=DEFAULT_ATTACK_PATH,
        help="Path to an example attack submission file.",
    )
    parser.add_argument(
        "--budget-s",
        type=float,
        default=DEFAULT_BUDGET_S,
        help="Smoke-test attack budget in seconds.",
    )
    parser.add_argument(
        "--agent",
        default="deterministic",
        help="Agent selection for the smoke test.",
    )
    return parser.parse_args()


def main() -> int:
    build_agent_factory, eval_attack, load_module_from_file, summarize_attack_findings = (
        _load_sdk_dependencies()
    )

    args = _parse_args()
    submission_path = args.submission.resolve()
    module = load_module_from_file(submission_path, "examples_attack_submission")
    attack_cls = getattr(module, "AttackAlgorithm", None)
    if attack_cls is None:
        raise SystemExit(f"Missing AttackAlgorithm in {submission_path}")

    with redirect_stdout(io.StringIO()):
        findings = eval_attack(
            attack_cls,
            float(args.budget_s),
            agent_factory=build_agent_factory(args.agent),
            env_selection="gym",
        )
    summary = summarize_attack_findings(findings)

    print(f"Attack smoke test: {submission_path.relative_to(REPO_ROOT)}")
    print(f"Budget (s):        {float(args.budget_s):.1f}")
    print(f"Agent:             {args.agent}")
    print(f"Attack score:      {summary['score']:.2f}")
    print(f"Attack raw:        {summary['score_raw']:.2f}")
    print(f"Findings:          {summary['findings_count']}")
    print(f"Unique cells:      {summary['unique_cells']}")
    print("Note: short smoke runs check evaluator compatibility and may yield 0 findings.")
    print("For a longer public-contract run, use evaluation_redteam.py with attack.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
