#!/usr/bin/env python3
"""Kaggle-style local smoke test for an attack-only submission."""

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

SMOKE_BUDGET_S = 5.0


def _bootstrap_repo_root() -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))


_bootstrap_repo_root()

from aicomp_sdk.agents import build_agent_factory  # noqa: E402
from aicomp_sdk.evaluation_core import eval_attack, summarize_attack_findings  # noqa: E402
from attack import AttackAlgorithm  # noqa: E402


def main() -> int:
    print("=" * 70)
    print("TESTING ATTACK-ONLY SUBMISSION")
    print("=" * 70)
    print("\nRunning official red-team evaluation locally...")

    with redirect_stdout(io.StringIO()):
        findings = eval_attack(
            AttackAlgorithm,
            SMOKE_BUDGET_S,
            agent_factory=build_agent_factory("deterministic"),
            env_selection="gym",
        )
    summary = summarize_attack_findings(findings)

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Attack Score: {summary['score']:.2f}")
    print(f"Raw Score:    {summary['score_raw']:.2f}")
    print(f"Findings:     {summary['findings_count']}")
    print(f"Unique Cells: {summary['unique_cells']}")
    print("\nUse evaluation_redteam.py for longer Kaggle-compatible scoring runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
