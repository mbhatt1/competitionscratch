"""Kaggle red-team-only evaluator.

This scorer accepts a standalone `attack.py` submission and emits only the
normalized attack score for leaderboard use.
"""

import argparse
import json
from pathlib import Path

from aicomp_sdk.agents import AgentSelection, build_agent_factory, parse_agent_selection
from aicomp_sdk.core.env_api import EnvSelection, parse_env_selection
from aicomp_sdk.evaluation_core import (
    DEFAULT_KAGGLE_ATTACK_BUDGET_S,
    eval_attack,
    load_module_from_file,
    summarize_attack_findings,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--submission", type=str, required=True, help="Path to attack.py")
    ap.add_argument("--out", type=str, default="scores.txt")
    ap.add_argument("--out_json", type=str, default="scores.json", help="Detailed JSON output")
    ap.add_argument(
        "--budget-s",
        type=float,
        default=DEFAULT_KAGGLE_ATTACK_BUDGET_S,
        help="Attack evaluation budget in seconds.",
    )
    ap.add_argument(
        "--fixtures_dir",
        type=str,
        default=None,
        help="Optional fixtures root override (defaults to packaged fixtures).",
    )
    ap.add_argument("--verbose", action="store_true", help="Print detailed breakdown")
    ap.add_argument(
        "--agent",
        type=str,
        default="auto",
        choices=[member.value for member in AgentSelection],
        help="Agent selection mode for attack eval.",
    )
    ap.add_argument(
        "--env",
        type=str,
        default="gym",
        choices=[member.value for member in EnvSelection],
        help="Attack environment selection (default: gym for Kaggle-style evaluation).",
    )
    args = ap.parse_args()
    agent_selection = parse_agent_selection(args.agent)
    env_selection = parse_env_selection(args.env)
    agent_factory = build_agent_factory(agent_selection)

    submission_path = Path(args.submission).resolve()
    if submission_path.name != "attack.py":
        raise SystemExit("Kaggle red-team submissions must be provided as attack.py")

    attack_mod = load_module_from_file(submission_path, "user_attack")
    if not hasattr(attack_mod, "AttackAlgorithm"):
        raise SystemExit("Submission missing attack.py with AttackAlgorithm")

    print("\n" + "=" * 70)
    print("EVALUATING RED-TEAM SUBMISSION")
    print("=" * 70)
    print(f"Agent selection: {agent_selection}")
    print(f"Env selection:   {env_selection}")

    attack_findings = eval_attack(
        attack_mod.AttackAlgorithm,
        float(args.budget_s),
        agent_factory=agent_factory,
        env_selection=env_selection,
        fixtures_dir=Path(args.fixtures_dir).resolve() if args.fixtures_dir else None,
    )
    attack_summary = summarize_attack_findings(attack_findings)

    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Attack Score: {attack_summary['score']:.2f}")
    print("=" * 70)

    if args.verbose:
        print("\nDETAILED BREAKDOWN:")
        print(f"  Attack Findings: {attack_summary['findings_count']}")
        print(f"  Unique Cells: {attack_summary['unique_cells']}")
        print(f"  Raw Attack Score: {attack_summary['score_raw']:.2f}")

    out_path = Path(args.out)
    out_path.write_text(f"{attack_summary['score']}\n", encoding="utf-8")

    detailed_results = {
        "track": "redteam",
        "attack": attack_summary,
        "final_score": attack_summary["score"],
        "attack_seed": 123,
        "budget_s": float(args.budget_s),
        "agent_selection": agent_selection.value,
        "env_selection": env_selection.value,
        "scoring_mode": "normalized",
        "submission_type": "attack_only",
    }

    json_out = Path(args.out_json)
    json_out.write_text(json.dumps(detailed_results, indent=2), encoding="utf-8")

    print(f"\nResults written to: {out_path}")
    print(f"Detailed results written to: {json_out}")


if __name__ == "__main__":
    main()
