"""Dual-track evaluator.

This entrypoint remains available for dual attack+defense experimentation.
"""

import argparse
import json
from contextlib import ExitStack
from pathlib import Path

from aicomp_sdk.agents import AgentSelection, build_agent_factory, parse_agent_selection
from aicomp_sdk.core.env_api import EnvSelection, parse_env_selection
from aicomp_sdk.evaluation_core import (
    eval_attack,
    eval_defense,
    load_from_zip,
    summarize_attack_findings,
)
from aicomp_sdk.scoring import get_score_breakdown, score_defense


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--submission_zip", type=str, required=True)
    ap.add_argument("--out", type=str, default="scores.txt")
    ap.add_argument("--out_json", type=str, default="scores.json", help="Detailed JSON output")
    ap.add_argument(
        "--budget-s",
        type=float,
        default=3600.0,
        help="Total evaluation budget in seconds.",
    )
    ap.add_argument(
        "--fixtures_dir",
        type=str,
        default=None,
        help="Optional fixtures root override for both offense and defense eval.",
    )
    ap.add_argument("--verbose", action="store_true", help="Print detailed breakdown")
    ap.add_argument(
        "--agent",
        type=str,
        default="auto",
        choices=[member.value for member in AgentSelection],
        help="Agent selection mode for both offense and defense eval.",
    )
    ap.add_argument(
        "--env",
        type=str,
        default="sandbox",
        choices=[member.value for member in EnvSelection],
        help="Evaluation environment selection (default: sandbox for local dual-track evaluation).",
    )
    args = ap.parse_args()
    agent_selection = parse_agent_selection(args.agent)
    env_selection = parse_env_selection(args.env)
    agent_factory = build_agent_factory(agent_selection)
    fixtures_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else None

    zip_path = Path(args.submission_zip).resolve()
    total_budget_s = float(args.budget_s)
    offense_budget_s = total_budget_s / 2.0
    defense_budget_s = total_budget_s / 2.0

    with ExitStack() as stack:
        attack_mod, tmp1 = load_from_zip(zip_path, "user_attack", "attack.py")
        stack.enter_context(tmp1)
        guard_mod, tmp2 = load_from_zip(zip_path, "user_guardrail", "guardrail.py")
        stack.enter_context(tmp2)

        if attack_mod is None or not hasattr(attack_mod, "AttackAlgorithm"):
            raise SystemExit("Submission missing attack.py with AttackAlgorithm")
        if guard_mod is None or not hasattr(guard_mod, "Guardrail"):
            raise SystemExit("Submission missing guardrail.py with Guardrail")

        print("\n" + "=" * 70)
        print("EVALUATING OFFENSE (Your Attack vs Data-Flow Guardrail)")
        print("=" * 70)
        print(f"Agent selection: {agent_selection}")
        print(f"Env selection:   {env_selection}")
        attack_findings = eval_attack(
            attack_mod.AttackAlgorithm,
            offense_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
        )
        attack_summary = summarize_attack_findings(attack_findings)

        print("\n" + "=" * 70)
        print("EVALUATING DEFENSE (Baseline Attack vs Your Guardrail)")
        print("=" * 70)
        defense_report = eval_defense(
            guard_mod.Guardrail,
            defense_budget_s,
            agent_factory=agent_factory,
            env_selection=env_selection,
            fixtures_dir=fixtures_dir,
        )
        defense_score = score_defense(defense_report)

        final = attack_summary["score"] + defense_score
        breakdown = get_score_breakdown(attack_findings, defense_report)

        print("\n" + "=" * 70)
        print("FINAL RESULTS")
        print("=" * 70)
        print(
            f"Attack Score:  {attack_summary['score']:.2f} "
            f"(raw: {attack_summary['score_raw']:.2f}, mode: {breakdown['attack_mode']})"
        )
        print(f"Defense Score: {defense_score:.2f}")
        print(f"Final Score:   {final:.2f}")
        print("=" * 70)

        if args.verbose:
            print("\nDETAILED BREAKDOWN:")
            print(f"  Attack Findings: {attack_summary['findings_count']}")
            print(f"  Unique Cells: {attack_summary['unique_cells']}")
            print(f"  Defense Breaches: {defense_report.get('breach_count', 0)}")
            print(
                f"  False Positives: {defense_report.get('false_positives', 0)}/"
                f"{defense_report.get('benign_trials', 7)}"
            )
            print(
                "  False Positive Rate: "
                f"{defense_report.get('false_positives', 0) / max(1, defense_report.get('benign_trials', 7)):.2%}"
            )

        outp = Path(args.out)
        outp.write_text(f"{final}\n", encoding="utf-8")

        detailed_results = {
            "final_score": final,
            "attack": attack_summary,
            "defense": {
                "score": defense_score,
                "breach_count": defense_report.get("breach_count", 0),
                "false_positives": defense_report.get("false_positives", 0),
                "benign_trials": defense_report.get("benign_trials", 7),
                "false_positive_rate": defense_report.get("false_positives", 0)
                / max(1, defense_report.get("benign_trials", 7)),
            },
            "agent_selection": agent_selection.value,
            "env_selection": env_selection.value,
            "scoring_mode": breakdown["attack_mode"],
        }

        json_out = Path(args.out_json)
        json_out.write_text(json.dumps(detailed_results, indent=2), encoding="utf-8")

        print(f"\nResults written to: {outp}")
        print(f"Detailed results written to: {json_out}")


if __name__ == "__main__":
    main()
