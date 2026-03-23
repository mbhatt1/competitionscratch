"""Shared CLI option helpers for evaluation command profiles."""

from __future__ import annotations

import argparse
import math

from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.diagnostics import EvaluatorVerbosity


def parse_positive_seconds(value: str) -> float:
    """Parse a strictly positive finite second count."""
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(
            "time budget must be a finite number greater than 0 seconds"
        )
    return seconds


def add_shared_execution_arguments(
    parser: argparse.ArgumentParser,
    *,
    budget_default: float | None,
    budget_help: str,
    agent_help: str,
    env_help: str,
    fixtures_help: str,
    verbosity_help: str,
) -> None:
    """Add the common execution knobs shared by `evaluate` and `test`."""
    parser.add_argument(
        "--budget-s",
        type=parse_positive_seconds,
        default=budget_default,
        help=budget_help,
    )
    parser.add_argument(
        "--agent",
        type=AgentSelection,
        default=AgentSelection.AUTO,
        choices=list(AgentSelection),
        help=agent_help,
    )
    parser.add_argument(
        "--env",
        type=EnvSelection,
        default=EnvSelection.SANDBOX,
        choices=list(EnvSelection),
        help=env_help,
    )
    parser.add_argument(
        "--fixtures-dir",
        type=str,
        default=None,
        help=fixtures_help,
    )
    parser.add_argument(
        "--verbosity",
        type=EvaluatorVerbosity,
        default=EvaluatorVerbosity.SUMMARY,
        choices=list(EvaluatorVerbosity),
        help=verbosity_help,
    )
