"""
Main CLI entry point for aicomp_sdk.

Provides subcommands for common operations on competition submissions.
"""

from __future__ import annotations

import argparse
import sys
from textwrap import dedent
from typing import Callable, Final, TextIO

from aicomp_sdk.evaluation.diagnostics import EvaluatorVerbosity
from aicomp_sdk.evaluation.tracks import EvaluationTrack


def _load_rich_print() -> Callable[[str], None] | None:
    """Return a rich-backed print function when rich is available."""

    try:
        from rich.console import Console
    except ImportError:
        return None
    return Console().print


# Try to import rich for beautiful output, fall back to plain output.
RICH_PRINT: Final[Callable[[str], None] | None] = _load_rich_print()


CLI_EPILOG: Final[str] = dedent("""\
    Examples:
      Create attack template:
        aicomp init attack

      Create guardrail template:
        aicomp init guardrail

      Validate attack submission:
        aicomp validate redteam attack.py

      Run scorer-style evaluation and write artifacts:
        aicomp evaluate redteam attack.py

      Run local dual-track evaluation and save history:
        aicomp test dual submission.zip

      Show past results:
        aicomp history

      Compare two runs:
        aicomp compare run1 run2

      Generate charts:
        aicomp visualize latest

    For more help on a command: aicomp <command> --help

    Command choice:
      Use `aicomp evaluate` for scorer-style runs and stable machine-readable artifacts.
      Use `aicomp test` for local iteration with saved history, compare, and visualize.
    """)


def _print_message(
    icon: str,
    color: str,
    message: str,
    *,
    fallback_file: TextIO | None = None,
) -> None:
    """Print with rich formatting when available, else plain text."""
    if RICH_PRINT is not None:
        RICH_PRINT(f"[{color}]{icon}[/{color}] {message}")
        return

    print(f"{icon} {message}", file=fallback_file)


def print_success(message: str) -> None:
    """Print success message with color."""
    _print_message("✓", "green", message)


def print_error(message: str) -> None:
    """Print error message with color."""
    _print_message("✗", "red", message, fallback_file=sys.stderr)


def print_info(message: str) -> None:
    """Print info message with color."""
    _print_message("ℹ", "blue", message)


def print_warning(message: str) -> None:
    """Print warning message with color."""
    _print_message("⚠", "yellow", message)


def _add_init_parser(subparsers: argparse._SubParsersAction) -> None:
    init_parser = subparsers.add_parser(
        "init",
        help="Create submission templates",
        description="Initialize a new attack or guardrail submission from template",
    )
    init_parser.add_argument(
        "type", choices=["attack", "guardrail"], help="Type of submission to create"
    )
    init_parser.add_argument(
        "-o", "--output", help="Output file path (default: attack.py or guardrail.py)"
    )
    init_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing file")


def _add_validate_parser(subparsers: argparse._SubParsersAction) -> None:
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate submission file",
        description="Fast validation (<5s) to check submission structure and imports",
    )
    validate_subparsers = validate_parser.add_subparsers(dest="track", required=True)

    validate_redteam_parser = validate_subparsers.add_parser(
        EvaluationTrack.REDTEAM.value,
        help="Validate a Python attack module that defines AttackAlgorithm.",
    )
    validate_redteam_parser.add_argument(
        "file",
        help="Path to a Python attack module.",
    )

    validate_defense_parser = validate_subparsers.add_parser(
        EvaluationTrack.DEFENSE.value,
        help="Validate a Python guardrail module that defines Guardrail.",
    )
    validate_defense_parser.add_argument(
        "file",
        help="Path to a Python guardrail module.",
    )

    validate_dual_parser = validate_subparsers.add_parser(
        EvaluationTrack.DUAL.value,
        help="Validate a submission zip containing attack.py and guardrail.py.",
    )
    validate_dual_parser.add_argument(
        "file",
        help="Path to a submission zip containing attack.py and guardrail.py.",
    )


def _add_compare_parser(subparsers: argparse._SubParsersAction) -> None:
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare evaluation results",
        description="Compare two evaluation runs side-by-side",
    )
    compare_parser.add_argument("run1", help="First run name or path")
    compare_parser.add_argument("run2", help="Second run name or path")
    compare_parser.add_argument(
        "--metric",
        choices=["all", "attack", "defense", "final"],
        default="all",
        help="Which metrics to compare (default: all)",
    )


def _add_history_parser(subparsers: argparse._SubParsersAction) -> None:
    history_parser = subparsers.add_parser(
        "history",
        help="Show evaluation history",
        description="List past evaluation results with scores and timestamps",
    )
    history_parser.add_argument(
        "--limit", type=int, default=10, help="Number of results to show (default: 10)"
    )
    history_parser.add_argument(
        "--sort",
        choices=["date", "score", "name"],
        default="date",
        help="Sort order (default: date)",
    )
    history_parser.add_argument("--filter", help="Filter by submission name")


def _add_visualize_parser(subparsers: argparse._SubParsersAction) -> None:
    visualize_parser = subparsers.add_parser(
        "visualize",
        help="Generate visualizations",
        description="Create charts and graphs from evaluation results",
    )
    visualize_parser.add_argument("run", help='Run name or "latest" for most recent')
    visualize_parser.add_argument(
        "--output",
        help="Output directory for charts (default: .aicomp/visualizations/)",
    )
    visualize_parser.add_argument(
        "--format",
        choices=["png", "markdown", "both"],
        default="png",
        help="Output format (default: png)",
    )


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="aicomp",
        description="AI Agent Security Competition CLI - Tools for creating and testing submissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CLI_EPILOG,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    _add_init_parser(subparsers)
    _add_validate_parser(subparsers)

    from aicomp_sdk.cli.commands.evaluate import add_evaluate_parser
    from aicomp_sdk.cli.commands.test import add_test_parser

    add_evaluate_parser(subparsers)
    add_test_parser(subparsers)
    _add_compare_parser(subparsers)
    _add_history_parser(subparsers)
    _add_visualize_parser(subparsers)
    return parser


def _run_command(args: argparse.Namespace) -> int:
    match args.command:
        case "init":
            from aicomp_sdk.cli.commands.init import run_init

            return run_init(args)
        case "validate":
            from aicomp_sdk.cli.commands.validate import run_validate

            return run_validate(args)
        case "test":
            from aicomp_sdk.cli.commands.test import run_test

            return run_test(args)
        case "evaluate":
            from aicomp_sdk.cli.commands.evaluate import run_evaluate

            return run_evaluate(args)
        case "compare":
            from aicomp_sdk.cli.commands.compare import run_compare

            return run_compare(args)
        case "history":
            from aicomp_sdk.cli.commands.history import run_history

            return run_history(args)
        case "visualize":
            from aicomp_sdk.cli.commands.visualize import run_visualize

            return run_visualize(args)
        case _:
            print_error(f"Unknown command: {args.command}")
            return 1


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    try:
        return _run_command(args)
    except KeyboardInterrupt:
        print_warning("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print_error(f"Error: {e}")
        if getattr(args, "verbosity", None) is EvaluatorVerbosity.DEBUG:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
