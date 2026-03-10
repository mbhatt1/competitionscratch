"""
Main CLI entry point for aicomp_sdk.

Provides subcommands for common operations on competition submissions.
"""

import argparse
import sys
from typing import Callable, Optional, TextIO

from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.core.env_api import EnvSelection

# Try to import rich for beautiful output, fall back to plain output.
RICH_PRINT: Optional[Callable[[str], None]]
try:
    from rich.console import Console

    RICH_PRINT = Console().print
except ImportError:
    RICH_PRINT = None


def _print_message(
    icon: str,
    color: str,
    message: str,
    *,
    fallback_file: Optional[TextIO] = None,
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


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="aicomp",
        description="AI Agent Security Competition CLI - Tools for creating and testing submissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aicomp init attack              # Create attack template
  aicomp init guardrail           # Create guardrail template
  aicomp validate attack.py       # Validate attack submission
  aicomp test attack.py           # Run Kaggle-style red-team evaluation
  aicomp test submission.zip      # Run legacy local dual-track evaluation
  aicomp test attack.py --env sandbox  # Run attack-only eval on SandboxEnv
  aicomp test --quick attack.py   # Quick red-team smoke test
  aicomp history                  # Show past results
  aicomp compare run1 run2        # Compare two runs
  aicomp visualize latest         # Generate charts

For more help on a command: aicomp <command> --help
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Init command
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

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate submission file",
        description="Fast validation (<5s) to check submission structure and imports",
    )
    validate_parser.add_argument("file", help="Path to submission file (attack.py or guardrail.py)")
    validate_parser.add_argument(
        "--type",
        choices=["attack", "guardrail", "auto"],
        default="auto",
        help="Submission type (default: auto-detect)",
    )

    # Test command
    test_parser = subparsers.add_parser(
        "test",
        help="Run evaluation tests",
        description="Evaluate submission with progress tracking and save results",
    )
    test_parser.add_argument("submission", help="Path to submission file or zip")
    test_parser.add_argument(
        "--budget-s",
        type=float,
        default=3600.0,
        help="Total evaluation budget in seconds (default: 3600)",
    )
    test_parser.add_argument(
        "--track",
        choices=["auto", "redteam", "dual", "defense"],
        default="auto",
        help="Evaluation track (default: auto-detect from submission type)",
    )
    test_parser.add_argument(
        "--fixtures_dir",
        default=None,
        help=(
            "Optional fixtures root override. Defaults to AICOMP_FIXTURES_DIR, then packaged "
            "fixtures, then legacy repo fixtures."
        ),
    )
    test_parser.add_argument(
        "--agent",
        choices=[member.value for member in AgentSelection],
        default="auto",
        help="Blue-agent selection policy for evaluation runs (default: auto)",
    )
    test_parser.add_argument(
        "--env",
        choices=[member.value for member in EnvSelection],
        default=None,
        help=(
            "Attack environment selection. Defaults to gym for redteam, sandbox for dual "
            "and defense."
        ),
    )
    test_parser.add_argument(
        "--quick", action="store_true", help="Quick test with reduced time budget"
    )
    test_parser.add_argument("--name", help="Name for this test run (default: auto-generated)")
    test_parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    # Compare command
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

    # History command
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

    # Visualize command
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
        choices=["png", "html", "both"],
        default="png",
        help="Output format (default: png)",
    )

    return parser


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    try:
        # Import command modules lazily to avoid unnecessary imports
        if args.command == "init":
            from aicomp_sdk.cli.commands.init import run_init

            return run_init(args)

        elif args.command == "validate":
            from aicomp_sdk.cli.commands.validate import run_validate

            return run_validate(args)

        elif args.command == "test":
            from aicomp_sdk.cli.commands.test import run_test

            return run_test(args)

        elif args.command == "compare":
            from aicomp_sdk.cli.commands.compare import run_compare

            return run_compare(args)

        elif args.command == "history":
            from aicomp_sdk.cli.commands.history import run_history

            return run_history(args)

        elif args.command == "visualize":
            from aicomp_sdk.cli.commands.visualize import run_visualize

            return run_visualize(args)

        else:
            print_error(f"Unknown command: {args.command}")
            return 1

    except KeyboardInterrupt:
        print_warning("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print_error(f"Error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
