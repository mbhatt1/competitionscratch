from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aicomp_sdk.cli.commands.validate import run_validate, validate_imports
from aicomp_sdk.cli.main import create_parser


def test_validate_imports_rejects_unknown_sdk_symbol(tmp_path: Path) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(
        "from aicomp_sdk import AttackAlgoritmBase\n",
        encoding="utf-8",
    )

    valid, issues = validate_imports(submission)

    assert valid is False
    assert issues == ["Could not resolve import: AttackAlgoritmBase from aicomp_sdk"]


def test_validate_imports_accepts_sdk_submodule_imports(tmp_path: Path) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(
        "from aicomp_sdk.evaluation import ops\n",
        encoding="utf-8",
    )

    valid, issues = validate_imports(submission)

    assert valid is True
    assert issues == []


def test_create_parser_accepts_validate_track_subcommand() -> None:
    parser = create_parser()

    args = parser.parse_args(["validate", "redteam", "attack.py"])

    assert args.command == "validate"
    assert args.track == "redteam"
    assert args.file == "attack.py"


def test_create_parser_rejects_legacy_validate_shape() -> None:
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["validate", "attack.py"])

    assert exc_info.value.code == 2


def test_run_validate_fails_on_unresolved_imports(tmp_path: Path) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(
        "from aicomp_sdk import DoesNotExist\n"
        "from aicomp_sdk.attacks import AttackAlgorithmBase\n\n"
        "class AttackAlgorithm(AttackAlgorithmBase):\n"
        "    def run(self, env, config):\n"
        "        return []\n",
        encoding="utf-8",
    )

    status = run_validate(
        SimpleNamespace(
            track="redteam",
            file=str(submission),
        )
    )

    assert status == 1
