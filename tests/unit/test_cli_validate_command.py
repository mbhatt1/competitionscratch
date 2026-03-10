from __future__ import annotations

from pathlib import Path

from aicomp_sdk.cli.commands.validate import validate_imports


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
        "from aicomp_sdk import evaluation_core\n",
        encoding="utf-8",
    )

    valid, issues = validate_imports(submission)

    assert valid is True
    assert issues == []
