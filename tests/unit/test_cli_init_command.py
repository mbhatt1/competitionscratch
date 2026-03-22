from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aicomp_sdk.cli.commands.init import run_init


@pytest.mark.parametrize(
    ("submission_type", "expected_track"),
    [
        ("attack", "redteam"),
        ("guardrail", "defense"),
    ],
)
def test_run_init_prints_track_aware_validate_next_step(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    submission_type: str,
    expected_track: str,
) -> None:
    output_path = tmp_path / f"{submission_type}.py"

    status = run_init(
        SimpleNamespace(
            type=submission_type,
            output=str(output_path),
            force=False,
        )
    )

    assert status == 0
    assert output_path.exists()

    stdout = capsys.readouterr().out

    assert (
        f"  2. Validate your submission: aicomp validate {expected_track} {output_path}"
        in stdout
    )
    assert f"  3. Test your submission: aicomp test {expected_track} {output_path} --budget-s 60" in stdout
