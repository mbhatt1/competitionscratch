from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

from aicomp_sdk.cli.commands.compare import compare_metrics
from aicomp_sdk.cli.commands.history import print_results_table
from aicomp_sdk.cli.commands.visualize import (
    create_markdown_report,
    create_matplotlib_visualizations,
)


def _attack_only_result() -> dict[str, object]:
    return {
        "run_name": "attack_only",
        "timestamp": "2026-03-15T12:00:00",
        "track": "redteam",
        "attack": {
            "evaluated": True,
            "score": 12.5,
            "score_raw": 4.0,
            "findings_count": 2,
            "unique_cells": 2,
            "time_taken": 0.1,
        },
        "defense": {
            "evaluated": False,
            "score": None,
            "breach_count": None,
            "false_positives": None,
            "benign_trials": None,
            "false_positive_rate": None,
            "time_taken": None,
        },
        "final_score": 12.5,
        "submission_type": "attack_only",
        "scoring_mode": "normalized",
    }


def _defense_only_result() -> dict[str, object]:
    return {
        "run_name": "defense_only",
        "timestamp": "2026-03-15T12:00:00",
        "track": "defense",
        "attack": {
            "evaluated": False,
            "score": None,
            "score_raw": None,
            "findings_count": None,
            "unique_cells": None,
            "time_taken": None,
        },
        "defense": {
            "evaluated": True,
            "score": 900.0,
            "breach_count": 0,
            "false_positives": 0,
            "benign_trials": 7,
            "false_positive_rate": 0.0,
            "time_taken": 0.1,
        },
        "final_score": 900.0,
        "submission_type": "guardrail_only",
    }


def test_history_prints_na_for_non_evaluated_metrics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_results_table([_attack_only_result()])

    output = capsys.readouterr().out
    assert "attack_only" in output
    assert "12.50" in output
    assert "N/A" in output


def test_compare_marks_non_evaluated_metrics_as_not_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    compare_metrics(_attack_only_result(), _defense_only_result(), "all")

    output = capsys.readouterr().out
    assert "Attack Metrics:" in output
    assert "Defense Metrics:" in output
    assert "N/A" in output
    assert "not run" in output


@pytest.mark.parametrize(
    ("result_factory", "expected_row", "forbidden_text"),
    [
        (
            _attack_only_result,
            "| Defense Score | N/A |",
            "Perfect defense",
        ),
        (
            _defense_only_result,
            "| Attack Score | N/A |",
            "No security violations found.",
        ),
    ],
)
def test_markdown_report_marks_non_evaluated_track(
    tmp_path: Path,
    result_factory,
    expected_row: str,
    forbidden_text: str,
) -> None:
    output_path = tmp_path / "report.md"

    create_markdown_report(result_factory(), output_path)

    report = output_path.read_text(encoding="utf-8")
    assert expected_row in report
    assert "Not evaluated in this run." in report
    assert forbidden_text not in report


class _FakeBar:
    def __init__(self, height: float, x: float) -> None:
        self._height = height
        self._x = x

    def get_height(self) -> float:
        return self._height

    def get_x(self) -> float:
        return self._x

    def get_width(self) -> float:
        return 0.8


class _FakeAxis:
    def __init__(self) -> None:
        self.transAxes = object()
        self.titles: list[str] = []
        self.axis_calls: list[str] = []
        self.text_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def bar(self, labels, values, **kwargs):  # noqa: ANN001, ANN202
        del labels, kwargs
        return [_FakeBar(float(value), float(index)) for index, value in enumerate(values)]

    def barh(self, labels, values, **kwargs):  # noqa: ANN001, ANN202
        del labels, kwargs
        return [_FakeBar(float(value), float(index)) for index, value in enumerate(values)]

    def set_ylabel(self, value: str) -> None:
        del value

    def set_title(self, value: str) -> None:
        self.titles.append(value)

    def set_ylim(self, lower: float, upper: float) -> None:
        del lower, upper

    def set_xlim(self, lower: float, upper: float) -> None:
        del lower, upper

    def set_xlabel(self, value: str) -> None:
        del value

    def text(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        self.text_calls.append((args, kwargs))

    def axis(self, value: str) -> None:
        self.axis_calls.append(value)


class _FakeAxesGrid:
    def __init__(self, axes_matrix: list[list[_FakeAxis]]) -> None:
        self._axes_matrix = axes_matrix

    def __getitem__(self, key):  # noqa: ANN001, ANN201
        row, col = key
        return self._axes_matrix[row][col]


class _FakeFigure:
    def suptitle(self, title: str, **kwargs) -> None:  # noqa: ANN003
        del title, kwargs


class _FakePyplot(ModuleType):
    def __init__(self) -> None:
        super().__init__("matplotlib.pyplot")
        self.axes_matrix = [
            [_FakeAxis(), _FakeAxis()],
            [_FakeAxis(), _FakeAxis()],
        ]
        self.saved_paths: list[Path] = []

    def subplots(self, rows: int, cols: int, figsize=None):  # noqa: ANN001, ANN201
        del rows, cols, figsize
        return _FakeFigure(), _FakeAxesGrid(self.axes_matrix)

    def tight_layout(self) -> None:
        pass

    def savefig(self, path, **kwargs) -> None:  # noqa: ANN001, ANN003
        del kwargs
        output_path = Path(path)
        output_path.write_text("fake image", encoding="utf-8")
        self.saved_paths.append(output_path)

    def close(self) -> None:
        pass


class _FakeMatplotlib(ModuleType):
    def __init__(self) -> None:
        super().__init__("matplotlib")

    def use(self, backend: str) -> None:
        del backend


def test_matplotlib_visualizations_mark_non_evaluated_axes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake_matplotlib = _FakeMatplotlib()
    fake_pyplot = _FakePyplot()
    monkeypatch.setitem(sys.modules, "matplotlib", fake_matplotlib)
    monkeypatch.setitem(sys.modules, "matplotlib.pyplot", fake_pyplot)

    assert create_matplotlib_visualizations(_attack_only_result(), tmp_path) is True

    score_panel_text = fake_pyplot.axes_matrix[0][0].text_calls[0][0][2]
    defense_panel_text = fake_pyplot.axes_matrix[1][0].text_calls[0][0][2]
    assert "Only Attack track evaluated" in score_panel_text
    assert "Not evaluated in this run." in defense_panel_text
    assert fake_pyplot.axes_matrix[1][0].axis_calls == ["off"]
    assert fake_pyplot.saved_paths == [tmp_path / "evaluation_charts.png"]
