from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


def _load_module(module_name: str, module_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_promptguard_example_caches_classifier_across_instances(monkeypatch) -> None:
    pipeline_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_pipeline(*args: Any, **kwargs: Any) -> Any:
        pipeline_calls.append((args, kwargs))
        return lambda text: [{"label": "BENIGN", "score": 0.0}]

    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace(pipeline=fake_pipeline))

    module_path = (
        Path(__file__).resolve().parents[2] / "examples" / "guardrails" / "guardrail_promptguard.py"
    )
    module = _load_module(
        "test_guardrail_promptguard_example",
        module_path,
    )

    guardrail_one = module.Guardrail()
    guardrail_two = module.Guardrail()

    assert len(pipeline_calls) == 0
    assert guardrail_one.classifier is None
    assert guardrail_two.classifier is None

    guardrail_one._scan_text("first check")
    guardrail_two._scan_text("second check")

    assert len(pipeline_calls) == 1
    assert guardrail_one.classifier is guardrail_two.classifier
