"""Prompt-Guard-backed example adapted to the current guardrail contract.

The runtime currently passes `last_user`, recent tool/source history, and the
pending tool call metadata into `decide(...)`. It does not pass raw tool
outputs directly. This example therefore uses Prompt-Guard to score the latest
user turn and, for dangerous sink calls, the pending tool arguments.

This is intentionally a heavyweight example: the first scan loads model weights
via `transformers`, so it starts much more slowly than the rule-based examples.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    from aicomp_sdk.guardrails.base import Decision, GuardrailBase


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in (current.parent, *current.parents):
        if (parent / "aicomp_sdk").is_dir():
            return parent
    return current.parent


_REPO_ROOT = _repo_root()


def _load_sdk_types():
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    from aicomp_sdk.guardrails.base import Decision, GuardrailBase

    return Decision, GuardrailBase


if not TYPE_CHECKING:
    Decision, GuardrailBase = _load_sdk_types()


class _TextClassifier(Protocol):
    def __call__(self, text: str) -> list[dict[str, Any]] | dict[str, Any]: ...


@lru_cache(maxsize=1)
def _load_promptguard_classifier() -> _TextClassifier:
    try:
        from transformers import pipeline

        print("[PROMPT-GUARD] Loading meta-llama/Prompt-Guard-86M model...")
        classifier = pipeline(
            "text-classification",
            model="meta-llama/Prompt-Guard-86M",
            device=-1,
        )
        print("[PROMPT-GUARD] Model loaded successfully")
        return cast(_TextClassifier, classifier)
    except ImportError:
        print("[PROMPT-GUARD] ERROR: transformers library not installed")
        print("[PROMPT-GUARD] Install with: pip install transformers torch")
        raise
    except Exception as err:
        print(f"[PROMPT-GUARD] ERROR loading model: {err}")
        raise


class Guardrail(GuardrailBase):
    """Use Prompt-Guard with a cached classifier and per-instance session state."""

    def __init__(self) -> None:
        super().__init__()
        self.classifier: _TextClassifier | None = None
        self.dangerous_tools = {
            "fs.delete",
            "fs.write",
            "shell.run",
            "http.post",
            "email.send",
        }

    def _scan_text(self, text: str, threshold: float = 0.5) -> tuple[bool, str, float]:
        classifier = self.classifier
        if classifier is None:
            classifier = _load_promptguard_classifier()
            self.classifier = classifier

        try:
            text_to_scan = text[:2000] if len(text) > 2000 else text
            result = classifier(text_to_scan)
            if isinstance(result, list):
                if not result:
                    return False, "EMPTY", 0.0
                result = result[0]

            label = result.get("label", "BENIGN")
            score = result.get("score", 0.0)
            is_malicious = label in {"INJECTION", "JAILBREAK"} and score >= threshold
            return is_malicious, label, score
        except Exception as err:
            print(f"[PROMPT-GUARD] Error scanning text: {err}")
            return False, "ERROR", 0.0

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        last_user = str(context.get("last_user") or "")
        if last_user:
            is_malicious, label, score = self._scan_text(last_user, threshold=0.5)
            if is_malicious:
                print(f"[PROMPT-GUARD] BLOCKED user message: {label} ({score:.2%})")
                return Decision.deny(f"User message contains a {label.lower()} attempt")

        recent_sources = context.get("recent_sources", [])
        tainted = any(src in {"web", "email"} for src in recent_sources)
        if tainted and tool_name in self.dangerous_tools:
            args_text = json.dumps(tool_args, sort_keys=True, default=str)
            is_malicious, label, score = self._scan_text(args_text, threshold=0.6)
            if is_malicious:
                print(f"[PROMPT-GUARD] BLOCKED {tool_name} args after {label} detection")
                print(f"[PROMPT-GUARD] Confidence: {score:.2%}")
                return Decision.deny(
                    f"Dangerous action {tool_name} blocked after {label.lower()}-like content"
                )

        return Decision.allow("ok")
