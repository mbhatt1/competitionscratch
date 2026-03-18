#!/usr/bin/env python3
"""Compatibility shim for the maintained OpenAI attack demo runner."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import scripts.run_attack_openai as _impl

if TYPE_CHECKING:
    from aicomp_sdk.core.env import SandboxEnv


def _select_openai_demo_agent() -> str:
    """Return the demo agent selection used by the maintained script."""
    return _impl._select_openai_demo_agent()


def _build_demo_env(*, seed: int, fixtures_dir: Path) -> SandboxEnv:
    """Delegate demo environment construction to the maintained script."""
    return _impl._build_demo_env(seed=seed, fixtures_dir=fixtures_dir)


def main() -> None:
    """Run the maintained OpenAI attack demo."""
    _impl.main()


if __name__ == "__main__":
    main()
