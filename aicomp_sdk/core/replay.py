from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .env.sandbox import SandboxEnv


class ReplayHarness:
    """Replay user messages against a fresh sandboxed environment."""

    def __init__(self, fixtures_dir: str | Path):
        self.fixtures_dir = Path(fixtures_dir) if isinstance(fixtures_dir, str) else fixtures_dir

    def replay(self, seed: int, user_messages: Iterable[str], agent, guardrail) -> dict[str, Any]:
        """Run the messages through a new `SandboxEnv` and return its trace dict."""

        env = SandboxEnv(
            seed=seed, fixtures_dir=self.fixtures_dir, agent=agent, guardrail=guardrail
        )
        env.reset()
        for um in user_messages:
            env.interact(um)
        trace: dict[str, Any] = env.export_trace_dict()
        return trace
