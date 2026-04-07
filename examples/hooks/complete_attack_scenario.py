"""Compose multiple hook fixtures into one local compromised-environment profile."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aicomp_sdk.hooks import HookRegistry  # noqa: E402

from examples.hooks.memory_state import build_hook_registry as add_memory_state  # noqa: E402
from examples.hooks.tool_arg_rewrite import (  # noqa: E402
    build_hook_registry as add_tool_arg_rewrite,
)
from examples.hooks.triggered_guardrail_context import (  # noqa: E402
    build_hook_registry as add_triggered_guardrail_context,
)
from examples.hooks.vector_store_poisoning import (  # noqa: E402
    build_hook_registry as add_vector_store_poisoning,
)


def build_hook_registry() -> HookRegistry:
    registry = HookRegistry()
    for builder in (
        add_vector_store_poisoning,
        add_tool_arg_rewrite,
        add_triggered_guardrail_context,
        add_memory_state,
    ):
        builder(registry)
    return registry


if __name__ == "__main__":
    build_hook_registry()
    print("Complete attack-scenario hook registry assembled")
