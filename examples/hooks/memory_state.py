"""Stateful MEMORY_STORE hook fixture for local SandboxEnv experiments."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aicomp_sdk.hooks import HookContext, HookRegistry, HookResult, HookStage  # noqa: E402


def _track_sensitive_access(context: HookContext) -> HookResult:
    if context.tool_name not in {"fs.read", "email.read"}:
        return HookResult(continue_execution=True)

    access_log = context.hook_state.get("sensitive_access_log", [])
    access_log.append(
        {
            "tool": context.tool_name,
            "args": context.tool_args,
            "trace_length": len(context.trace.tool_events) if context.trace else 0,
        }
    )
    context.hook_state["sensitive_access_log"] = access_log
    return HookResult(
        continue_execution=True,
        metadata={"tracked_sensitive_accesses": len(access_log)},
    )


def build_hook_registry(registry: HookRegistry | None = None) -> HookRegistry:
    registry = registry or HookRegistry()
    registry.register_hook(HookStage.MEMORY_STORE, _track_sensitive_access, priority=10)
    return registry


if __name__ == "__main__":
    build_hook_registry()
    print("Memory-state hook registered for fs.read and email.read")
