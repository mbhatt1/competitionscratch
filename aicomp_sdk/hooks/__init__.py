"""Public hook APIs for harness-owned compromised-environment fixtures."""

from aicomp_sdk.hooks.helpers import (
    create_detection_hook,
    create_memory_hook,
    create_payload_injection_hook,
    create_trigger_hook,
)
from aicomp_sdk.hooks.lpci import (
    create_lpci_tool_poisoning_hook,
    create_lpci_vector_store_hook,
)
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import (
    HookCallback,
    HookContext,
    HookResult,
    HookStage,
)

__all__ = [
    "HookCallback",
    "HookContext",
    "HookRegistry",
    "HookResult",
    "HookStage",
    "create_detection_hook",
    "create_lpci_tool_poisoning_hook",
    "create_lpci_vector_store_hook",
    "create_memory_hook",
    "create_payload_injection_hook",
    "create_trigger_hook",
]
