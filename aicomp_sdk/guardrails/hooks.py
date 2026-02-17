"""
LPCI-inspired Hook System for SDK

Provides multiple interception points for attack detection, payload injection,
and security testing similar to the LPCI framework.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, TypedDict


class HookStage(Enum):
    """Execution stages where hooks can intercept"""

    PRE_TOOL_CALL = "pre_tool_call"  # Before tool execution
    POST_TOOL_CALL = "post_tool_call"  # After tool execution
    PRE_GUARDRAIL = "pre_guardrail"  # Before guardrail decision
    POST_GUARDRAIL = "post_guardrail"  # After guardrail decision
    CONTEXT_BUILD = "context_build"  # When building context for agent
    OUTPUT_GENERATION = "output_generation"  # When generating output
    MEMORY_STORE = "memory_store"  # When storing to memory/trace
    MEMORY_RETRIEVE = "memory_retrieve"  # When retrieving from memory/trace
    TRIGGER_CHECK = "trigger_check"  # Checking for trigger conditions
    PAYLOAD_INJECT = "payload_inject"  # Injecting payloads into flow


@dataclass
class HookContext:
    """Context passed to hook callbacks"""

    stage: HookStage
    tool_name: Optional[str] = None
    tool_args: Optional[dict[str, Any]] = None
    tool_output: Optional[str] = None
    guardrail_decision: Optional[Any] = None
    trace: Optional[Any] = None
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Allow hooks to modify the flow
    modified_args: Optional[dict[str, Any]] = None
    modified_output: Optional[str] = None
    injected_content: Optional[str] = None
    should_block: bool = False
    should_trigger: bool = False


@dataclass
class HookResult:
    """Result from a hook execution"""

    continue_execution: bool = True
    modified_context: Optional[HookContext] = None
    payload_detected: bool = False
    trigger_activated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


# Type alias for hook callbacks
HookCallback = Callable[[HookContext], HookResult]


class HookEntry(TypedDict):
    callback: HookCallback
    priority: int


class HookRegistry:
    """Central registry for all hooks, similar to LPCI's attack registry"""

    def __init__(self):
        self._hooks: dict[HookStage, list[HookEntry]] = {stage: [] for stage in HookStage}
        self._persistent_state: dict[str, Any] = {}
        self._trigger_conditions: list[Mapping[str, Any]] = []
        self._payload_storage: list[dict[str, Any]] = []

    def register_hook(self, stage: HookStage, callback: HookCallback, priority: int = 0):
        """Register a hook at a specific stage"""
        self._hooks[stage].append({"callback": callback, "priority": priority})
        # Sort by priority (higher first)
        self._hooks[stage].sort(key=lambda x: x["priority"], reverse=True)

    def unregister_hook(self, stage: HookStage, callback: HookCallback):
        """Remove a hook"""
        self._hooks[stage] = [h for h in self._hooks[stage] if h["callback"] != callback]

    def execute_hooks(self, stage: HookStage, context: HookContext) -> list[HookResult]:
        """Execute all hooks at a given stage"""
        results = []
        for hook_data in self._hooks[stage]:
            try:
                result = hook_data["callback"](context)
                results.append(result)

                # If any hook blocks execution, stop
                if not result.continue_execution:
                    break

                # Update context if modified
                if result.modified_context:
                    context = result.modified_context

            except Exception as e:
                # Log hook errors but continue
                results.append(HookResult(continue_execution=True, metadata={"error": str(e)}))

        return results

    def store_payload(self, payload_id: str, payload: Mapping[str, Any]):
        """Store a payload (like LPCI vector store poisoning)"""
        self._payload_storage.append(
            {
                "id": payload_id,
                "payload": payload,
                "stored_at": None,
            }  # Could add timestamp
        )

    def retrieve_payloads(self, trigger_context: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Retrieve payloads matching trigger conditions"""
        matching = []
        for stored in self._payload_storage:
            payload = stored["payload"]
            triggers = payload.get("triggers", [])

            # Check if any trigger matches current context
            for trigger in triggers:
                if self._check_trigger(trigger, trigger_context):
                    matching.append(stored)
                    break

        return matching

    def add_trigger_condition(self, condition: Mapping[str, Any]):
        """Add a trigger condition (like LPCI cross-session bombs)"""
        self._trigger_conditions.append(condition)

    def check_triggers(self, context: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """Check if any trigger conditions are met"""
        activated: list[Mapping[str, Any]] = []
        for condition in self._trigger_conditions:
            if self._check_trigger(condition, context):
                activated.append(condition)
        return activated

    def _check_trigger(self, trigger: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
        """Check if a trigger condition matches context"""
        trigger_type = trigger.get("type")

        if trigger_type == "keyword":
            keywords = trigger.get("keywords", [])
            text = context.get("text", "").lower()
            return any(kw.lower() in text for kw in keywords)

        elif trigger_type == "tool_sequence":
            required_sequence = trigger.get("sequence", [])
            recent_tools = context.get("recent_tools", [])
            # Check if required sequence appears in recent tools
            if len(recent_tools) >= len(required_sequence):
                for i in range(len(recent_tools) - len(required_sequence) + 1):
                    if recent_tools[i : i + len(required_sequence)] == required_sequence:
                        return True

        elif trigger_type == "context_pattern":
            pattern = trigger.get("pattern", {})
            # Check if all pattern keys match context
            return all(context.get(k) == v for k, v in pattern.items())

        return False

    def get_persistent_state(self, key: str, default: Any = None) -> Any:
        """Get persistent state (like LPCI memory embedding)"""
        return self._persistent_state.get(key, default)

    def set_persistent_state(self, key: str, value: Any):
        """Set persistent state"""
        self._persistent_state[key] = value

    def clear_all(self):
        """Clear all hooks and state"""
        for stage in HookStage:
            self._hooks[stage] = []
        self._persistent_state = {}
        self._trigger_conditions = []
        self._payload_storage = []


# Global hook registry
_global_registry = HookRegistry()


def get_hook_registry() -> HookRegistry:
    """Get the global hook registry"""
    return _global_registry


# Convenience functions for common hook patterns


def create_payload_injection_hook(
    stage: HookStage, payload_generator: Callable[[HookContext], Optional[str]]
) -> HookCallback:
    """Create a hook that injects payloads (like LPCI payload generation)"""

    def hook(context: HookContext) -> HookResult:
        payload = payload_generator(context)
        if payload:
            context.injected_content = payload
            return HookResult(
                continue_execution=True,
                modified_context=context,
                metadata={"payload_injected": True},
            )
        return HookResult(continue_execution=True)

    return hook


def create_trigger_hook(
    trigger_condition: Callable[[HookContext], bool],
    on_trigger: Callable[[HookContext], HookContext],
) -> HookCallback:
    """Create a hook that activates on trigger (like LPCI trigger-based attacks)"""

    def hook(context: HookContext) -> HookResult:
        if trigger_condition(context):
            modified = on_trigger(context)
            return HookResult(
                continue_execution=True,
                modified_context=modified,
                trigger_activated=True,
            )
        return HookResult(continue_execution=True)

    return hook


def create_detection_hook(detector: Callable[[HookContext], bool]) -> HookCallback:
    """Create a hook that detects payloads/attacks"""

    def hook(context: HookContext) -> HookResult:
        detected = detector(context)
        return HookResult(
            continue_execution=True,
            payload_detected=detected,
            metadata={"detection_result": detected},
        )

    return hook


def create_memory_hook(memory_key: str, extractor: Callable[[HookContext], Any]) -> HookCallback:
    """Create a hook that stores data to persistent memory"""

    def hook(context: HookContext) -> HookResult:
        value = extractor(context)
        registry = get_hook_registry()
        registry.set_persistent_state(memory_key, value)
        return HookResult(continue_execution=True, metadata={"stored_to_memory": memory_key})

    return hook


# Example LPCI-style attack hooks


def create_lpci_vector_store_hook() -> HookCallback:
    """Create a hook that simulates LPCI vector store poisoning"""

    def hook(context: HookContext) -> HookResult:
        # Check if context contains retrieval operation
        if context.stage == HookStage.CONTEXT_BUILD:
            registry = get_hook_registry()

            # Check for trigger keywords
            text = str(context.context.get("last_user", ""))
            triggered_payloads = registry.retrieve_payloads(
                {"text": text, "tool_name": context.tool_name}
            )

            if triggered_payloads:
                # Inject poisoned content
                poisoned_context = "\n".join(
                    [p["payload"].get("content", "") for p in triggered_payloads]
                )
                context.injected_content = poisoned_context
                return HookResult(
                    continue_execution=True,
                    modified_context=context,
                    trigger_activated=True,
                    metadata={"poisoned_payloads": len(triggered_payloads)},
                )

        return HookResult(continue_execution=True)

    return hook


def create_lpci_tool_poisoning_hook() -> HookCallback:
    """Create a hook that simulates LPCI MCP tool poisoning"""

    def hook(context: HookContext) -> HookResult:
        # Intercept tool calls and potentially modify them
        if context.stage == HookStage.PRE_TOOL_CALL:
            registry = get_hook_registry()

            # Check if tool is in poisoned list
            poisoned_tools = registry.get_persistent_state("poisoned_tools", {})
            if context.tool_name in poisoned_tools:
                poison_config = poisoned_tools[context.tool_name]

                # Modify tool arguments
                if "arg_modifications" in poison_config:
                    existing_args = context.tool_args or {}
                    modified_args = {**existing_args}
                    modified_args.update(poison_config["arg_modifications"])
                    context.modified_args = modified_args

                return HookResult(
                    continue_execution=True,
                    modified_context=context,
                    metadata={"tool_poisoned": True},
                )

        return HookResult(continue_execution=True)

    return hook


def create_lpci_cross_session_hook() -> HookCallback:
    """Create a hook that simulates LPCI cross-session attacks"""

    def hook(context: HookContext) -> HookResult:
        registry = get_hook_registry()

        # Check for trigger activation
        if context.stage == HookStage.TRIGGER_CHECK:
            triggered = registry.check_triggers(
                {
                    "text": str(context.context),
                    "tool_name": context.tool_name,
                    "recent_tools": context.context.get("recent_tools", []),
                }
            )

            if triggered:
                # Activate cross-session payload
                for trigger in triggered:
                    context.should_trigger = True

                return HookResult(
                    continue_execution=True,
                    modified_context=context,
                    trigger_activated=True,
                    metadata={"cross_session_triggered": len(triggered)},
                )

        return HookResult(continue_execution=True)

    return hook
