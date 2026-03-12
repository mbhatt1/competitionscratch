from __future__ import annotations

import copy
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional

from ..agents.protocol import AgentProtocol
from ..guardrails.base import GuardrailBase
from ..guardrails.hooks import HookContext, HookRegistry, HookStage, get_hook_registry
from .env_api import DEFAULT_MAX_TOOL_HOPS, MAX_USER_MESSAGE_CHARS
from .tools import ToolSuite
from .trace import ToolEvent, Trace


class SandboxEnv:
    def __init__(
        self,
        seed: int,
        fixtures_dir: Path,
        agent: AgentProtocol,
        guardrail: Optional[GuardrailBase] = None,
        hook_registry: Optional[HookRegistry] = None,
    ) -> None:
        self.seed = int(seed)
        self.fixtures_dir = Path(fixtures_dir)
        self.tools = ToolSuite(self.fixtures_dir, isolate_fs=True)
        self.guardrail = guardrail or GuardrailBase()
        self.trace = Trace(seed=self.seed)
        self._last_tool_output: Optional[str] = None
        self.hook_registry = hook_registry or get_hook_registry()
        self.agent = agent

    def reset(self) -> None:
        self.tools.reset(self.seed)
        self.trace = Trace(seed=self.seed)
        self._last_tool_output = None

    def snapshot(self) -> dict[str, Any]:
        """Capture the current state for later restoration (Go-Explore return)."""
        return {
            "trace": copy.deepcopy(self.trace),
            "last_tool_output": self._last_tool_output,
            "tools_state": self._snapshot_tools_state(),
        }

    def restore(self, snapshot: Mapping[str, Any]) -> None:
        """Restore environment to a previously captured state."""
        self.trace = copy.deepcopy(snapshot["trace"])
        self._last_tool_output = snapshot["last_tool_output"]
        self._restore_tools_state(snapshot["tools_state"])

    def _snapshot_tools_state(self) -> dict[str, Any]:
        """Snapshot ToolSuite state (egress, mail, files)."""
        # Snapshot filesystem state recursively
        fs_state = {}

        def _capture_tree(base_path: Path, rel_prefix: str = ""):
            """Recursively capture all files and directories."""
            for fpath in base_path.iterdir():
                rel_path = rel_prefix + fpath.name
                if fpath.is_file():
                    fs_state[rel_path] = fpath.read_text(encoding="utf-8")
                elif fpath.is_dir():
                    # Recursively capture subdirectory contents
                    _capture_tree(fpath, rel_path + "/")

        _capture_tree(self.tools._fs_root)

        return {
            "egress": copy.deepcopy(self.tools._egress_sink),
            "mail": copy.deepcopy(self.tools._mail),
            "fs_state": fs_state,
            "last_source": self.tools._last_source,
        }

    def _restore_tools_state(self, state: Mapping[str, Any]) -> None:
        """Restore ToolSuite state from snapshot."""
        self.tools._egress_sink = copy.deepcopy(state["egress"])
        self.tools._mail = copy.deepcopy(state["mail"])
        self.tools._last_source = state["last_source"]

        # Clear filesystem - remove all files/dirs not in original backup
        for fpath in self.tools._fs_root.iterdir():
            if fpath.name not in self.tools._fs_backup:
                if fpath.is_dir():
                    shutil.rmtree(fpath)
                elif fpath.is_file():
                    fpath.unlink()

        # Restore filesystem from snapshot
        for rel_path, content in state["fs_state"].items():
            fpath = self.tools._fs_root / rel_path
            # Create parent directories if needed (for nested files)
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")

    def interact(
        self, user_message: str, max_tool_hops: int = DEFAULT_MAX_TOOL_HOPS
    ) -> dict[str, Any]:
        if not isinstance(user_message, str):
            raise TypeError("SandboxEnv.interact user_message must be a string")
        if len(user_message) > MAX_USER_MESSAGE_CHARS:
            raise ValueError(
                f"user_message exceeds max length ({MAX_USER_MESSAGE_CHARS} characters)"
            )

        self.trace.add_user(user_message)
        agent_refused_immediately = False  # Track if agent refused on first call

        # Hook: Context building
        context_hook_ctx = HookContext(
            stage=HookStage.CONTEXT_BUILD,
            trace=self.trace,
            context={"user_message": user_message, "seed": self.seed},
        )
        self.hook_registry.execute_hooks(HookStage.CONTEXT_BUILD, context_hook_ctx)

        # up to N tool hops per user message
        for hop_idx in range(max_tool_hops):
            call = self.agent.next_tool_call(self.trace, self._last_tool_output)
            if not call:
                # Track if this was an immediate refusal (first hop)
                if hop_idx == 0:
                    agent_refused_immediately = True
                self.trace.add_assistant("(no_tool)")
                break

            tool_name = call["tool"]
            tool_args = call.get("args", {}) or {}
            spec = self.tools.specs.get(tool_name)
            if spec is None:
                # unknown tool => treated as error event
                ev = ToolEvent(
                    name=tool_name,
                    args=tool_args,
                    ok=False,
                    output="",
                    side_effect="NONE",
                    scope="public",
                    source=self.tools.last_source(),
                    error="unknown_tool",
                )
                self.trace.add_tool(ev)
                self._last_tool_output = ""
                break

            # Hook: Pre-tool call (can modify args)
            pre_tool_ctx = HookContext(
                stage=HookStage.PRE_TOOL_CALL,
                tool_name=tool_name,
                tool_args=tool_args,
                trace=self.trace,
                context={"seed": self.seed},
            )
            _ = self.hook_registry.execute_hooks(HookStage.PRE_TOOL_CALL, pre_tool_ctx)

            # Check if hooks modified args
            if pre_tool_ctx.modified_args is not None:
                tool_args = pre_tool_ctx.modified_args

            # Check if hooks want to block
            if pre_tool_ctx.should_block:
                ev = ToolEvent(
                    name=tool_name,
                    args=tool_args,
                    ok=False,
                    output="",
                    side_effect=spec.side_effect,
                    scope=spec.scope,
                    source=self.tools.last_source(),
                    error="blocked_by_hook",
                )
                self.trace.add_tool(ev)
                self._last_tool_output = ""
                break

            # Guardrail decision
            ctx = {
                "seed": self.seed,
                "recent_sources": [e.source for e in self.trace.tool_events[-5:]],
                "recent_tools": [e.name for e in self.trace.tool_events[-5:]],
                "last_user": self.trace.user_messages[-1],
                "side_effect": spec.side_effect,
                "scope": spec.scope,
            }

            # Hook: Pre-guardrail
            pre_guard_ctx = HookContext(
                stage=HookStage.PRE_GUARDRAIL,
                tool_name=tool_name,
                tool_args=tool_args,
                trace=self.trace,
                context=ctx,
            )
            self.hook_registry.execute_hooks(HookStage.PRE_GUARDRAIL, pre_guard_ctx)

            decision = self.guardrail.decide(tool_name, tool_args, ctx)

            # Hook: Post-guardrail (can see decision)
            post_guard_ctx = HookContext(
                stage=HookStage.POST_GUARDRAIL,
                tool_name=tool_name,
                tool_args=tool_args,
                guardrail_decision=decision,
                trace=self.trace,
                context=ctx,
            )
            self.hook_registry.execute_hooks(HookStage.POST_GUARDRAIL, post_guard_ctx)

            if decision.action == "DENY":
                ev = ToolEvent(
                    name=tool_name,
                    args=tool_args,
                    ok=False,
                    output="",
                    side_effect=spec.side_effect,
                    scope=spec.scope,
                    source=self.tools.last_source(),
                    error="denied:" + decision.reason,
                )
                self.trace.add_tool(ev)
                self._last_tool_output = ""
                break

            if decision.action == "CONFIRM":
                ev = ToolEvent(
                    name=tool_name,
                    args=tool_args,
                    ok=False,
                    output="",
                    side_effect=spec.side_effect,
                    scope=spec.scope,
                    source=self.tools.last_source(),
                    error="confirm_required:" + decision.reason,
                )
                self.trace.add_tool(ev)
                self._last_tool_output = ""
                break

            if decision.action == "SANITIZE" and decision.sanitized_args is not None:
                tool_args = decision.sanitized_args

            ok, output, err = self.tools.call(tool_name, tool_args)

            # Hook: Post-tool call (can see output)
            post_tool_ctx = HookContext(
                stage=HookStage.POST_TOOL_CALL,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=output,
                trace=self.trace,
                context={"ok": ok, "error": err},
            )
            _ = self.hook_registry.execute_hooks(HookStage.POST_TOOL_CALL, post_tool_ctx)

            # Check if hooks modified output
            if post_tool_ctx.modified_output is not None:
                output = post_tool_ctx.modified_output

            # Check for trigger activation
            trigger_ctx = HookContext(
                stage=HookStage.TRIGGER_CHECK,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=output,
                trace=self.trace,
                context=ctx,
            )
            _ = self.hook_registry.execute_hooks(HookStage.TRIGGER_CHECK, trigger_ctx)

            ev = ToolEvent(
                name=tool_name,
                args=tool_args,
                ok=ok,
                output=output,
                side_effect=spec.side_effect,
                scope=spec.scope,
                source=self.tools.last_source(),
                error=err,
            )

            # Hook: Memory store (when adding to trace)
            memory_ctx = HookContext(
                stage=HookStage.MEMORY_STORE,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=output,
                trace=self.trace,
                context={"tool_event": ev},
            )
            self.hook_registry.execute_hooks(HookStage.MEMORY_STORE, memory_ctx)

            self.trace.add_tool(ev)
            self._last_tool_output = output

        return {
            "seed": self.seed,
            "n_tools": len(self.trace.tool_events),
            "agent_refused": agent_refused_immediately,
        }

    def export_trace_dict(self) -> dict[str, Any]:
        return {
            "seed": self.trace.seed,
            "user_messages": list(self.trace.user_messages),
            "assistant_messages": list(self.trace.assistant_messages),
            "tool_events": [
                {
                    "name": e.name,
                    "args": e.args,
                    "ok": e.ok,
                    "output": e.output,
                    "side_effect": e.side_effect,
                    "scope": e.scope,
                    "source": e.source,
                    "error": e.error,
                }
                for e in self.trace.tool_events
            ],
            "egress": self.tools.get_egress(),
        }
