from __future__ import annotations

import copy
import json
import string
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal

import gymnasium as gym
from gymnasium import spaces

from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.api import (
    DEFAULT_MAX_TOOL_HOPS,
    MAX_USER_MESSAGE_CHARS,
    EnvInteractionResult,
)
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.predicates import eval_predicates, is_breach
from aicomp_sdk.hooks import HookRegistry

MAX_TRACE_SUMMARY_JSON_CHARS: Final[int] = 8_192
RECENT_TOOL_WINDOW: Final[int] = 8
RECENT_ERROR_WINDOW: Final[int] = 4
LAST_OUTPUT_WINDOW: Final[int] = 4
LAST_OUTPUT_CHARS: Final[int] = 256
TEXT_CHARSET: Final[str] = string.printable


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


class GymAttackEnv(gym.Env[dict[str, Any], str]):
    """Gymnasium wrapper for the blue-agent sandbox used in red-team evaluation."""

    metadata = {"render_modes": ["ansi"], "render_fps": 0}

    def _build_observation_space(self) -> spaces.Dict:
        return spaces.Dict(
            {
                "turn_index": spaces.Discrete(self.max_episode_messages + 1),
                "trace_summary_json": spaces.Text(
                    max_length=MAX_TRACE_SUMMARY_JSON_CHARS,
                    charset=TEXT_CHARSET,
                ),
            }
        )

    def __init__(
        self,
        seed: int,
        fixtures_dir: Path,
        guardrail,
        agent: AgentProtocol,
        max_tool_hops: int = DEFAULT_MAX_TOOL_HOPS,
        max_episode_messages: int = 32,
        reward_mode: Literal["none"] = "none",
        hook_registry: HookRegistry | None = None,
    ) -> None:
        super().__init__()
        if max_tool_hops <= 0:
            raise ValueError("max_tool_hops must be positive")
        if max_episode_messages <= 0:
            raise ValueError("max_episode_messages must be positive")
        if reward_mode != "none":
            raise ValueError(f"Unsupported reward_mode: {reward_mode}")

        self._sandbox = SandboxEnv(
            seed=seed,
            fixtures_dir=fixtures_dir,
            agent=agent,
            guardrail=guardrail,
            hook_registry=hook_registry,
        )
        self.max_tool_hops = int(max_tool_hops)
        self.max_episode_messages = int(max_episode_messages)
        self.reward_mode = reward_mode
        self.action_space = spaces.Text(
            max_length=MAX_USER_MESSAGE_CHARS,
            charset=TEXT_CHARSET,
        )
        self.observation_space = self._build_observation_space()
        self._last_interaction_result = self._empty_interaction_result()

    @property
    def seed(self) -> int:
        return self._sandbox.seed

    @seed.setter
    def seed(self, value: int) -> None:
        self._sandbox.seed = int(value)

    @property
    def trace(self):
        return self._sandbox.trace

    @property
    def tools(self):
        return self._sandbox.tools

    @property
    def guardrail(self):
        return self._sandbox.guardrail

    def _empty_interaction_result(self) -> EnvInteractionResult:
        return EnvInteractionResult(seed=self.seed)

    def _trace_summary(self) -> dict[str, Any]:
        trace = self.export_trace_dict()
        user_messages = trace.get("user_messages", [])
        tool_events = trace.get("tool_events", [])
        egress = trace.get("egress", [])
        if user_messages:
            last_user_message = user_messages[-1]
        else:
            last_user_message = ""

        summary = {
            "seed": trace["seed"],
            "n_user_messages": len(user_messages),
            "last_user_message": last_user_message,
            "n_tool_events": len(tool_events),
            "recent_tools": [event.get("name", "") for event in tool_events[-RECENT_TOOL_WINDOW:]],
            "recent_sources": [
                event.get("source", "") for event in tool_events[-RECENT_TOOL_WINDOW:]
            ],
            "recent_errors": [
                event.get("error") or "" for event in tool_events[-RECENT_ERROR_WINDOW:]
            ],
            "last_tool_outputs": [
                _truncate(str(event.get("output", "")), LAST_OUTPUT_CHARS)
                for event in tool_events[-LAST_OUTPUT_WINDOW:]
            ],
            "egress_count": len(egress),
            "agent_refused_last_turn": self._last_interaction_result.agent_refused,
        }

        summary_json = json.dumps(summary, sort_keys=True, separators=(",", ":"))
        if len(summary_json) <= MAX_TRACE_SUMMARY_JSON_CHARS:
            return summary

        compact_summary = {
            "seed": summary["seed"],
            "n_user_messages": summary["n_user_messages"],
            "last_user_message": _truncate(summary["last_user_message"], 128),
            "n_tool_events": summary["n_tool_events"],
            "recent_tools": summary["recent_tools"][-4:],
            "recent_sources": summary["recent_sources"][-4:],
            "recent_errors": summary["recent_errors"][-2:],
            "last_tool_outputs": [
                _truncate(output, 64) for output in summary["last_tool_outputs"][-2:]
            ],
            "egress_count": summary["egress_count"],
            "agent_refused_last_turn": summary["agent_refused_last_turn"],
        }
        return compact_summary

    def _observation(self) -> dict[str, Any]:
        summary_json = json.dumps(
            self._trace_summary(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "turn_index": min(len(self.trace.user_messages), self.max_episode_messages),
            "trace_summary_json": summary_json,
        }

    def _info(self) -> dict[str, Any]:
        trace = self.export_trace_dict()
        predicates = eval_predicates(trace)
        return {
            "trace": trace,
            "interaction_result": copy.deepcopy(self._last_interaction_result),
            "predicates": predicates,
            "cell_signature": cell_signature(
                trace.get("tool_events", []),
                egress_data=trace.get("egress", []),
                user_messages=trace.get("user_messages", []),
            ),
            "breach": is_breach(trace, predicates),
            "max_tool_hops": self.max_tool_hops,
            "max_episode_messages": self.max_episode_messages,
        }

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if seed is not None:
            self.seed = seed
        super().reset(seed=seed)

        if options:
            if "max_tool_hops" in options:
                self.max_tool_hops = int(options["max_tool_hops"])
            if "max_episode_messages" in options:
                self.max_episode_messages = int(options["max_episode_messages"])
                self.observation_space = self._build_observation_space()

        self._sandbox.reset()
        self._last_interaction_result = self._empty_interaction_result()
        return self._observation(), self._info()

    def step(self, action: str) -> tuple[dict[str, Any], float, bool, bool, dict[str, Any]]:
        if not isinstance(action, str):
            raise TypeError("GymAttackEnv.step action must be a string")
        if len(action) > MAX_USER_MESSAGE_CHARS:
            raise ValueError(f"Action exceeds max length ({MAX_USER_MESSAGE_CHARS} characters)")

        self._last_interaction_result = self._sandbox.interact(
            action, max_tool_hops=self.max_tool_hops
        )
        truncated = len(self.trace.user_messages) >= self.max_episode_messages
        observation = self._observation()
        info = self._info()
        return observation, 0.0, False, truncated, info

    def interact(self, user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult:
        if max_tool_hops is not None and max_tool_hops != self.max_tool_hops:
            previous = self.max_tool_hops
            self.max_tool_hops = int(max_tool_hops)
            try:
                _, _, _, _, info = self.step(user_message)
            finally:
                self.max_tool_hops = previous
        else:
            self.step(user_message)
        return copy.deepcopy(self._last_interaction_result)

    def export_trace_dict(self) -> dict[str, Any]:
        return self._sandbox.export_trace_dict()

    def snapshot(self) -> dict[str, Any]:
        return {
            "sandbox": self._sandbox.snapshot(),
            "last_interaction_result": copy.deepcopy(self._last_interaction_result),
            "max_tool_hops": self.max_tool_hops,
            "max_episode_messages": self.max_episode_messages,
        }

    def restore(self, snapshot: Mapping[str, Any]) -> None:
        self._sandbox.restore(snapshot["sandbox"])
        self._last_interaction_result = copy.deepcopy(snapshot["last_interaction_result"])
        self.max_tool_hops = int(snapshot["max_tool_hops"])
        self.max_episode_messages = int(snapshot["max_episode_messages"])
        self.observation_space = self._build_observation_space()

    def render(self) -> Any:
        return json.dumps(self.export_trace_dict(), indent=2, sort_keys=True)

    def close(self) -> None:
        pass
