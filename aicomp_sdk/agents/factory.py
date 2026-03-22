from __future__ import annotations
from typing import Final

import os
from collections.abc import Callable
from enum import StrEnum

from .debug import AgentDebugSink
from .deterministic_agent import VulnerableDeterministicAgent
from .gemma_agent import GemmaAgent, build_gemma_backend
from .gpt_oss_agent import GPTOSSAgent, build_gpt_oss_backend
from .openai_agent import OpenAIResponsesAgent
from .protocol import AgentProtocol


class AgentSelection(StrEnum):
    AUTO = "auto"
    DETERMINISTIC = "deterministic"
    OPENAI = "openai"
    GPT_OSS = "gpt_oss"
    GEMMA = "gemma"


AgentFactory = Callable[[], AgentProtocol]
_DEBUG_AGENT_ENV_VALUES: Final[tuple[str, ...]] = ("1", "true", "yes")


def coerce_agent_selection(value: str | AgentSelection) -> AgentSelection:
    try:
        return AgentSelection(value)
    except ValueError as err:
        raise ValueError(f"Unsupported agent selection: {value}") from err


def _default_verbose() -> bool:
    return os.environ.get("DEBUG_AGENT", "").lower() in _DEBUG_AGENT_ENV_VALUES


def _resolve_verbose(verbose: bool | None) -> bool:
    if verbose is None:
        return _default_verbose()
    return verbose


def _require_openai_api_key() -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY must be set when agent selection is 'openai'.")
    return api_key


def _create_openai_agent(
    api_key: str,
    verbose: bool,
    debug_sink: AgentDebugSink | None = None,
) -> OpenAIResponsesAgent:
    try:
        from openai import OpenAI
    except Exception as err:
        exc = RuntimeError("OpenAI SDK is not available")
        exc.add_note("Install the 'openai' dependency before using agent selection 'openai'.")
        raise exc from err

    return OpenAIResponsesAgent(
        client=OpenAI(api_key=api_key),
        verbose=verbose,
        debug_sink=debug_sink,
    )


def _resolve_auto_factory(
    verbose: bool,
    debug_sink: AgentDebugSink | None,
) -> AgentFactory:
    try:
        backend = build_gpt_oss_backend()
    except RuntimeError:
        backend = None
    if backend is not None:
        return lambda: GPTOSSAgent(backend, debug_sink=debug_sink)

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        return lambda: _create_openai_agent(api_key, verbose, debug_sink)

    return lambda: VulnerableDeterministicAgent(debug_sink=debug_sink)


def format_agent_selection(selection: AgentSelection) -> str:
    if selection is AgentSelection.DETERMINISTIC:
        return "Deterministic vulnerable agent (forced)"
    if selection is AgentSelection.OPENAI:
        return "OpenAI API agent (forced)"
    if selection is AgentSelection.GPT_OSS:
        return "Local GPT-OSS agent (forced)"
    if selection is AgentSelection.GEMMA:
        return "Local Gemma HF chat-template agent (forced)"
    return "Auto selection (gpt-oss -> OpenAI if key -> deterministic)"


def require_agent_selection_configuration(selection: AgentSelection) -> None:
    if selection is AgentSelection.OPENAI:
        _require_openai_api_key()
        return
    if selection is AgentSelection.GPT_OSS:
        build_gpt_oss_backend()
        return
    if selection is AgentSelection.GEMMA:
        build_gemma_backend()


def build_agent_factory(
    selection: str | AgentSelection,
    *,
    verbose: bool | None = None,
    debug_sink: AgentDebugSink | None = None,
) -> AgentFactory:
    resolved_selection = coerce_agent_selection(selection)
    resolved_verbose = _resolve_verbose(verbose)

    if resolved_selection is AgentSelection.DETERMINISTIC:
        return lambda: VulnerableDeterministicAgent(debug_sink=debug_sink)

    if resolved_selection is AgentSelection.OPENAI:
        api_key = _require_openai_api_key()
        return lambda: _create_openai_agent(api_key, resolved_verbose, debug_sink)

    if resolved_selection is AgentSelection.GPT_OSS:
        backend = build_gpt_oss_backend()
        return lambda: GPTOSSAgent(backend, debug_sink=debug_sink)

    if resolved_selection is AgentSelection.GEMMA:
        backend = build_gemma_backend()
        return lambda: GemmaAgent(backend, debug_sink=debug_sink)

    return _resolve_auto_factory(resolved_verbose, debug_sink)


def build_agent(
    selection: str | AgentSelection,
    *,
    verbose: bool | None = None,
    debug_sink: AgentDebugSink | None = None,
) -> AgentProtocol:
    return build_agent_factory(selection, verbose=verbose, debug_sink=debug_sink)()
