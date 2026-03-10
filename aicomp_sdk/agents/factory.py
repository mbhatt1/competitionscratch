from __future__ import annotations

import os
from collections.abc import Callable
from enum import Enum
from typing import Optional

from .deterministic_agent import VulnerableDeterministicAgent
from .gpt_oss_agent import GPTOSSAgent, GPTOSSBackend
from .openai_agent import OpenAIAgent
from .protocol import AgentProtocol


class AgentSelection(str, Enum):
    AUTO = "auto"
    DETERMINISTIC = "deterministic"
    OPENAI = "openai"
    GPT_OSS = "gpt_oss"

    def __str__(self) -> str:
        return self.value


AgentFactory = Callable[[], AgentProtocol]
_DEBUG_AGENT_ENV_VALUES = ("1", "true", "yes")


def parse_agent_selection(value: str | AgentSelection) -> AgentSelection:
    if isinstance(value, AgentSelection):
        return value
    try:
        return AgentSelection(value)
    except ValueError as err:
        raise ValueError(f"Unsupported agent selection: {value}") from err


def _default_verbose() -> bool:
    return os.environ.get("DEBUG_AGENT", "").lower() in _DEBUG_AGENT_ENV_VALUES


def _resolve_verbose(verbose: Optional[bool]) -> bool:
    if verbose is None:
        return _default_verbose()
    return verbose


def _require_openai_api_key() -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY must be set when agent selection is 'openai'.")
    return api_key


def _require_gpt_oss_model_path() -> str:
    model_path = os.environ.get("GPT_OSS_MODEL_PATH", "").strip()
    if not model_path:
        raise RuntimeError("GPT_OSS_MODEL_PATH must be set when agent selection is 'gpt_oss'.")
    return model_path


def _create_openai_agent(api_key: str, verbose: bool) -> OpenAIAgent:
    return OpenAIAgent(api_key=api_key, verbose=verbose)


def _create_gpt_oss_backend() -> GPTOSSBackend:
    model_path = _require_gpt_oss_model_path()

    backend = GPTOSSBackend(model_path)
    if not backend.ready():
        raise RuntimeError(
            "Failed to load gpt-oss-20b from GPT_OSS_MODEL_PATH='{}'. "
            "Ensure the weights are present locally and Transformers/Torch are available.".format(
                model_path
            )
        )
    return backend


def _resolve_auto_factory(verbose: bool) -> AgentFactory:
    model_path = os.environ.get("GPT_OSS_MODEL_PATH", "").strip()
    if model_path:
        backend = _create_gpt_oss_backend()
        return lambda: GPTOSSAgent(backend)

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        return lambda: _create_openai_agent(api_key, verbose)

    return VulnerableDeterministicAgent


def format_agent_selection(selection: AgentSelection) -> str:
    if selection is AgentSelection.DETERMINISTIC:
        return "Deterministic vulnerable agent (forced)"
    if selection is AgentSelection.OPENAI:
        return "OpenAI API agent (forced)"
    if selection is AgentSelection.GPT_OSS:
        return "Local GPT-OSS agent (forced)"
    return "Auto selection (gpt-oss -> OpenAI if key -> deterministic)"


def require_agent_selection_configuration(selection: AgentSelection) -> None:
    if selection is AgentSelection.OPENAI:
        _require_openai_api_key()
        return

    if selection is AgentSelection.GPT_OSS:
        _require_gpt_oss_model_path()


def build_agent_factory(
    selection: str | AgentSelection,
    *,
    verbose: Optional[bool] = None,
) -> AgentFactory:
    resolved_selection = parse_agent_selection(selection)
    resolved_verbose = _resolve_verbose(verbose)

    if resolved_selection is AgentSelection.DETERMINISTIC:
        return VulnerableDeterministicAgent

    if resolved_selection is AgentSelection.OPENAI:
        api_key = _require_openai_api_key()
        return lambda: _create_openai_agent(api_key, resolved_verbose)

    if resolved_selection is AgentSelection.GPT_OSS:
        backend = _create_gpt_oss_backend()
        return lambda: GPTOSSAgent(backend)

    return _resolve_auto_factory(resolved_verbose)


def build_agent(
    selection: str | AgentSelection,
    *,
    verbose: Optional[bool] = None,
) -> AgentProtocol:
    return build_agent_factory(selection, verbose=verbose)()
