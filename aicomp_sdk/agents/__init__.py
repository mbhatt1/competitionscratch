"""Agent implementations for AI competition."""

from .deterministic_agent import VulnerableDeterministicAgent
from .factory import (
    AgentFactory,
    AgentSelection,
    build_agent,
    build_agent_factory,
    format_agent_selection,
    parse_agent_selection,
    require_agent_selection_configuration,
)
from .gpt_oss_agent import GPTOSSAgent, GPTOSSBackend
from .openai_agent import OpenAIAgent
from .protocol import AgentProtocol

__all__ = [
    "AgentFactory",
    "AgentProtocol",
    "AgentSelection",
    "GPTOSSAgent",
    "GPTOSSBackend",
    "OpenAIAgent",
    "VulnerableDeterministicAgent",
    "build_agent",
    "build_agent_factory",
    "format_agent_selection",
    "parse_agent_selection",
    "require_agent_selection_configuration",
]
