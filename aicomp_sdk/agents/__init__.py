"""Agent implementations for AI competition."""

from .debug import (
    AgentDebugEvent,
    AgentDebugSink,
    DebugPhase,
    InMemoryAgentDebugSink,
    JsonlAgentDebugSink,
)
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
from .gemma_agent import (
    DEFAULT_GEMMA_MODEL_ID,
    GemmaAgent,
    build_gemma_backend,
    build_gemma_backend_config,
)
from .gpt_oss_agent import (
    DEFAULT_GPT_OSS_MODEL_ID,
    GPTOSSAgent,
    build_gpt_oss_backend,
    build_gpt_oss_backend_config,
    build_gpt_oss_parser,
)
from .hf_chat_template import (
    HFBackendConfig,
    HFChatTemplateAgent,
    HFChatTemplateBackend,
    HFGenerationBackendProtocol,
    HFGenerationRequest,
    HFGenerationResponse,
    HFModelProfile,
    HFRequestBuilder,
    HFResponseParser,
    JsonEnvelopeToolCallParser,
    TokenizerNativeResponseParser,
    build_hf_response_parser,
    normalize_parsed_response,
    normalize_tool_arguments,
)
from .openai_agent import OpenAIResponsesAgent
from .protocol import AgentProtocol

__all__ = [
    "AgentFactory",
    "AgentDebugEvent",
    "AgentDebugSink",
    "AgentProtocol",
    "AgentSelection",
    "DEFAULT_GPT_OSS_MODEL_ID",
    "DEFAULT_GEMMA_MODEL_ID",
    "DebugPhase",
    "HFBackendConfig",
    "HFChatTemplateAgent",
    "HFChatTemplateBackend",
    "HFGenerationBackendProtocol",
    "HFGenerationRequest",
    "HFGenerationResponse",
    "HFModelProfile",
    "HFRequestBuilder",
    "HFResponseParser",
    "InMemoryAgentDebugSink",
    "GPTOSSAgent",
    "GemmaAgent",
    "JsonEnvelopeToolCallParser",
    "JsonlAgentDebugSink",
    "normalize_parsed_response",
    "normalize_tool_arguments",
    "OpenAIResponsesAgent",
    "TokenizerNativeResponseParser",
    "VulnerableDeterministicAgent",
    "build_agent",
    "build_agent_factory",
    "build_gpt_oss_backend",
    "build_gpt_oss_backend_config",
    "build_gpt_oss_parser",
    "build_gemma_backend",
    "build_gemma_backend_config",
    "build_hf_response_parser",
    "format_agent_selection",
    "parse_agent_selection",
    "require_agent_selection_configuration",
]
