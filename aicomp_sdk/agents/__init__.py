"""Extension-facing agent backend namespace.

Import ``AgentSelection`` and ``build_agent_factory`` for SDK-managed backends.
Import ``AgentProtocol`` and the debug sink types when adding a custom backend.
Backend-specific classes and parser helpers are exported here for extension
authors, not as the high-level evaluation API.
"""

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
    coerce_agent_selection,
    format_agent_selection,
    require_agent_selection_configuration,
)
from .gemma4_agent import (
    DEFAULT_GEMMA4_MODEL_ID,
    Gemma4Agent,
    build_gemma4_backend,
    build_gemma4_backend_config,
    build_gemma4_parser,
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
    HFProcessorChatTemplateBackend,
    HFRequestBuilder,
    HFResponseParser,
    JsonEnvelopeToolCallParser,
    LlamaCppChatTemplateBackend,
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
    "DEFAULT_GEMMA4_MODEL_ID",
    "DebugPhase",
    "HFBackendConfig",
    "HFChatTemplateAgent",
    "HFChatTemplateBackend",
    "HFGenerationBackendProtocol",
    "HFGenerationRequest",
    "HFGenerationResponse",
    "HFModelProfile",
    "HFProcessorChatTemplateBackend",
    "LlamaCppChatTemplateBackend",
    "HFRequestBuilder",
    "HFResponseParser",
    "InMemoryAgentDebugSink",
    "GPTOSSAgent",
    "GemmaAgent",
    "Gemma4Agent",
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
    "build_gemma4_backend",
    "build_gemma4_backend_config",
    "build_gemma4_parser",
    "build_hf_response_parser",
    "coerce_agent_selection",
    "format_agent_selection",
    "require_agent_selection_configuration",
]
