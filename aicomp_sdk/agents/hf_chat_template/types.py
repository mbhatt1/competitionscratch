from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from aicomp_sdk.agents.types import AgentDecision, AgentToolSpec, JsonObject
from aicomp_sdk.core.runtime_history import RuntimeHistory


@dataclass(frozen=True)
class HFBackendConfig:
    model_id: str
    model_path: str | None = None
    local_files_only: bool = True
    device_map: str = "auto"
    torch_dtype: str = "auto"
    tokenizer_kwargs: Mapping[str, Any] = field(default_factory=dict)
    model_kwargs: Mapping[str, Any] = field(default_factory=dict)
    trust_remote_code: bool | None = None
    attn_implementation: str | None = None
    max_new_tokens: int = 256
    generation_kwargs: Mapping[str, Any] = field(default_factory=lambda: {"do_sample": False})

    def __post_init__(self) -> None:
        if "max_new_tokens" in self.generation_kwargs:
            raise ValueError(
                "HF backend generation_kwargs must not include 'max_new_tokens'; "
                "use HFBackendConfig.max_new_tokens instead"
            )

        tokenizer_conflicts = ["local_files_only"]
        model_conflicts = ["local_files_only", "device_map", "torch_dtype"]
        if self.trust_remote_code is not None:
            tokenizer_conflicts.append("trust_remote_code")
            model_conflicts.append("trust_remote_code")
        if self.attn_implementation is not None:
            model_conflicts.append("attn_implementation")

        _validate_loader_kwarg_conflicts(
            self.tokenizer_kwargs,
            keys=tokenizer_conflicts,
            target="tokenizer_kwargs",
        )
        _validate_loader_kwarg_conflicts(
            self.model_kwargs,
            keys=model_conflicts,
            target="model_kwargs",
        )

    def model_source(self) -> str:
        return self.model_path or self.model_id

    def tokenizer_loader_kwargs(self) -> dict[str, Any]:
        loader_kwargs = dict(self.tokenizer_kwargs)
        loader_kwargs["local_files_only"] = self.local_files_only
        if self.trust_remote_code is not None:
            loader_kwargs["trust_remote_code"] = self.trust_remote_code
        return loader_kwargs

    def model_loader_kwargs(self) -> dict[str, Any]:
        loader_kwargs = dict(self.model_kwargs)
        loader_kwargs["torch_dtype"] = self.torch_dtype
        loader_kwargs["device_map"] = self.device_map
        loader_kwargs["local_files_only"] = self.local_files_only
        if self.trust_remote_code is not None:
            loader_kwargs["trust_remote_code"] = self.trust_remote_code
        if self.attn_implementation is not None:
            loader_kwargs["attn_implementation"] = self.attn_implementation
        return loader_kwargs


@dataclass(frozen=True)
class HFModelProfile:
    instruction_role: Literal["system", "developer"] = "system"
    chat_template: str | None = None
    assistant_prefill: str | None = None
    continue_final_message: bool = False

    def __post_init__(self) -> None:
        if self.assistant_prefill is not None and not self.continue_final_message:
            raise ValueError(
                "HF model profile assistant_prefill requires " "continue_final_message=True"
            )


@dataclass(frozen=True)
class HFGenerationRequest:
    messages: list[dict[str, Any]]
    tools: list[JsonObject]
    chat_template: str | None
    add_generation_prompt: bool
    continue_final_message: bool
    max_new_tokens: int
    generation_kwargs: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.add_generation_prompt and self.continue_final_message:
            raise ValueError(
                "HF generation request cannot set both add_generation_prompt and "
                "continue_final_message"
            )


@dataclass(frozen=True)
class HFGenerationResponse:
    text: str
    raw_text: str
    finish_reason: str | None = None
    parsed_response: Mapping[str, Any] | None = None


class HFGenerationBackendProtocol(Protocol):
    config: HFBackendConfig

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        """Execute a chat-templated generation request."""


class HFRequestBuilder(Protocol):
    def __call__(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
        profile: HFModelProfile,
        backend: HFGenerationBackendProtocol,
    ) -> HFGenerationRequest:
        """Build a backend request from canonical runtime history."""


class HFResponseParser(Protocol):
    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        """Parse backend output into a normalized agent decision."""


def _validate_loader_kwarg_conflicts(
    loader_kwargs: Mapping[str, Any],
    *,
    keys: Sequence[str],
    target: str,
) -> None:
    for key in keys:
        if key in loader_kwargs:
            raise ValueError(
                f"HF backend config {target} must not override '{key}'; use the "
                "top-level HFBackendConfig field instead"
            )
