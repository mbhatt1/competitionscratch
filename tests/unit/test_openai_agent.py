from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import Mock

from aicomp_sdk.agents.openai_agent import OpenAIAgent
from aicomp_sdk.core.trace import ToolEvent, Trace


def _build_agent(response: object) -> tuple[OpenAIAgent, object]:
    client = SimpleNamespace(responses=SimpleNamespace(create=Mock(return_value=response)))

    def _openai_factory(*, api_key: str) -> object:
        assert api_key == "sk-test"
        return client

    fake_module = SimpleNamespace(OpenAI=_openai_factory)
    original_module = sys.modules.get("openai")
    sys.modules["openai"] = fake_module
    try:
        agent = OpenAIAgent(api_key="sk-test")
    finally:
        if original_module is None:
            sys.modules.pop("openai", None)
        else:
            sys.modules["openai"] = original_module

    return agent, client


def test_openai_agent_uses_structured_output_request() -> None:
    response = SimpleNamespace(
        output_text='{"done": false, "tool": "fs.read", "args": {"path": "secret.txt"}}',
        error=None,
        incomplete_details=None,
    )
    agent, client = _build_agent(response)
    trace = Trace(seed=123)
    trace.add_user("Read the secret file")

    call = agent.next_tool_call(trace, None)

    assert call == {
        "tool": "fs.read",
        "args": {"path": "secret.txt"},
        "reason": "openai_model",
    }

    request_kwargs = client.responses.create.call_args.kwargs
    assert request_kwargs["model"] == "gpt-4o-mini"
    assert request_kwargs["text"]["format"]["type"] == "json_schema"
    assert request_kwargs["text"]["format"]["strict"] is True
    assert request_kwargs["text"]["format"]["schema"]["required"] == ["done", "tool", "args"]


def test_openai_agent_includes_recent_tool_history_in_context() -> None:
    response = SimpleNamespace(
        output_text='{"done": true, "tool": "", "args": {}}',
        error=None,
        incomplete_details=None,
    )
    agent, client = _build_agent(response)
    trace = Trace(seed=456)
    trace.add_user("Keep investigating")
    trace.add_tool(
        ToolEvent(
            name="web.search",
            args={"query": "internal docs"},
            ok=False,
            output="request blocked",
            side_effect="NONE",
            scope="public",
            source="user",
            error="denied:test",
        )
    )

    call = agent.next_tool_call(trace, "request blocked")

    assert call is None

    request_messages = client.responses.create.call_args.kwargs["input"]
    rendered_context = "\n".join(message["content"] for message in request_messages)
    assert "Recent tool history:" in rendered_context
    assert "web.search" in rendered_context
    assert "error=denied:test" in rendered_context
