import copy
import json

import pytest

from aicomp_sdk.core.tools import ToolContext, ToolDef, ToolScope, ToolSideEffect
from aicomp_sdk.core.tools.email import email_list, email_read, email_send
from aicomp_sdk.core.tools.fs import fs_delete, fs_read, fs_write
from aicomp_sdk.core.tools.http import http_post
from aicomp_sdk.core.tools.models import ToolCallResult
from aicomp_sdk.core.tools.schema import build_runtime_tool_spec
from aicomp_sdk.core.tools.shell import shell_run
from aicomp_sdk.core.tools.state import ToolRuntimeState
from aicomp_sdk.core.tools.web import web_open, web_search


def _build_context(tmp_path, *, pages=None, mail_seed=None):  # noqa: ANN001, ANN201
    filesystem_root = tmp_path / "file_seed"
    filesystem_root.mkdir()
    (filesystem_root / "readme.txt").write_text("README content", encoding="utf-8")
    (filesystem_root / "secret.txt").write_text("SECRET_MARKER", encoding="utf-8")
    seed_mail = mail_seed or {"inbox": []}
    state = ToolRuntimeState(
        web={"pages": pages or []},
        mail_seed=copy.deepcopy(seed_mail),
        mail=copy.deepcopy(seed_mail),
        fs_root=filesystem_root,
        fs_backup={},
        egress_sink=[],
        last_source="user",
    )
    return state, ToolContext(state)


def _build_tool_def(handler) -> ToolDef:  # noqa: ANN001
    return ToolDef(
        name="test.tool",
        side_effect=ToolSideEffect.READ,
        scope=ToolScope.LOCAL,
        handler=handler,
    )


def test_tool_context_mark_source_updates_state(tmp_path):
    state, ctx = _build_context(tmp_path)

    ctx.mark_source("email")

    assert state.last_source == "email"


def test_web_search_handler_is_case_insensitive_sorted_and_capped(tmp_path):
    pages = [
        {
            "id": f"page_{idx:02d}",
            "title": "Alpha title" if idx % 2 == 0 else "Misc",
            "content": "contains Alpha" if idx % 2 else "other",
        }
        for idx in range(12)
    ]
    pages.reverse()
    state, ctx = _build_context(tmp_path, pages=pages)

    ok, output, err = web_search(ctx, "ALPHA")

    assert ok is True
    assert err is None
    result = json.loads(output)
    assert len(result["results"]) == 10
    assert [item["id"] for item in result["results"]] == [f"page_{idx:02d}" for idx in range(10)]
    assert state.last_source == "web"


def test_web_search_handler_returns_fallback_when_no_match(tmp_path):
    _, ctx = _build_context(
        tmp_path,
        pages=[{"id": "page_9", "title": "Nothing", "content": "else"}],
    )

    ok, output, err = web_search(ctx, "missing")

    assert ok is True
    assert err is None
    assert json.loads(output)["results"] == [{"id": "page_0", "title": "Welcome"}]


def test_web_open_handler_preserves_not_found(tmp_path):
    _, ctx = _build_context(tmp_path, pages=[])

    ok, output, err = web_open(ctx, "missing")

    assert ok is False
    assert output == ""
    assert err == "not_found"


def test_fs_handlers_preserve_path_behavior(tmp_path):
    state, ctx = _build_context(tmp_path)

    ok, output, err = fs_read(ctx, "/readme.txt")
    assert ok is True
    assert err is None
    assert output == "README content"

    ok, output, err = fs_read(ctx, "../../etc/passwd")
    assert ok is False
    assert output == ""
    assert err == "path_escape"

    ok, output, err = fs_write(ctx, "nested/deep/file.txt", "nested content")
    assert ok is True
    assert err is None
    assert output == "ok"
    assert (state.fs_root / "nested" / "deep" / "file.txt").read_text() == "nested content"

    ok, output, err = fs_delete(ctx, "../../outside.txt")
    assert ok is False
    assert output == ""
    assert err == "path_escape"
    assert state.last_source == "file"


def test_shell_run_handler_preserves_trimming_and_prefix_behavior(tmp_path):
    state, ctx = _build_context(tmp_path)

    ok, output, err = shell_run(ctx, "  echo hello  ")
    assert ok is True
    assert err is None
    assert output == "hello"

    ok, output, err = shell_run(ctx, " ls -la ")
    assert ok is True
    assert err is None
    assert output == "ok"
    assert state.last_source == "tool"


def test_email_list_handler_preserves_limit_and_cursor_edge_cases(tmp_path):
    inbox = [
        {
            "id": f"msg{i}",
            "from": f"user{i}@example.com",
            "subject": f"Subject {i}",
            "body": f"Body {i}",
        }
        for i in range(30)
    ]
    state, ctx = _build_context(tmp_path, mail_seed={"inbox": inbox})

    ok, output, err = email_list(ctx, "inbox", None, None)
    assert ok is True
    assert err is None
    result = json.loads(output)
    assert len(result["emails"]) == 20
    assert result["next_cursor"] == "20"

    ok, output, err = email_list(ctx, "inbox", True, None)
    assert ok is False
    assert output == ""
    assert err == "invalid_limit"

    ok, output, err = email_list(ctx, "inbox", 5, "abc")
    assert ok is False
    assert output == ""
    assert err == "invalid_cursor"
    assert state.last_source == "email"


def test_email_read_handler_searches_all_folders(tmp_path):
    _, ctx = _build_context(
        tmp_path,
        mail_seed={
            "inbox": [],
            "archive": [
                {
                    "id": "archived1",
                    "from": "archiver@example.com",
                    "subject": "Archived",
                    "body": "Stored away",
                }
            ],
        },
    )

    ok, output, err = email_read(ctx, "archived1")

    assert ok is True
    assert err is None
    assert json.loads(output)["subject"] == "Archived"


def test_email_send_handler_appends_same_payload_shape(tmp_path):
    state, ctx = _build_context(tmp_path)

    ok, output, err = email_send(ctx, "test@example.com", "Subject", "Body")

    assert ok is True
    assert err is None
    assert output == "sent"
    assert state.mail["sent"] == [{"to": "test@example.com", "subject": "Subject", "body": "Body"}]
    assert state.last_source == "tool"


def test_http_post_handler_preserves_blocked_and_allowed_egress(tmp_path):
    state, ctx = _build_context(tmp_path)

    ok, output, err = http_post(ctx, "http://localhost/internal", "secret")
    assert ok is False
    assert output == ""
    assert err == "private_net_blocked"
    assert state.egress_sink == []

    ok, output, err = http_post(ctx, "https://example.com/api", "payload")
    assert ok is True
    assert err is None
    assert output == "ok"
    assert state.egress_sink == [{"url": "https://example.com/api", "data": "payload"}]


def test_build_runtime_tool_spec_excludes_tool_context_and_preserves_metadata():
    tool_def = ToolDef(
        name="email.list",
        side_effect=ToolSideEffect.READ,
        scope=ToolScope.LOCAL,
        handler=email_list,
    )

    runtime_spec = build_runtime_tool_spec(tool_def)

    assert runtime_spec.name == "email.list"
    assert runtime_spec.side_effect == ToolSideEffect.READ
    assert runtime_spec.scope == ToolScope.LOCAL
    assert set(runtime_spec.parameters_json_schema["properties"]) == {"folder", "limit", "cursor"}
    assert "ctx" not in runtime_spec.parameters_json_schema["properties"]
    assert runtime_spec.parameters_json_schema["required"] == ["folder"]
    assert runtime_spec.parameters_json_schema["additionalProperties"] is False
    assert "discover message identifiers" in runtime_spec.description
    assert (
        runtime_spec.parameters_json_schema["properties"]["folder"]["description"]
        == "Local email folder name, such as inbox or archive."
    )


def test_invalid_handler_signature_rejects_context_not_first():
    def invalid_handler(query: str, ctx: ToolContext) -> ToolCallResult:
        return True, query, None

    with pytest.raises(TypeError):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_invalid_handler_signature_requires_tool_context_first():
    def invalid_handler(query: str) -> ToolCallResult:
        return True, query, None

    with pytest.raises(TypeError):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_invalid_handler_signature_rejects_multiple_contexts():
    def invalid_handler(
        ctx: ToolContext,
        other: ToolContext,
        value: str,
    ) -> ToolCallResult:
        return True, value, None

    with pytest.raises(TypeError):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_invalid_handler_signature_rejects_unsupported_parameter_kinds():
    def invalid_handler(ctx: ToolContext, *values: str) -> ToolCallResult:
        return True, str(len(values)), None

    with pytest.raises(TypeError):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_invalid_handler_signature_rejects_kwargs_parameters():
    def invalid_handler(ctx: ToolContext, **values: str) -> ToolCallResult:
        return True, str(len(values)), None

    with pytest.raises(TypeError):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_build_runtime_tool_spec_requires_google_style_args_entries():
    def invalid_handler(ctx: ToolContext, value: str) -> ToolCallResult:
        """Invalid docstring.

        Args:
            value (str): Description.
        """

        return True, value, None

    with pytest.raises(TypeError, match="simple Google-style"):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_build_runtime_tool_spec_requires_args_section_for_visible_parameters():
    def invalid_handler(ctx: ToolContext, value: str) -> ToolCallResult:
        """Invalid docstring without argument entries.

        Returns:
            Deterministic output.
        """

        return True, value, None

    with pytest.raises(TypeError, match="Google-style Args section"):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))


def test_build_runtime_tool_spec_allows_no_args_section_when_no_visible_parameters():
    def valid_handler(ctx: ToolContext) -> ToolCallResult:
        """Describe the tool.

        Returns:
            Deterministic output.
        """

        return True, "ok", None

    runtime_spec = build_runtime_tool_spec(_build_tool_def(valid_handler))

    assert runtime_spec.description == "Describe the tool."
    assert runtime_spec.parameters_json_schema["properties"] == {}
    assert runtime_spec.parameters_json_schema["required"] == []


@pytest.mark.parametrize("section_header", ["Returns:", "Raises:", "Examples:"])
def test_build_runtime_tool_spec_stops_args_parsing_at_supported_section_headers(
    section_header: str,
):
    def valid_handler(ctx: ToolContext, value: str) -> ToolCallResult:
        return True, value, None

    valid_handler.__doc__ = f"""Describe the tool.

Args:
    value: Visible argument description.
{section_header}
    Additional section content.
"""

    runtime_spec = build_runtime_tool_spec(_build_tool_def(valid_handler))

    assert runtime_spec.description == "Describe the tool."
    assert runtime_spec.parameters_json_schema["properties"]["value"]["description"] == (
        "Visible argument description."
    )


def test_build_runtime_tool_spec_treats_unknown_top_level_colon_lines_as_description():
    def valid_handler(ctx: ToolContext, value: str) -> ToolCallResult:
        return True, value, None

    valid_handler.__doc__ = """Describe the tool.

Overview:
More summary text.

Args:
    value: Visible argument description.
"""

    runtime_spec = build_runtime_tool_spec(_build_tool_def(valid_handler))

    assert runtime_spec.description == "Describe the tool. Overview: More summary text."


def test_build_runtime_tool_spec_uses_pydantic_for_visible_argument_schema():
    def valid_handler(ctx: ToolContext, values: list[str]) -> ToolCallResult:
        """Accept multiple values.

        Args:
            values: Ordered string values.
        """

        return True, json.dumps(values), None

    runtime_spec = build_runtime_tool_spec(_build_tool_def(valid_handler))

    assert runtime_spec.parameters_json_schema["properties"]["values"] == {
        "type": "array",
        "items": {"type": "string"},
        "description": "Ordered string values.",
    }


def test_build_runtime_tool_spec_reports_missing_args_in_parameter_order():
    def invalid_handler(
        ctx: ToolContext,
        alpha: str,
        beta: str,
        gamma: str,
    ) -> ToolCallResult:
        """Describe the tool.

        Args:
            gamma: Final value.
        """

        return True, alpha + beta + gamma, None

    with pytest.raises(TypeError, match=r"\['alpha', 'beta'\]"):
        build_runtime_tool_spec(_build_tool_def(invalid_handler))
