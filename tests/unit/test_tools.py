"""
Unit tests for aicomp_sdk.core.tools module.
Tests tool specifications and implementations with mocked I/O.
"""

import json

import pytest

from aicomp_sdk.agents.tool_specs import to_agent_tool_spec, to_agent_tool_specs
from aicomp_sdk.agents.types import AgentToolSpec
from aicomp_sdk.core.tools import (
    RuntimeToolSpec,
    ToolScope,
    ToolSideEffect,
    ToolSuite,
)
from aicomp_sdk.core.tools.http import PRIVATE_NET_RE


def _assert_rich_object_schema(schema):
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert properties
    for property_schema in properties.values():
        assert isinstance(property_schema["description"], str)
        assert property_schema["description"]
        if "type" in property_schema:
            assert property_schema["type"] in {"string", "integer"}
            continue
        assert "anyOf" in property_schema
        assert property_schema["anyOf"]


class TestRuntimeToolSpec:
    """Test RuntimeToolSpec dataclass."""

    def test_tool_spec_creation(self):
        """Test creating a RuntimeToolSpec."""
        spec = RuntimeToolSpec(
            name="test.tool",
            description="Test tool description with routing guidance.",
            side_effect=ToolSideEffect.READ,
            scope=ToolScope.LOCAL,
            parameters_json_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relative to the sandbox root.",
                    }
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        )

        assert spec.name == "test.tool"
        assert spec.description == "Test tool description with routing guidance."
        assert spec.side_effect == ToolSideEffect.READ
        assert spec.side_effect == "READ"
        assert spec.scope == ToolScope.LOCAL
        assert spec.scope == "local"
        assert spec.parameters_json_schema["required"] == ["path"]

    def test_enum_members_work_in_string_oriented_flows(self):
        payload = {
            "side_effect": ToolSideEffect.EXEC,
            "scope": ToolScope.EXTERNAL,
        }

        assert payload["side_effect"] in {"EXEC", "WRITE", "SHARE"}
        assert payload["scope"] == "external"
        assert json.dumps(payload, sort_keys=True) == (
            '{"scope": "external", "side_effect": "EXEC"}'
        )


class TestAgentToolSpecProjection:
    def test_to_agent_tool_spec_uses_runtime_metadata_directly(self):
        runtime_spec = RuntimeToolSpec(
            name="custom.tool",
            description="Canonical runtime description.",
            side_effect=ToolSideEffect.READ,
            scope=ToolScope.INTERNAL,
            parameters_json_schema={
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "Tool input value.",
                    }
                },
                "required": ["value"],
                "additionalProperties": False,
            },
        )

        agent_spec = to_agent_tool_spec(runtime_spec)

        assert agent_spec == AgentToolSpec(
            name="custom.tool",
            description="Canonical runtime description.",
            parameters_json_schema={
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "Tool input value.",
                    }
                },
                "required": ["value"],
                "additionalProperties": False,
            },
            strict=True,
        )

    def test_to_agent_tool_specs_projects_all_specs(self):
        runtime_specs = (
            RuntimeToolSpec(
                name="first.tool",
                description="First description.",
                side_effect=ToolSideEffect.READ,
                scope=ToolScope.LOCAL,
                parameters_json_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "First input.",
                        }
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            RuntimeToolSpec(
                name="second.tool",
                description="Second description.",
                side_effect=ToolSideEffect.SHARE,
                scope=ToolScope.EXTERNAL,
                parameters_json_schema={
                    "type": "object",
                    "properties": {
                        "body": {
                            "type": "string",
                            "description": "Second input.",
                        }
                    },
                    "required": ["body"],
                    "additionalProperties": False,
                },
            ),
        )

        projected_specs = to_agent_tool_specs(runtime_specs)

        assert tuple(spec.name for spec in projected_specs) == (
            "first.tool",
            "second.tool",
        )
        assert projected_specs[0].description == "First description."
        assert projected_specs[1].parameters_json_schema["required"] == ["body"]

    def test_to_agent_tool_spec_uses_canonical_rich_description(self):
        runtime_spec = RuntimeToolSpec(
            name="web.open",
            description=(
                "Open a public page from the offline web corpus by known page "
                "identifier. Do not use this for local file paths or email "
                "message identifiers."
            ),
            side_effect=ToolSideEffect.NETWORK,
            scope=ToolScope.PUBLIC,
            parameters_json_schema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Known public page identifier.",
                    }
                },
                "required": ["id"],
                "additionalProperties": False,
            },
        )

        agent_spec = to_agent_tool_spec(runtime_spec)

        assert (
            agent_spec.description
            == "Open a public page from the offline web corpus by known page identifier. Do not use this for local file paths or email message identifiers."
        )


class TestBuiltinRoutingSemantics:
    def test_builtins_project_routing_guidance(self, tmp_path):
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}', encoding="utf-8")
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}', encoding="utf-8")
        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "readme.txt").write_text("README", encoding="utf-8")

        tools = ToolSuite(fixtures_dir)
        projected = {spec.name: spec for spec in to_agent_tool_specs(tuple(tools.specs.values()))}

        assert "keywords or title" in projected["web.search"].description
        assert "known page identifier" in projected["web.open"].description
        assert "local file paths or email message identifiers" in projected["web.open"].description
        assert "relative file path" in projected["fs.read"].description
        assert (
            "web page identifiers or email message identifiers" in projected["fs.read"].description
        )
        assert "discover message identifiers" in projected["email.list"].description
        assert (
            "folder name"
            in projected["email.list"].parameters_json_schema["properties"]["folder"]["description"]
        )
        assert "known message identifier" in projected["email.read"].description


class TestPrivateNetRegex:
    """Test PRIVATE_NET_RE regex pattern."""

    def test_detects_localhost(self):
        """Test that localhost URLs are detected."""
        assert PRIVATE_NET_RE.search("http://localhost/api") is not None
        assert PRIVATE_NET_RE.search("https://localhost:8080") is not None

    def test_detects_127_addresses(self):
        """Test that 127.x.x.x addresses are detected."""
        assert PRIVATE_NET_RE.search("http://127.0.0.1/") is not None
        assert PRIVATE_NET_RE.search("http://127.1.1.1/") is not None

    def test_detects_10_network(self):
        """Test that 10.x.x.x addresses are detected."""
        assert PRIVATE_NET_RE.search("http://10.0.0.1/") is not None
        assert PRIVATE_NET_RE.search("http://10.255.255.255/") is not None

    def test_detects_192_168_network(self):
        """Test that 192.168.x.x addresses are detected."""
        assert PRIVATE_NET_RE.search("http://192.168.1.1/") is not None
        assert PRIVATE_NET_RE.search("http://192.168.0.1/") is not None

    def test_detects_172_16_31_network(self):
        """Test that 172.16-31.x.x addresses are detected."""
        assert PRIVATE_NET_RE.search("http://172.16.0.1/") is not None
        assert PRIVATE_NET_RE.search("http://172.31.255.255/") is not None

    def test_allows_public_addresses(self):
        """Test that public addresses are not detected."""
        assert PRIVATE_NET_RE.search("https://example.com/") is None
        assert PRIVATE_NET_RE.search("https://8.8.8.8/") is None
        assert PRIVATE_NET_RE.search("https://172.15.0.1/") is None
        assert PRIVATE_NET_RE.search("https://172.32.0.1/") is None


class TestToolSuiteInitialization:
    """Test ToolSuite initialization and setup."""

    @pytest.fixture
    def temp_fixtures(self, tmp_path):
        """Create temporary fixture files."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()

        # Create web corpus
        web_corpus = {"pages": [{"id": "page1", "title": "Test Page", "content": "Test content"}]}
        (fixtures_dir / "web_corpus.json").write_text(json.dumps(web_corpus))

        # Create mail seed
        mail_seed = {
            "inbox": [
                {
                    "id": "msg1",
                    "from": "sender@example.com",
                    "subject": "Test",
                    "body": "Test email",
                }
            ]
        }
        (fixtures_dir / "mail_seed.json").write_text(json.dumps(mail_seed))

        # Create file seed directory with files
        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "readme.txt").write_text("README content")
        (file_seed / "secret.txt").write_text("SECRET_MARKER")
        (file_seed / "config.txt").write_text("config data")

        return fixtures_dir

    def test_toolsuite_initialization(self, temp_fixtures):
        """Test that ToolSuite initializes with fixtures."""
        tools = ToolSuite(temp_fixtures)
        tools_state = tools.snapshot_state()

        assert tools.fixtures_dir == temp_fixtures
        assert tools.filesystem_root == temp_fixtures / "file_seed"
        assert len(tools_state["mail"]["inbox"]) == 1
        assert tools.last_source == "user"
        assert tools.get_egress() == []

    def test_toolsuite_loads_all_specs(self, temp_fixtures):
        """Test that all tool specifications are loaded."""
        tools = ToolSuite(temp_fixtures)

        expected_tools = [
            "web.search",
            "web.open",
            "fs.read",
            "fs.write",
            "fs.delete",
            "shell.run",
            "email.list",
            "email.read",
            "email.send",
            "http.post",
        ]

        for tool_name in expected_tools:
            assert tool_name in tools.specs
            assert isinstance(tools.specs[tool_name], RuntimeToolSpec)

    def test_toolsuite_specs_include_rich_parameter_descriptions(self, temp_fixtures):
        tools = ToolSuite(temp_fixtures)

        for spec in tools.specs.values():
            assert spec.description
            _assert_rich_object_schema(spec.parameters_json_schema)

    def test_toolsuite_backups_files(self, temp_fixtures):
        """Test that reset restores top-level seeded file contents."""
        tools = ToolSuite(temp_fixtures)
        secret_path = tools.filesystem_root / "secret.txt"
        secret_path.write_text("changed")
        tools.reset(42)

        assert secret_path.read_text() == "SECRET_MARKER"


class TestToolSuiteReset:
    """Test ToolSuite reset functionality."""

    @pytest.fixture
    def temp_fixtures(self, tmp_path):
        """Create temporary fixture files."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": [{"id": "msg1"}]}')
        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "test.txt").write_text("original")
        return fixtures_dir

    def test_reset_clears_egress(self, temp_fixtures):
        """Test that reset clears egress sink."""
        tools = ToolSuite(temp_fixtures)
        tools.call("http.post", {"url": "https://example.com", "data": "test"})

        tools.reset(42)

        assert tools.get_egress() == []

    def test_reset_restores_last_source(self, temp_fixtures):
        """Test that reset restores last_source to 'user'."""
        tools = ToolSuite(temp_fixtures)
        tools.call("web.search", {"query": "missing"})

        tools.reset(42)

        assert tools.last_source == "user"

    def test_reset_restores_mail(self, temp_fixtures):
        """Test that reset restores mail from seed."""
        tools = ToolSuite(temp_fixtures)
        mutated_state = json.loads(json.dumps(tools.snapshot_state()))

        mutated_state["mail"]["inbox"] = []
        mutated_state["mail"]["sent"] = [{"to": "test@example.com"}]
        tools.restore_state(mutated_state)

        # Reset
        tools.reset(42)
        reset_state = tools.snapshot_state()

        # Mail should be restored
        assert len(reset_state["mail"]["inbox"]) == 1
        assert "sent" not in reset_state["mail"] or len(reset_state["mail"].get("sent", [])) == 0

    def test_reset_restores_files(self, temp_fixtures):
        """Test that reset restores files from backup."""
        tools = ToolSuite(temp_fixtures)
        file_path = temp_fixtures / "file_seed" / "test.txt"

        # Modify file
        file_path.write_text("modified")
        assert file_path.read_text() == "modified"

        # Reset
        tools.reset(42)

        # File should be restored
        assert file_path.read_text() == "original"

    def test_reset_deletes_new_files(self, temp_fixtures):
        """Test that reset deletes files created during episode."""
        tools = ToolSuite(temp_fixtures)

        # Create a new file (not in backup)
        new_file_path = temp_fixtures / "file_seed" / "newfile.txt"
        new_file_path.write_text("new content")
        assert new_file_path.exists()

        # Reset
        tools.reset(42)

        # New file should be deleted
        assert not new_file_path.exists()
        # Original file should still exist
        assert (temp_fixtures / "file_seed" / "test.txt").exists()


class TestToolValidation:
    """Test tool argument validation."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite instance."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def test_validate_unknown_tool(self, tools):
        """Test that unknown tools raise ValueError."""
        with pytest.raises(ValueError, match="Unknown tool"):
            tools.validate("unknown.tool", {})

    def test_validate_missing_required_keys(self, tools):
        """Test that missing required keys raise ValueError."""
        with pytest.raises(ValueError, match="Missing keys"):
            tools.validate("fs.read", {})  # Missing 'path'

    def test_validate_extra_keys_not_allowed(self, tools):
        """Test that extra keys raise ValueError when not allowed."""
        with pytest.raises(ValueError, match="Extra keys"):
            tools.validate("fs.read", {"path": "test.txt", "extra": "value"})

    def test_validate_correct_args_pass(self, tools):
        """Test that correct arguments pass validation."""
        # Should not raise
        tools.validate("fs.read", {"path": "test.txt"})
        tools.validate("web.search", {"query": "test"})
        tools.validate("shell.run", {"cmd": "echo test"})

    def test_validate_does_not_enforce_argument_types(self, tools):
        """Test that validation only checks key presence and extra keys."""
        tools.validate("fs.read", {"path": 123})
        tools.validate("email.list", {"folder": "inbox", "limit": "20"})

    def test_call_preserves_handler_level_type_behavior(self, tools):
        """Test that call dispatches directly without adding schema type checks."""
        result = tools.call("email.list", {"folder": "inbox", "limit": "20"})

        assert result == (False, "", "invalid_limit")


class TestWebTools:
    """Test web-related tools (web.search, web.open)."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite with web corpus."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()

        web_corpus = {
            "pages": [
                {
                    "id": "page1",
                    "title": "Welcome Page",
                    "content": "Welcome to the site",
                },
                {
                    "id": "page2",
                    "title": "Documentation",
                    "content": "How to use the system",
                },
            ]
        }
        (fixtures_dir / "web_corpus.json").write_text(json.dumps(web_corpus))
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        (fixtures_dir / "file_seed").mkdir()

        return ToolSuite(fixtures_dir)

    def test_web_search_finds_pages(self, tools):
        """Test that web.search finds matching pages."""
        ok, output, err = tools.call("web.search", {"query": "welcome"})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert len(result["results"]) > 0
        assert any(r["id"] == "page1" for r in result["results"])

    def test_web_search_returns_welcome_on_no_match(self, tools):
        """Test that web.search returns welcome page when no match."""
        ok, output, err = tools.call("web.search", {"query": "nonexistent"})

        assert ok is True
        result = json.loads(output)
        assert len(result["results"]) > 0
        assert result["results"][0]["id"] == "page_0"  # Fixed: fallback now uses existing page
        assert result["results"][0]["title"] == "Welcome"

    def test_web_search_sets_source(self, tools):
        """Test that web.search sets source to 'web'."""
        tools.call("web.search", {"query": "test"})
        assert tools.last_source == "web"

    def test_web_open_returns_page_content(self, tools):
        """Test that web.open returns page content."""
        ok, output, err = tools.call("web.open", {"id": "page1"})

        assert ok is True
        assert err is None
        assert "Welcome to the site" in output

    def test_web_open_nonexistent_page(self, tools):
        """Test that web.open fails for nonexistent pages."""
        ok, output, err = tools.call("web.open", {"id": "nonexistent"})

        assert ok is False
        assert err == "not_found"
        assert output == ""

    def test_web_open_sets_source(self, tools):
        """Test that web.open sets source to 'web'."""
        tools.call("web.open", {"id": "page1"})
        assert tools.last_source == "web"


class TestFileSystemTools:
    """Test filesystem tools (fs.read, fs.write, fs.delete)."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite with file system."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')

        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "readme.txt").write_text("README content")
        (file_seed / "secret.txt").write_text("SECRET_MARKER")

        return ToolSuite(fixtures_dir)

    def test_fs_read_existing_file(self, tools):
        """Test reading an existing file."""
        ok, output, err = tools.call("fs.read", {"path": "readme.txt"})

        assert ok is True
        assert err is None
        assert output == "README content"

    def test_fs_read_strips_leading_slash(self, tools):
        """Test reading a file with a leading slash path."""
        ok, output, err = tools.call("fs.read", {"path": "/readme.txt"})

        assert ok is True
        assert err is None
        assert output == "README content"

    def test_fs_read_nonexistent_file(self, tools):
        """Test reading a nonexistent file."""
        ok, output, err = tools.call("fs.read", {"path": "nonexistent.txt"})

        assert ok is False
        assert err == "not_found"
        assert output == ""

    def test_fs_read_prevents_path_escape(self, tools):
        """Test that fs.read prevents path traversal."""
        ok, output, err = tools.call("fs.read", {"path": "../../etc/passwd"})

        assert ok is False
        assert err == "path_escape"

    def test_fs_read_directory_fails(self, tools, tmp_path):
        """Test that reading a directory fails."""
        # Create a subdirectory
        subdir = tmp_path / "fixtures" / "file_seed" / "subdir"
        subdir.mkdir()

        ok, output, err = tools.call("fs.read", {"path": "subdir"})

        assert ok is False
        assert err == "is_directory"

    def test_fs_read_sets_source(self, tools):
        """Test that fs.read sets source to 'file'."""
        tools.call("fs.read", {"path": "readme.txt"})
        assert tools.last_source == "file"

    def test_fs_write_creates_file(self, tools, tmp_path):
        """Test writing a new file."""
        ok, output, err = tools.call("fs.write", {"path": "newfile.txt", "content": "new content"})

        assert ok is True
        assert err is None
        assert output == "ok"

        # Verify file was created
        file_path = tmp_path / "fixtures" / "file_seed" / "newfile.txt"
        assert file_path.exists()
        assert file_path.read_text() == "new content"

    def test_fs_write_overwrites_existing(self, tools, tmp_path):
        """Test overwriting an existing file."""
        ok, output, err = tools.call("fs.write", {"path": "readme.txt", "content": "overwritten"})

        assert ok is True
        file_path = tmp_path / "fixtures" / "file_seed" / "readme.txt"
        assert file_path.read_text() == "overwritten"

    def test_fs_write_creates_parent_directories(self, tools, tmp_path):
        """Test writing to a nested path creates missing parents."""
        ok, output, err = tools.call(
            "fs.write",
            {"path": "nested/deep/file.txt", "content": "nested content"},
        )

        assert ok is True
        assert err is None
        assert output == "ok"
        file_path = tmp_path / "fixtures" / "file_seed" / "nested" / "deep" / "file.txt"
        assert file_path.read_text() == "nested content"

    def test_fs_write_prevents_path_escape(self, tools):
        """Test that fs.write prevents path traversal."""
        ok, output, err = tools.call("fs.write", {"path": "../../../etc/passwd", "content": "bad"})

        assert ok is False
        assert err == "path_escape"

    def test_fs_write_sets_source(self, tools):
        """Test that fs.write sets source to 'file'."""
        tools.call("fs.write", {"path": "test.txt", "content": "test"})
        assert tools.last_source == "file"

    def test_fs_delete_removes_file(self, tools, tmp_path):
        """Test deleting an existing file."""
        file_path = tmp_path / "fixtures" / "file_seed" / "readme.txt"
        assert file_path.exists()

        ok, output, err = tools.call("fs.delete", {"path": "readme.txt"})

        assert ok is True
        assert err is None
        assert output == "ok"
        assert not file_path.exists()

    def test_fs_delete_nonexistent_file(self, tools):
        """Test deleting a nonexistent file."""
        ok, output, err = tools.call("fs.delete", {"path": "nonexistent.txt"})

        assert ok is False
        assert err == "not_found"

    def test_fs_delete_prevents_path_escape(self, tools):
        """Test that fs.delete prevents path traversal."""
        ok, output, err = tools.call("fs.delete", {"path": "../../important.txt"})

        assert ok is False
        assert err == "path_escape"

    def test_fs_delete_sets_source(self, tools):
        """Test that fs.delete sets source to 'file'."""
        tools.call("fs.delete", {"path": "readme.txt"})
        assert tools.last_source == "file"


class TestShellTool:
    """Test shell.run tool."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "file1.txt").write_text("content1")
        (file_seed / "file2.txt").write_text("content2")
        return ToolSuite(fixtures_dir)

    def test_shell_echo_command(self, tools):
        """Test running echo command."""
        ok, output, err = tools.call("shell.run", {"cmd": "echo hello world"})

        assert ok is True
        assert err is None
        assert output == "hello world"

    def test_shell_ls_command(self, tools):
        """Test running ls command."""
        ok, output, err = tools.call("shell.run", {"cmd": "ls"})

        assert ok is True
        assert "file1.txt" in output
        assert "file2.txt" in output

    def test_shell_pwd_command(self, tools, tmp_path):
        """Test running pwd command."""
        ok, output, err = tools.call("shell.run", {"cmd": "pwd"})

        assert ok is True
        assert str(tmp_path / "fixtures" / "file_seed") in output

    def test_shell_whoami_command(self, tools):
        """Test running whoami command."""
        ok, output, err = tools.call("shell.run", {"cmd": "whoami"})

        assert ok is True
        assert output == "sandbox"

    def test_shell_date_command(self, tools):
        """Test running date command."""
        ok, output, err = tools.call("shell.run", {"cmd": "date"})

        assert ok is True
        assert output == "1970-01-01"

    def test_shell_blocks_dangerous_commands(self, tools):
        """Test that dangerous commands are blocked."""
        ok, output, err = tools.call("shell.run", {"cmd": "rm -rf /"})

        assert ok is False
        assert err == "cmd_not_allowed"

    def test_shell_blocks_arbitrary_commands(self, tools):
        """Test that arbitrary commands are blocked."""
        ok, output, err = tools.call("shell.run", {"cmd": "curl http://evil.com"})

        assert ok is False
        assert err == "cmd_not_allowed"

    def test_shell_preserves_prefix_allowlist_behavior(self, tools):
        """Test that prefixed allowlisted commands still pass through."""
        ok, output, err = tools.call("shell.run", {"cmd": "ls -la"})

        assert ok is True
        assert err is None
        assert output == "ok"

    def test_shell_sets_source(self, tools):
        """Test that shell.run sets source to 'tool'."""
        tools.call("shell.run", {"cmd": "whoami"})
        assert tools.last_source == "tool"


class TestEmailTools:
    """Test email tools (email.read, email.send)."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite with email data."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')

        mail_seed = {
            "inbox": [
                {
                    "id": "msg1",
                    "from": "alice@example.com",
                    "subject": "Hello",
                    "body": "Hello world",
                },
                {
                    "id": "msg2",
                    "from": "bob@example.com",
                    "subject": "Test",
                    "body": "Test message",
                },
            ]
        }
        (fixtures_dir / "mail_seed.json").write_text(json.dumps(mail_seed))
        (fixtures_dir / "file_seed").mkdir()

        return ToolSuite(fixtures_dir)

    def _build_tools_with_inbox(self, tmp_path, inbox):
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text(json.dumps({"inbox": inbox}))
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def _build_tools_with_mail(self, tmp_path, mail_seed):
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text(json.dumps(mail_seed))
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def test_email_list_returns_inbox_summaries(self, tools):
        """Test that email.list returns email summaries."""
        ok, output, err = tools.call("email.list", {"folder": "inbox"})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert result["folder"] == "inbox"
        assert "emails" in result
        assert len(result["emails"]) == 2
        assert result["next_cursor"] is None
        assert result["has_more"] is False

        # Check first email summary
        assert result["emails"][0]["id"] == "msg1"
        assert result["emails"][0]["from"] == "alice@example.com"
        assert result["emails"][0]["subject"] == "Hello"
        assert "body" not in result["emails"][0]  # Body not included in summary

    def test_email_list_custom_limit_returns_requested_page_size(self, tmp_path):
        inbox = [
            {
                "id": f"msg{i}",
                "from": f"user{i}@example.com",
                "subject": f"Subject {i}",
                "body": f"Body {i}",
            }
            for i in range(30)
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox", "limit": 5})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert len(result["emails"]) == 5
        assert result["emails"][0]["id"] == "msg0"
        assert result["emails"][-1]["id"] == "msg4"
        assert result["next_cursor"] == "5"
        assert result["has_more"] is True

    def test_email_list_clamps_limit_to_hard_max(self, tmp_path):
        inbox = [
            {
                "id": f"msg{i}",
                "from": f"user{i}@example.com",
                "subject": f"Subject {i}",
                "body": f"Body {i}",
            }
            for i in range(80)
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox", "limit": 500})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert len(result["emails"]) == 50
        assert result["next_cursor"] == "50"
        assert result["has_more"] is True

    def test_email_list_cursor_advances_deterministically(self, tmp_path):
        inbox = [
            {
                "id": f"msg{i}",
                "from": f"user{i}@example.com",
                "subject": f"Subject {i}",
                "body": f"Body {i}",
            }
            for i in range(8)
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox", "limit": 3})
        assert ok is True
        assert err is None
        first_page = json.loads(output)

        ok, output, err = tools.call(
            "email.list",
            {"folder": "inbox", "limit": 3, "cursor": first_page["next_cursor"]},
        )

        assert ok is True
        assert err is None
        second_page = json.loads(output)
        assert [email["id"] for email in first_page["emails"]] == [
            "msg0",
            "msg1",
            "msg2",
        ]
        assert [email["id"] for email in second_page["emails"]] == [
            "msg3",
            "msg4",
            "msg5",
        ]
        assert second_page["next_cursor"] == "6"
        assert second_page["has_more"] is True

    def test_email_list_out_of_range_cursor_returns_empty_page(self, tmp_path):
        inbox = [
            {
                "id": "msg1",
                "from": "alice@example.com",
                "subject": "Hello",
                "body": "Hello world",
            }
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox", "cursor": "99"})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert result["emails"] == []
        assert result["next_cursor"] is None
        assert result["has_more"] is False

    @pytest.mark.parametrize("cursor", ["abc", "-1", 1])
    def test_email_list_invalid_cursor_returns_error(self, tools, cursor):
        ok, output, err = tools.call("email.list", {"folder": "inbox", "cursor": cursor})

        assert ok is False
        assert output == ""
        assert err == "invalid_cursor"

    @pytest.mark.parametrize("limit", [0, -1, "20", True])
    def test_email_list_invalid_limit_returns_error(self, tools, limit):
        ok, output, err = tools.call("email.list", {"folder": "inbox", "limit": limit})

        assert ok is False
        assert output == ""
        assert err == "invalid_limit"

    def test_email_list_none_limit_uses_default_page_size(self, tmp_path):
        inbox = [
            {
                "id": f"msg{i}",
                "from": f"user{i}@example.com",
                "subject": f"Subject {i}",
                "body": f"Body {i}",
            }
            for i in range(30)
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox", "limit": None})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert len(result["emails"]) == 20
        assert result["next_cursor"] == "20"
        assert result["has_more"] is True

    def test_email_list_nonexistent_folder(self, tools):
        """Test that email.list fails for nonexistent folders."""
        ok, output, err = tools.call("email.list", {"folder": "nonexistent"})

        assert ok is False
        assert err == "folder_not_found"

    def test_email_list_sets_source(self, tools):
        """Test that email.list sets source to 'email'."""
        tools.call("email.list", {"folder": "inbox"})
        assert tools.last_source == "email"

    def test_email_list_large_mailbox_stays_bounded(self, tmp_path):
        inbox = [
            {
                "id": f"msg{i}",
                "from": f"user{i}@example.com",
                "subject": f"Subject line {i}",
                "body": "X" * 1000,
            }
            for i in range(200)
        ]
        tools = self._build_tools_with_inbox(tmp_path, inbox)

        ok, output, err = tools.call("email.list", {"folder": "inbox"})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert len(result["emails"]) == 20
        assert result["next_cursor"] == "20"
        assert result["has_more"] is True
        assert len(output) < 5000

    def test_email_read_existing_message(self, tools):
        """Test reading an existing email."""
        ok, output, err = tools.call("email.read", {"id": "msg1"})

        assert ok is True
        assert err is None
        msg = json.loads(output)
        assert msg["id"] == "msg1"
        assert msg["from"] == "alice@example.com"
        assert msg["subject"] == "Hello"

    def test_email_read_nonexistent_message(self, tools):
        """Test reading a nonexistent email."""
        ok, output, err = tools.call("email.read", {"id": "nonexistent"})

        assert ok is False
        assert err == "not_found"

    def test_email_read_searches_all_folders(self, tmp_path):
        tools = self._build_tools_with_mail(
            tmp_path,
            {
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

        ok, output, err = tools.call("email.read", {"id": "archived1"})

        assert ok is True
        assert err is None
        msg = json.loads(output)
        assert msg["subject"] == "Archived"

    def test_email_read_sets_source(self, tools):
        """Test that email.read sets source to 'email'."""
        tools.call("email.read", {"id": "msg1"})
        assert tools.last_source == "email"

    def test_email_send_stores_message(self, tools):
        """Test that email.send stores the sent message."""
        ok, output, err = tools.call(
            "email.send",
            {"to": "test@example.com", "subject": "Test Subject", "body": "Test Body"},
        )

        assert ok is True
        assert err is None
        assert output == "sent"

        # Check that message was stored
        sent_mail = tools.snapshot_state()["mail"]["sent"]
        assert len(sent_mail) == 1
        assert sent_mail[0]["to"] == "test@example.com"

    def test_email_send_multiple_messages(self, tools):
        """Test sending multiple emails."""
        tools.call("email.send", {"to": "user1@example.com", "subject": "s1", "body": "b1"})
        tools.call("email.send", {"to": "user2@example.com", "subject": "s2", "body": "b2"})

        assert len(tools.snapshot_state()["mail"]["sent"]) == 2

    def test_email_send_sets_source(self, tools):
        """Test that email.send sets source to 'tool'."""
        tools.call("email.send", {"to": "test@example.com", "subject": "s", "body": "b"})
        assert tools.last_source == "tool"


class TestHttpTool:
    """Test http.post tool."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def test_http_post_to_public_url(self, tools):
        """Test posting to a public URL."""
        ok, output, err = tools.call(
            "http.post", {"url": "https://example.com/api", "data": "test data"}
        )

        assert ok is True
        assert err is None
        assert output == "ok"

    def test_http_post_stores_egress(self, tools):
        """Test that http.post stores egress data."""
        tools.call("http.post", {"url": "https://example.com", "data": "secret"})

        egress = tools.get_egress()
        assert len(egress) == 1
        assert egress[0]["url"] == "https://example.com"
        assert egress[0]["data"] == "secret"

    def test_http_post_blocks_private_networks(self, tools):
        """Test that http.post blocks private network addresses."""
        ok, output, err = tools.call("http.post", {"url": "http://localhost/api", "data": "test"})

        assert ok is False
        assert err == "private_net_blocked"

    def test_http_post_blocks_127_addresses(self, tools):
        """Test that http.post blocks 127.x.x.x addresses."""
        ok, output, err = tools.call("http.post", {"url": "http://127.0.0.1/api", "data": "test"})

        assert ok is False
        assert err == "private_net_blocked"

    def test_http_post_blocks_10_network(self, tools):
        """Test that http.post blocks 10.x.x.x network."""
        ok, output, err = tools.call("http.post", {"url": "http://10.0.0.1/api", "data": "test"})

        assert ok is False
        assert err == "private_net_blocked"

    def test_http_post_blocked_requests_do_not_append_egress(self, tools):
        """Test that blocked POSTs do not reach the egress sink."""
        ok, output, err = tools.call(
            "http.post",
            {"url": "http://localhost/internal", "data": "secret"},
        )

        assert ok is False
        assert output == ""
        assert err == "private_net_blocked"
        assert tools.get_egress() == []

    def test_http_post_sets_source(self, tools):
        """Test that http.post sets source to 'tool'."""
        tools.call("http.post", {"url": "https://example.com", "data": "test"})
        assert tools.last_source == "tool"

    def test_http_post_multiple_requests(self, tools):
        """Test multiple http.post requests."""
        tools.call("http.post", {"url": "https://site1.com", "data": "data1"})
        tools.call("http.post", {"url": "https://site2.com", "data": "data2"})

        egress = tools.get_egress()
        assert len(egress) == 2


class TestToolSuiteEgress:
    """Test egress tracking functionality."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def test_get_egress_empty_initially(self, tools):
        """Test that egress is empty initially."""
        egress = tools.get_egress()
        assert egress == []

    def test_get_egress_returns_copy(self, tools):
        """Test that get_egress returns a copy, not the original."""
        tools.call("http.post", {"url": "https://example.com", "data": "test"})

        egress1 = tools.get_egress()
        egress1.append({"url": "fake", "data": "fake"})

        egress2 = tools.get_egress()
        assert len(egress2) == 1  # Should not include the fake entry


class TestToolCallErrors:
    """Test error handling in tool calls."""

    @pytest.fixture
    def tools(self, tmp_path):
        """Create a ToolSuite."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        (fixtures_dir / "file_seed").mkdir()
        return ToolSuite(fixtures_dir)

    def test_call_unknown_tool(self, tools):
        """Test calling an unknown tool."""
        with pytest.raises(ValueError, match="Unknown tool"):
            tools.call("unknown.tool", {})

    def test_call_with_invalid_args_raises(self, tools):
        """Test that calling with invalid args raises ValueError."""
        with pytest.raises(ValueError):
            tools.call("fs.read", {})  # Missing required 'path'


class TestResetParity:
    """Characterization tests for current reset behavior."""

    def test_reset_drops_seeded_nested_directories_due_to_top_level_backup(self, tmp_path):
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')
        file_seed = fixtures_dir / "file_seed"
        nested_dir = file_seed / "nested"
        nested_dir.mkdir(parents=True)
        nested_file = nested_dir / "seeded.txt"
        nested_file.write_text("seeded")

        tools = ToolSuite(fixtures_dir)
        nested_file.write_text("modified")

        tools.reset(seed=999)

        assert not nested_dir.exists()
