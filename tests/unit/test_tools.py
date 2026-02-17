"""
Unit tests for aicomp_sdk.core.tools module.
Tests tool specifications and implementations with mocked I/O.
"""

import json
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from aicomp_sdk.core.tools import PRIVATE_NET_RE, ToolSpec, ToolSuite


class TestToolSpec:
    """Test ToolSpec dataclass."""

    def test_tool_spec_creation(self):
        """Test creating a ToolSpec."""
        spec = ToolSpec(
            name="test.tool",
            side_effect="READ",
            scope="local",
            schema={"type": "object"},
        )

        assert spec.name == "test.tool"
        assert spec.side_effect == "READ"
        assert spec.scope == "local"
        assert spec.schema == {"type": "object"}


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

        assert tools.fixtures_dir == temp_fixtures
        assert len(tools._web["pages"]) == 1
        assert len(tools._mail_seed["inbox"]) == 1
        assert len(tools._fs_backup) == 3  # readme, secret, config
        assert tools._last_source == "user"
        assert tools._egress_sink == []

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
            assert isinstance(tools.specs[tool_name], ToolSpec)

    def test_toolsuite_backups_files(self, temp_fixtures):
        """Test that ToolSuite backs up original file contents."""
        tools = ToolSuite(temp_fixtures)

        assert "readme.txt" in tools._fs_backup
        assert "secret.txt" in tools._fs_backup
        assert tools._fs_backup["secret.txt"] == "SECRET_MARKER"


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
        tools._egress_sink = [{"url": "https://example.com", "data": "test"}]

        tools.reset(42)

        assert tools._egress_sink == []

    def test_reset_restores_last_source(self, temp_fixtures):
        """Test that reset restores last_source to 'user'."""
        tools = ToolSuite(temp_fixtures)
        tools._last_source = "web"

        tools.reset(42)

        assert tools._last_source == "user"

    def test_reset_restores_mail(self, temp_fixtures):
        """Test that reset restores mail from seed."""
        tools = ToolSuite(temp_fixtures)

        # Modify mail
        tools._mail["inbox"] = []
        tools._mail["sent"] = [{"to": "test@example.com"}]

        # Reset
        tools.reset(42)

        # Mail should be restored
        assert len(tools._mail["inbox"]) == 1
        assert "sent" not in tools._mail or len(tools._mail.get("sent", [])) == 0

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

    def test_web_search_sets_source(self, tools):
        """Test that web.search sets source to 'web'."""
        tools.call("web.search", {"query": "test"})
        assert tools.last_source() == "web"

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
        assert tools.last_source() == "web"


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
        assert tools.last_source() == "file"

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

    def test_fs_write_prevents_path_escape(self, tools):
        """Test that fs.write prevents path traversal."""
        ok, output, err = tools.call("fs.write", {"path": "../../../etc/passwd", "content": "bad"})

        assert ok is False
        assert err == "path_escape"

    def test_fs_write_sets_source(self, tools):
        """Test that fs.write sets source to 'file'."""
        tools.call("fs.write", {"path": "test.txt", "content": "test"})
        assert tools.last_source() == "file"

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
        assert tools.last_source() == "file"


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

    def test_shell_sets_source(self, tools):
        """Test that shell.run sets source to 'tool'."""
        tools.call("shell.run", {"cmd": "whoami"})
        assert tools.last_source() == "tool"


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

    def test_email_list_returns_inbox_summaries(self, tools):
        """Test that email.list returns email summaries."""
        ok, output, err = tools.call("email.list", {"folder": "inbox"})

        assert ok is True
        assert err is None
        result = json.loads(output)
        assert "emails" in result
        assert len(result["emails"]) == 2

        # Check first email summary
        assert result["emails"][0]["id"] == "msg1"
        assert result["emails"][0]["from"] == "alice@example.com"
        assert result["emails"][0]["subject"] == "Hello"
        assert "body" not in result["emails"][0]  # Body not included in summary

    def test_email_list_nonexistent_folder(self, tools):
        """Test that email.list fails for nonexistent folders."""
        ok, output, err = tools.call("email.list", {"folder": "nonexistent"})

        assert ok is False
        assert err == "folder_not_found"

    def test_email_list_sets_source(self, tools):
        """Test that email.list sets source to 'email'."""
        tools.call("email.list", {"folder": "inbox"})
        assert tools.last_source() == "email"

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

    def test_email_read_sets_source(self, tools):
        """Test that email.read sets source to 'email'."""
        tools.call("email.read", {"id": "msg1"})
        assert tools.last_source() == "email"

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
        assert "sent" in tools._mail
        assert len(tools._mail["sent"]) == 1
        assert tools._mail["sent"][0]["to"] == "test@example.com"

    def test_email_send_multiple_messages(self, tools):
        """Test sending multiple emails."""
        tools.call("email.send", {"to": "user1@example.com", "subject": "s1", "body": "b1"})
        tools.call("email.send", {"to": "user2@example.com", "subject": "s2", "body": "b2"})

        assert len(tools._mail["sent"]) == 2

    def test_email_send_sets_source(self, tools):
        """Test that email.send sets source to 'tool'."""
        tools.call("email.send", {"to": "test@example.com", "subject": "s", "body": "b"})
        assert tools.last_source() == "tool"


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

    def test_http_post_sets_source(self, tools):
        """Test that http.post sets source to 'tool'."""
        tools.call("http.post", {"url": "https://example.com", "data": "test"})
        assert tools.last_source() == "tool"

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
