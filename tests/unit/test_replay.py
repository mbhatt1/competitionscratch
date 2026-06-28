"""
Unit tests for aicomp_sdk.core.replay module.
Tests replay harness functionality for reproducing traces.
"""

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from aicomp_sdk.core.replay import ReplayHarness


class TestReplayHarness:
    """Test ReplayHarness initialization and replay functionality."""

    @pytest.fixture
    def temp_fixtures(self, tmp_path):
        """Create temporary fixture directory."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()

        # Create minimal required fixtures
        (fixtures_dir / "web_corpus.json").write_text('{"pages": []}')
        (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}')

        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "test.txt").write_text("test content")

        return fixtures_dir

    def test_harness_initialization(self, temp_fixtures):
        """Test that ReplayHarness initializes correctly."""
        harness = ReplayHarness(temp_fixtures)

        assert harness.fixtures_dir == temp_fixtures
        assert isinstance(harness.fixtures_dir, Path)

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_creates_sandbox_env(self, mock_env_class, temp_fixtures):
        """Test that replay creates a SandboxEnv with correct parameters."""
        # Setup mock environment
        mock_env_instance = MagicMock()
        mock_env_class.return_value = mock_env_instance
        mock_env_instance.export_trace_dict.return_value = {"seed": 42}

        # Create harness and replay
        harness = ReplayHarness(temp_fixtures)
        mock_agent = Mock()
        mock_guardrail = Mock()

        result = harness.replay(
            seed=42,
            user_messages=["message1", "message2"],
            agent=mock_agent,
            guardrail=mock_guardrail,
        )

        # Verify SandboxEnv was created with correct parameters
        mock_env_class.assert_called_once()
        call_kwargs = mock_env_class.call_args[1]
        assert call_kwargs["seed"] == 42
        assert call_kwargs["fixtures_dir"] == temp_fixtures
        assert call_kwargs["agent"] == mock_agent
        assert call_kwargs["guardrail"] == mock_guardrail

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_resets_environment(self, mock_env_class, temp_fixtures):
        """Test that replay resets the environment before replaying."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = {}
        mock_env_class.return_value = mock_env_instance

        # Replay
        harness = ReplayHarness(temp_fixtures)
        harness.replay(42, [], Mock(), Mock())

        # Verify reset was called
        mock_env_instance.reset.assert_called_once()

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_interacts_with_user_messages(self, mock_env_class, temp_fixtures):
        """Test that replay interacts with all user messages in order."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = {"messages": []}
        mock_env_class.return_value = mock_env_instance

        # Replay with multiple messages
        harness = ReplayHarness(temp_fixtures)
        user_messages = ["message1", "message2", "message3"]
        harness.replay(42, user_messages, Mock(), Mock())

        # Verify interact was called for each message in order
        assert mock_env_instance.interact.call_count == 3
        calls = mock_env_instance.interact.call_args_list
        assert calls[0][0][0] == "message1"
        assert calls[1][0][0] == "message2"
        assert calls[2][0][0] == "message3"

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_returns_trace_dict(self, mock_env_class, temp_fixtures):
        """Test that replay returns the exported trace dictionary."""
        # Setup mock with expected trace
        expected_trace = {
            "seed": 42,
            "user_messages": ["test"],
            "tool_events": [],
            "egress": [],
        }
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = expected_trace
        mock_env_class.return_value = mock_env_instance

        # Replay
        harness = ReplayHarness(temp_fixtures)
        result = harness.replay(42, ["test"], Mock(), Mock())

        # Verify we got the expected trace
        assert result == expected_trace
        mock_env_instance.export_trace_dict.assert_called_once()

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_with_empty_messages(self, mock_env_class, temp_fixtures):
        """Test that replay works with empty user messages list."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = {}
        mock_env_class.return_value = mock_env_instance

        # Replay with no messages
        harness = ReplayHarness(temp_fixtures)
        result = harness.replay(42, [], Mock(), Mock())

        # Should still reset and export, but no interactions
        mock_env_instance.reset.assert_called_once()
        mock_env_instance.interact.assert_not_called()
        mock_env_instance.export_trace_dict.assert_called_once()

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_with_single_message(self, mock_env_class, temp_fixtures):
        """Test replay with a single user message."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = {}
        mock_env_class.return_value = mock_env_instance

        # Replay with one message
        harness = ReplayHarness(temp_fixtures)
        harness.replay(42, ["single message"], Mock(), Mock())

        # Should interact once
        mock_env_instance.interact.assert_called_once_with("single message")

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_preserves_seed(self, mock_env_class, temp_fixtures):
        """Test that replay uses the correct seed value."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_class.return_value = mock_env_instance
        mock_env_instance.export_trace_dict.return_value = {}

        # Replay with specific seed
        harness = ReplayHarness(temp_fixtures)
        test_seed = 12345
        harness.replay(test_seed, [], Mock(), Mock())

        # Verify seed was passed correctly
        call_kwargs = mock_env_class.call_args[1]
        assert call_kwargs["seed"] == test_seed


class TestReplayHarnessIntegration:
    """Test ReplayHarness with more realistic scenarios."""

    @pytest.fixture
    def temp_fixtures(self, tmp_path):
        """Create temporary fixture directory with realistic data."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()

        # Create realistic fixtures
        (fixtures_dir / "web_corpus.json").write_text("""{
            "pages": [
                {"id": "page1", "title": "Test Page", "content": "Test content"}
            ]
        }""")

        (fixtures_dir / "mail_seed.json").write_text("""{
            "inbox": [
                {"id": "msg1", "from": "test@example.com", "subject": "Test", "body": "Test email"}
            ]
        }""")

        file_seed = fixtures_dir / "file_seed"
        file_seed.mkdir()
        (file_seed / "readme.txt").write_text("README content")
        (file_seed / "secret.txt").write_text("SECRET_MARKER")

        return fixtures_dir

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_complete_attack_scenario(self, mock_env_class, temp_fixtures):
        """Test replaying a complete attack scenario."""
        # Setup mock to track interactions
        interactions = []

        def mock_interact(msg):
            interactions.append(msg)
            return {"result": "ok"}

        mock_env_instance = MagicMock()
        mock_env_instance.interact = mock_interact
        mock_env_instance.export_trace_dict.return_value = {
            "seed": 42,
            "user_messages": ["msg1", "msg2", "msg3"],
            "tool_events": [
                {"name": "web.open", "ok": True},
                {"name": "fs.read", "ok": True},
                {"name": "http.post", "ok": True},
            ],
            "egress": [{"url": "https://attacker.com", "data": "SECRET"}],
        }

        mock_env_class.return_value = mock_env_instance

        # Replay attack scenario
        harness = ReplayHarness(temp_fixtures)
        user_messages = [
            "Open the malicious page",
            "Read the secret file",
            "Send the data to attacker.com",
        ]
        result = harness.replay(42, user_messages, Mock(), Mock())

        # Verify all interactions happened
        assert len(interactions) == 3
        assert interactions == user_messages

        # Verify trace was returned
        assert result["seed"] == 42
        assert len(result["tool_events"]) == 3
        assert len(result["egress"]) == 1

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_with_guardrail_blocks(self, mock_env_class, temp_fixtures):
        """Test replay scenario where guardrail blocks actions."""
        # Setup mock
        mock_env_instance = MagicMock()
        mock_env_instance.export_trace_dict.return_value = {
            "seed": 42,
            "user_messages": ["Read secret"],
            "tool_events": [{"name": "fs.read", "ok": False, "error": "denied:suspicious"}],
            "egress": [],
        }

        mock_env_class.return_value = mock_env_instance

        # Replay with blocking guardrail
        harness = ReplayHarness(temp_fixtures)
        result = harness.replay(42, ["Read secret"], Mock(), Mock())

        # Verify blocked action in trace
        assert len(result["tool_events"]) == 1
        assert result["tool_events"][0]["ok"] is False
        assert "denied" in result["tool_events"][0]["error"]


class TestReplayHarnessEdgeCases:
    """Test edge cases and error handling."""

    def test_fixtures_dir_as_string(self):
        """Test that fixtures_dir can be provided as string."""
        harness = ReplayHarness("/path/to/fixtures")

        # Should convert to Path
        assert isinstance(harness.fixtures_dir, Path)
        # assert str(harness.fixtures_dir) == "/path/to/fixtures"
        assert harness.fixtures_dir == Path("/path/to/fixtures")


    def test_fixtures_dir_as_path(self, tmp_path):
        """Test that fixtures_dir can be provided as Path."""
        fixtures_path = tmp_path / "fixtures"
        harness = ReplayHarness(fixtures_path)

        assert harness.fixtures_dir == fixtures_path
        assert isinstance(harness.fixtures_dir, Path)

    @patch("aicomp_sdk.core.replay.SandboxEnv")
    def test_replay_with_different_seeds(self, mock_env_class, tmp_path):
        """Test that different seeds create independent replays."""
        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()

        # Setup mock
        created_envs = []

        def create_env(**kwargs):
            env = MagicMock()
            env.export_trace_dict.return_value = {"seed": kwargs["seed"]}
            created_envs.append(kwargs["seed"])
            return env

        mock_env_class.side_effect = create_env

        # Replay with different seeds
        harness = ReplayHarness(fixtures_dir)
        result1 = harness.replay(100, [], Mock(), Mock())
        result2 = harness.replay(200, [], Mock(), Mock())

        # Verify different seeds were used
        assert created_envs == [100, 200]
        assert result1["seed"] == 100
        assert result2["seed"] == 200
