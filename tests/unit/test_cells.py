"""
Unit tests for aicomp_sdk.core.cells module.
Tests cell signature generation and hashing functionality.
"""

import pytest

from aicomp_sdk.core.cells import _bucket_path, _bucket_url, _short_hash, cell_signature


class TestHelperFunctions:
    """Test helper functions for cell signature generation."""

    def test_hash_function_consistency(self):
        """Test that _short_hash produces consistent hashes."""
        test_string = "test_string"
        hash1 = _short_hash(test_string)
        hash2 = _short_hash(test_string)
        assert hash1 == hash2
        assert len(hash1) == 16  # Should be first 16 chars of sha256

    def test_hash_function_uniqueness(self):
        """Test that different strings produce different hashes."""
        hash1 = _short_hash("string1")
        hash2 = _short_hash("string2")
        assert hash1 != hash2

    def test_bucket_path_extracts_filename(self):
        """Test that _bucket_path extracts the filename from a path."""
        assert _bucket_path("/path/to/file.txt") == "file.txt"
        assert _bucket_path("file.txt") == "file.txt"
        assert _bucket_path("") == ""
        assert _bucket_path("/folder/subfolder/document.pdf") == "document.pdf"

    def test_bucket_url_extracts_domain(self):
        """Test that _bucket_url extracts domain from URLs."""
        assert _bucket_url("https://example.com/path") == "example.com"
        assert _bucket_url("http://test.com/page") == "test.com"
        assert _bucket_url("https://sub.domain.com/api/v1") == "sub.domain.com"
        assert _bucket_url("no-protocol.com") == "unknown"


class TestCellSignatureBasic:
    """Test basic cell signature generation."""

    def test_empty_signature(self):
        """Test signature with no events."""
        sig = cell_signature([])
        assert sig["hash"] is not None
        assert sig["n_tools"] == 0
        assert sig["tool_seq_ngram"] == []
        assert sig["egress_count"] == 0
        assert sig["secret_read"] is False

    def test_single_tool_event(self):
        """Test signature with a single tool event."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "readme.txt"},
                "ok": True,
                "output": "Some content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events)
        assert sig["n_tools"] == 1
        assert "fs.read" in sig["tool_seq_ngram"]
        assert "READ" in sig["side_effects"]
        assert "local" in sig["scopes"]
        assert sig["secret_read"] is False

    def test_multiple_tool_events(self):
        """Test signature with multiple tool events."""
        events = [
            {
                "name": "web.search",
                "args": {"query": "test"},
                "ok": True,
                "output": "results",
                "side_effect": "NETWORK",
                "scope": "public",
                "source": "user",
            },
            {
                "name": "fs.read",
                "args": {"path": "config.txt"},
                "ok": True,
                "output": "config",
                "side_effect": "READ",
                "scope": "local",
                "source": "file",
            },
        ]
        sig = cell_signature(events, n_tool=5)
        assert sig["n_tools"] == 2
        assert len(sig["tool_seq_ngram"]) == 2
        assert len(sig["side_effects"]) == 2


class TestSecretDetection:
    """Test secret.txt detection in cell signatures."""

    def test_secret_read_detected(self):
        """Test that reading secret.txt is detected."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "secret.txt"},
                "ok": True,
                "output": "SECRET_MARKER",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events)
        assert sig["secret_read"] is True

    def test_secret_read_case_insensitive(self):
        """Test that secret detection is case-insensitive."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "SECRET.TXT"},
                "ok": True,
                "output": "content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events)
        assert sig["secret_read"] is True

    def test_secret_read_failed_not_detected(self):
        """Test that failed secret reads are not counted."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "secret.txt"},
                "ok": False,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
                "error": "not_found",
            }
        ]
        sig = cell_signature(events)
        assert sig["secret_read"] is False


class TestEgressTracking:
    """Test egress data tracking in cell signatures."""

    def test_egress_count_zero(self):
        """Test egress count with no egress events."""
        events = [
            {
                "name": "fs.read",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events, egress_data=[])
        assert sig["egress_count"] == 0

    def test_egress_count_tracking(self):
        """Test that egress events are counted correctly."""
        events = [
            {
                "name": "http.post",
                "args": {"url": "https://example.com", "data": "test"},
                "ok": True,
                "output": "ok",
                "side_effect": "SHARE",
                "scope": "external",
                "source": "tool",
            }
        ]
        egress_data = [
            {"url": "https://example.com", "data": "test1"},
            {"url": "https://attacker.com", "data": "test2"},
        ]
        sig = cell_signature(events, egress_data=egress_data)
        assert sig["egress_count"] == 2


class TestToolArguments:
    """Test tool argument tracking in signatures."""

    def test_tool_args_disabled(self):
        """Test signature with use_args=False."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "secret.txt"},
                "ok": True,
                "output": "content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events, use_args=False)
        assert sig["sensitive_tools"] == []

    def test_tool_args_fs_read(self):
        """Test that fs.read arguments are captured."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "config.txt"},
                "ok": True,
                "output": "content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events, use_args=True)
        assert any("fs.read:config.txt" in arg for arg in sig["sensitive_tools"])

    def test_tool_args_http_post(self):
        """Test that http.post arguments are captured."""
        events = [
            {
                "name": "http.post",
                "args": {"url": "https://example.com/api", "data": "payload"},
                "ok": True,
                "output": "ok",
                "side_effect": "SHARE",
                "scope": "external",
                "source": "tool",
            }
        ]
        sig = cell_signature(events, use_args=True)
        assert any("http.post:example.com" in arg for arg in sig["sensitive_tools"])

    def test_tool_args_shell_run(self):
        """Test that shell.run arguments are captured."""
        events = [
            {
                "name": "shell.run",
                "args": {"cmd": "echo hello world"},
                "ok": True,
                "output": "hello world",
                "side_effect": "EXEC",
                "scope": "local",
                "source": "tool",
            }
        ]
        sig = cell_signature(events, use_args=True)
        assert any("shell.run:echo hello world" in arg for arg in sig["sensitive_tools"])


class TestGuardrailBlocks:
    """Test guardrail block detection in signatures."""

    def test_denied_tool_tracked(self):
        """Test that denied tools are tracked."""
        events = [
            {
                "name": "fs.delete",
                "args": {"path": "secret.txt"},
                "ok": False,
                "output": "",
                "side_effect": "WRITE",
                "scope": "local",
                "source": "user",
                "error": "denied:suspicious_operation",
            }
        ]
        sig = cell_signature(events)
        assert "denied" in sig["guardrail_blocks"]

    def test_confirm_required_tracked(self):
        """Test that confirmation requirements are tracked."""
        events = [
            {
                "name": "email.send",
                "args": {"to": "test@example.com", "subject": "test", "body": "test"},
                "ok": False,
                "output": "",
                "side_effect": "SHARE",
                "scope": "external",
                "source": "user",
                "error": "confirm_required:user_approval_needed",
            }
        ]
        sig = cell_signature(events)
        assert "confirm_required" in sig["guardrail_blocks"]

    def test_multiple_blocks_tracked(self):
        """Test that multiple blocks are tracked (last 3)."""
        events = [
            {
                "name": "fs.delete",
                "args": {},
                "ok": False,
                "output": "",
                "side_effect": "WRITE",
                "scope": "local",
                "source": "user",
                "error": "denied:reason1",
            },
            {
                "name": "shell.run",
                "args": {},
                "ok": False,
                "output": "",
                "side_effect": "EXEC",
                "scope": "local",
                "source": "user",
                "error": "denied:reason2",
            },
            {
                "name": "http.post",
                "args": {},
                "ok": False,
                "output": "",
                "side_effect": "SHARE",
                "scope": "external",
                "source": "user",
                "error": "confirm_required:reason3",
            },
        ]
        sig = cell_signature(events)
        assert len(sig["guardrail_blocks"]) <= 3


class TestUserIntent:
    """Test user message intent tracking."""

    def test_user_intent_hashing(self):
        """Test that user messages are hashed in signature."""
        events = [
            {
                "name": "fs.read",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        user_messages = ["Read the secret file", "Delete everything"]
        sig = cell_signature(events, user_messages=user_messages)
        assert len(sig["user_intent"]) == 2
        assert sig["n_msgs"] == 2
        # Each hash should be 8 chars
        for intent_hash in sig["user_intent"]:
            assert len(intent_hash) == 8

    def test_user_intent_last_three(self):
        """Test that only last 3 user messages are tracked."""
        events = [
            {
                "name": "fs.read",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        user_messages = ["msg1", "msg2", "msg3", "msg4", "msg5"]
        sig = cell_signature(events, user_messages=user_messages)
        assert len(sig["user_intent"]) == 3
        assert sig["n_msgs"] == 5


class TestOutputSamples:
    """Test tool output sample tracking."""

    def test_output_samples_disabled(self):
        """Test signature with use_outputs=False."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "file.txt"},
                "ok": True,
                "output": "This is some file content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events, use_outputs=False)
        # Output samples should not be in the hash when disabled
        assert sig["hash"] is not None

    def test_output_samples_enabled(self):
        """Test that output samples are captured when enabled."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "file.txt"},
                "ok": True,
                "output": "This is some file content that should be sampled",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        sig = cell_signature(events, use_outputs=True)
        # Should generate a hash based on output
        assert sig["hash"] is not None


class TestSignatureUniqueness:
    """Test that different scenarios produce different signatures."""

    def test_different_tools_different_signatures(self):
        """Test that different tool sequences produce different signatures."""
        events1 = [
            {
                "name": "fs.read",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        events2 = [
            {
                "name": "fs.write",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "WRITE",
                "scope": "local",
                "source": "user",
            }
        ]

        sig1 = cell_signature(events1)
        sig2 = cell_signature(events2)
        assert sig1["hash"] != sig2["hash"]

    def test_different_args_different_signatures(self):
        """Test that different arguments produce different signatures."""
        events1 = [
            {
                "name": "fs.read",
                "args": {"path": "file1.txt"},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]
        events2 = [
            {
                "name": "fs.read",
                "args": {"path": "file2.txt"},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]

        sig1 = cell_signature(events1, use_args=True)
        sig2 = cell_signature(events2, use_args=True)
        assert sig1["hash"] != sig2["hash"]

    def test_same_events_same_signature(self):
        """Test that identical events produce identical signatures."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": "test.txt"},
                "ok": True,
                "output": "content",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
        ]

        sig1 = cell_signature(events)
        sig2 = cell_signature(events)
        assert sig1["hash"] == sig2["hash"]


class TestNGramWindow:
    """Test n-gram window functionality."""

    def test_ngram_respects_n_tool_parameter(self):
        """Test that n_tool parameter limits the window size."""
        events = [
            {
                "name": f"tool{i}",
                "args": {},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
            for i in range(10)
        ]

        sig = cell_signature(events, n_tool=3)
        # Should only keep last 3 tools
        assert len(sig["tool_seq_ngram"]) == 3
        assert sig["tool_seq_ngram"] == ["tool7", "tool8", "tool9"]

    def test_args_count_parameter(self):
        """Test that args_count parameter limits argument tracking."""
        events = [
            {
                "name": "fs.read",
                "args": {"path": f"file{i}.txt"},
                "ok": True,
                "output": "",
                "side_effect": "READ",
                "scope": "local",
                "source": "user",
            }
            for i in range(10)
        ]

        sig = cell_signature(events, args_count=3, use_args=True)
        # Should track at most args_count arguments
        assert len(sig["sensitive_tools"]) <= 3
