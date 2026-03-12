from __future__ import annotations

import json
from pathlib import Path

import pytest

gym = pytest.importorskip("gymnasium")
env_checker = pytest.importorskip("gymnasium.utils.env_checker")

from aicomp_sdk.agents import build_agent
from aicomp_sdk.core import gym_env
from aicomp_sdk.core.env_api import (
    DEFAULT_MAX_TOOL_HOPS,
    MAX_USER_MESSAGE_CHARS,
    AttackEnvProtocol,
)
from aicomp_sdk.core.gym_env import GymAttackEnv
from aicomp_sdk.guardrails.base import GuardrailBase


@pytest.fixture
def temp_fixtures(tmp_path: Path) -> Path:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "web_corpus.json").write_text('{"pages": []}', encoding="utf-8")
    (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}', encoding="utf-8")
    file_seed = fixtures_dir / "file_seed"
    file_seed.mkdir()
    (file_seed / "secret.txt").write_text("SECRET_MARKER", encoding="utf-8")
    (file_seed / "readme.txt").write_text("README content", encoding="utf-8")
    return fixtures_dir


def make_env(temp_fixtures: Path, *, max_episode_messages: int = 32) -> GymAttackEnv:
    return GymAttackEnv(
        seed=42,
        fixtures_dir=temp_fixtures,
        guardrail=GuardrailBase(),
        agent=build_agent("deterministic"),
        max_episode_messages=max_episode_messages,
    )


def test_reset_returns_observation_and_info(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    observation, info = env.reset(seed=7)

    assert observation["turn_index"] == 0
    summary = json.loads(observation["trace_summary_json"])
    assert summary["seed"] == 7
    assert info["trace"]["seed"] == 7


def test_step_returns_valid_gym_tuple(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env.reset()

    observation, reward, terminated, truncated, info = env.step("read secret")

    assert observation["turn_index"] == 1
    assert reward == 0.0
    assert terminated is False
    assert truncated is False
    assert info["legacy_result"]["seed"] == 42
    assert info["trace"]["user_messages"] == ["read secret"]


def test_step_respects_max_episode_messages(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures, max_episode_messages=1)
    env.reset()

    _, _, _, truncated, _ = env.step("read secret")

    assert truncated is True


def test_gym_env_uses_shared_message_limit() -> None:
    assert gym_env.MAX_USER_MESSAGE_CHARS == MAX_USER_MESSAGE_CHARS


def test_gym_env_uses_shared_default_tool_hops(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    assert env.max_tool_hops == DEFAULT_MAX_TOOL_HOPS


def test_interact_matches_legacy_shape(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env.reset()

    result = env.interact("read secret")

    assert result["seed"] == 42
    assert "n_tools" in result
    assert "agent_refused" in result


def test_snapshot_and_restore_preserve_trace(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env.reset()
    env.interact("read secret")
    snapshot = env.snapshot()
    before = env.export_trace_dict()

    env.interact("delete secret")
    env.restore(snapshot)

    assert env.export_trace_dict() == before
    observation, _, _, _, _ = env.step("read readme")
    assert env.observation_space.contains(observation)


def test_export_trace_matches_info_trace(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env.reset()

    _, _, _, _, info = env.step("read secret")

    assert env.export_trace_dict() == info["trace"]


def test_observation_summary_fits_space(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    observation, _ = env.reset()
    assert env.observation_space.contains(observation)

    observation, _, _, _, _ = env.step("read secret")
    assert env.observation_space.contains(observation)


def test_env_checker_passes(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env_checker.check_env(env, skip_render_check=True)


def test_env_checker_passes_after_restore(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    env.reset()
    env.step("read secret")
    snapshot = env.snapshot()
    env.step("delete secret")
    env.restore(snapshot)

    env_checker.check_env(env, skip_render_check=True)


def test_gym_env_satisfies_attack_env_protocol(temp_fixtures: Path) -> None:
    env = make_env(temp_fixtures)
    assert isinstance(env, AttackEnvProtocol)
