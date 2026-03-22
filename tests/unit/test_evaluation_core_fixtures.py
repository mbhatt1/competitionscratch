from __future__ import annotations

from pathlib import Path

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core


def _write_fixture_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "web_corpus.json").write_text('{"pages": []}', encoding="utf-8")
    (root / "mail_seed.json").write_text('{"inbox": []}', encoding="utf-8")
    (root / "file_seed").mkdir(exist_ok=True)


def test_resolve_fixtures_dir_prefers_explicit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = tmp_path / "explicit"
    _write_fixture_tree(explicit)
    monkeypatch.setenv(evaluation_core.FIXTURES_ENV_VAR, str(tmp_path / "ignored_env"))
    monkeypatch.setattr(evaluation_core, "PACKAGED_FIXTURES", tmp_path / "missing_packaged")
    monkeypatch.setattr(evaluation_core, "LEGACY_REPO_FIXTURES", tmp_path / "missing_legacy")

    resolved = evaluation_core.resolve_fixtures_dir(explicit)

    assert resolved == explicit.resolve()


def test_resolve_fixtures_dir_rejects_invalid_explicit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packaged = tmp_path / "packaged"
    _write_fixture_tree(packaged)
    monkeypatch.setattr(evaluation_core, "PACKAGED_FIXTURES", packaged)
    monkeypatch.setattr(evaluation_core, "LEGACY_REPO_FIXTURES", tmp_path / "missing_legacy")

    with pytest.raises(FileNotFoundError) as exc_info:
        evaluation_core.resolve_fixtures_dir(tmp_path / "typoed_explicit")

    message = str(exc_info.value)
    assert "Explicit fixtures directory" in message
    assert "typoed_explicit" in message


def test_resolve_fixtures_dir_uses_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_fixtures = tmp_path / "env_fixtures"
    _write_fixture_tree(env_fixtures)
    monkeypatch.setenv(evaluation_core.FIXTURES_ENV_VAR, str(env_fixtures))
    monkeypatch.setattr(evaluation_core, "PACKAGED_FIXTURES", tmp_path / "missing_packaged")
    monkeypatch.setattr(evaluation_core, "LEGACY_REPO_FIXTURES", tmp_path / "missing_legacy")

    resolved = evaluation_core.resolve_fixtures_dir()

    assert resolved == env_fixtures.resolve()


def test_resolve_fixtures_dir_falls_back_to_packaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packaged = tmp_path / "packaged"
    _write_fixture_tree(packaged)
    monkeypatch.delenv(evaluation_core.FIXTURES_ENV_VAR, raising=False)
    monkeypatch.setattr(evaluation_core, "PACKAGED_FIXTURES", packaged)
    monkeypatch.setattr(evaluation_core, "LEGACY_REPO_FIXTURES", tmp_path / "missing_legacy")

    resolved = evaluation_core.resolve_fixtures_dir()

    assert resolved == packaged.resolve()


def test_resolve_fixtures_dir_raises_actionable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad_env = tmp_path / "bad_env"
    bad_packaged = tmp_path / "bad_packaged"
    bad_legacy = tmp_path / "bad_legacy"
    bad_env.mkdir()
    bad_packaged.mkdir()
    bad_legacy.mkdir()
    monkeypatch.setenv(evaluation_core.FIXTURES_ENV_VAR, str(bad_env))
    monkeypatch.setattr(evaluation_core, "PACKAGED_FIXTURES", bad_packaged)
    monkeypatch.setattr(evaluation_core, "LEGACY_REPO_FIXTURES", bad_legacy)

    with pytest.raises(FileNotFoundError) as exc_info:
        evaluation_core.resolve_fixtures_dir()

    message = str(exc_info.value)
    assert evaluation_core.FIXTURES_ENV_VAR in message
    assert "web_corpus.json" in message
    assert "mail_seed.json" in message
    assert "file_seed/" in message
