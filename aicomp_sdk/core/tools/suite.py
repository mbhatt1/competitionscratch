from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .models import RuntimeToolSpec
from .registry import TOOL_REGISTRY
from .schema import build_runtime_tool_spec
from .state import ToolContext, ToolRuntimeState


class ToolSuite:
    """Deterministic offline tool implementations backed by fixtures."""

    def __init__(self, fixtures_dir: Path, *, isolate_fs: bool = False):
        self.fixtures_dir = fixtures_dir
        self._state = self._build_state(fixtures_dir, isolate_fs=isolate_fs)
        self._context = ToolContext(self._state)
        self.specs: dict[str, RuntimeToolSpec] = {
            name: build_runtime_tool_spec(tool_def) for name, tool_def in TOOL_REGISTRY.items()
        }

    def _build_state(self, fixtures_dir: Path, *, isolate_fs: bool) -> ToolRuntimeState:
        web = json.loads((fixtures_dir / "web_corpus.json").read_text())
        mail_seed = json.loads((fixtures_dir / "mail_seed.json").read_text())
        fs_root, fs_workspace = self._create_fs_root(isolate_fs)
        fs_backup: dict[str, str] = {}

        for path in fs_root.iterdir():
            if path.is_file():
                fs_backup[path.name] = path.read_text(encoding="utf-8")

        return ToolRuntimeState(
            web=web,
            mail_seed=mail_seed,
            mail=copy.deepcopy(mail_seed),
            fs_root=fs_root,
            fs_backup=fs_backup,
            egress_sink=[],
            last_source="user",
            fs_workspace=fs_workspace,
        )

    def _create_fs_root(self, isolate_fs: bool) -> tuple[Path, TemporaryDirectory | None]:
        fs_root = self.fixtures_dir / "file_seed"
        if not isolate_fs:
            return fs_root, None

        workspace = TemporaryDirectory(prefix="aicomp_file_seed_")
        workspace_root = Path(workspace.name) / "file_seed"
        shutil.copytree(fs_root, workspace_root)
        return workspace_root, workspace

    def reset(self, seed: int):
        del seed
        self._state.egress_sink = []
        self._state.last_source = "user"
        self._state.mail = copy.deepcopy(self._state.mail_seed)

        for path in self._state.fs_root.iterdir():
            if path.name not in self._state.fs_backup:
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.is_file():
                    path.unlink()

        for filename, content in self._state.fs_backup.items():
            path = self._state.fs_root / filename
            path.write_text(content, encoding="utf-8")

    @property
    def last_source(self) -> str:
        return self._state.last_source

    def validate(self, tool_name: str, args: Mapping[str, Any]):
        if tool_name not in self.specs:
            raise ValueError(f"Unknown tool: {tool_name}")

        spec = self.specs[tool_name].parameters_json_schema
        required = set(spec.get("required", []))
        properties = set(spec.get("properties", {}).keys())
        provided_keys = set(args)
        missing = sorted(required - provided_keys)
        if missing:
            raise ValueError(f"Missing keys: {missing}")
        if spec.get("additionalProperties", True) is False:
            extra = sorted(provided_keys - properties)
            if extra:
                raise ValueError(f"Extra keys: {extra}")

    def call(self, tool_name: str, args: Mapping[str, Any]) -> tuple[bool, str, str | None]:
        self.validate(tool_name, args)
        return TOOL_REGISTRY[tool_name].handler(self._context, **dict(args))

    def get_egress(self) -> list[dict[str, Any]]:
        return list(self._state.egress_sink)

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "egress": copy.deepcopy(self._state.egress_sink),
            "mail": copy.deepcopy(self._state.mail),
            "last_source": self._state.last_source,
        }

    def restore_state(self, state: Mapping[str, Any]) -> None:
        self._state.egress_sink = copy.deepcopy(state["egress"])
        self._state.mail = copy.deepcopy(state["mail"])
        self._state.last_source = state["last_source"]

    @property
    def filesystem_root(self) -> Path:
        return self._state.fs_root
