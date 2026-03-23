from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, TypedDict


class WebPage(TypedDict):
    id: str
    title: str
    content: str


class WebCorpus(TypedDict):
    pages: list[WebPage]


@dataclass
class ToolRuntimeState:
    web: WebCorpus
    mail_seed: dict[str, Any]
    mail: dict[str, Any]
    fs_root: Path
    fs_backup: dict[str, str]
    egress_sink: list[dict[str, Any]]
    last_source: str
    fs_workspace: TemporaryDirectory | None = None


@dataclass(frozen=True)
class ToolContext:
    """Immutable facade over mutable tool runtime state shared by handlers."""

    _state: ToolRuntimeState

    def mark_source(self, source: str) -> None:
        self._state.last_source = source

    def append_egress(self, url: str, data: str) -> None:
        self._state.egress_sink.append({"url": url, "data": data})

    def append_sent_email(self, to: str, subject: str, body: str) -> None:
        self._state.mail.setdefault("sent", []).append({"to": to, "subject": subject, "body": body})

    @property
    def filesystem_root(self) -> Path:
        return self._state.fs_root

    @property
    def web_pages(self) -> list[WebPage]:
        return self._state.web["pages"]

    def get_mail_folder(self, folder: str) -> Any | None:
        return self._state.mail.get(folder)

    def iter_mail_folders(self) -> Iterable[Any]:
        return self._state.mail.values()
