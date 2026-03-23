from __future__ import annotations

from collections import deque
from pathlib import Path


class TailBuffer:
    """Keep the most recent complete non-empty lines from a text stream."""

    def __init__(self, *, max_lines: int = 8) -> None:
        self._lines: deque[str] = deque(maxlen=max_lines)
        self._pending = ""

    def append(self, text: str) -> None:
        self._pending += text
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            self._remember(line)

    def finalize(self) -> None:
        if self._pending:
            self._remember(self._pending)
            self._pending = ""

    def last_line(self) -> str | None:
        if not self._lines:
            return None
        return self._lines[-1]

    def _remember(self, line: str) -> None:
        stripped = line.rstrip()
        if stripped:
            self._lines.append(stripped)


class TranscriptSection:
    """Write a labeled transcript section, adding stream headers lazily."""

    def __init__(self, handle, label: str) -> None:  # noqa: ANN001
        self._handle = handle
        self._label = label
        self._started = False
        self._active_stream: str | None = None
        self._ends_with_newline = True

    def write_chunk(self, stream_name: str, text: str) -> None:
        if not text:
            return
        if not self._started:
            self._handle.write(f"=== {self._label} ===\n")
            self._started = True
            self._ends_with_newline = True
        if stream_name != self._active_stream:
            if not self._ends_with_newline:
                self._handle.write("\n")
            self._handle.write(f"--- {stream_name} ---\n")
            self._active_stream = stream_name
            self._ends_with_newline = True
        self._handle.write(text)
        self._ends_with_newline = text.endswith("\n")
        self._handle.flush()


class TranscriptWriter:
    """Own the transcript file handle and open labeled sections on demand."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8")

    def open_section(self, label: str) -> TranscriptSection:
        return TranscriptSection(self._handle, label)

    def close(self) -> None:
        self._handle.close()
