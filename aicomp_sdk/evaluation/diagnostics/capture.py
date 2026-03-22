from __future__ import annotations

import io
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .diagnostics import ConsoleRenderer
    from .transcript import TailBuffer, TranscriptSection


class ForeignOutputCapture:
    def __init__(
        self,
        *,
        label: str,
        console_renderer: ConsoleRenderer,
        stdout_tail: TailBuffer,
        stderr_tail: TailBuffer,
        transcript_section: TranscriptSection | None,
    ) -> None:
        self.label = label
        self._console_renderer = console_renderer
        self._stdout_tail = stdout_tail
        self._stderr_tail = stderr_tail
        self._transcript_section = transcript_section
        self._pending_lines = {"stdout": "", "stderr": ""}

    @contextmanager
    def redirect(self) -> Iterator[None]:
        stdout_stream = _CapturedStream(owner=self, stream_name="stdout")
        stderr_stream = _CapturedStream(owner=self, stream_name="stderr")
        with redirect_stdout(stdout_stream), redirect_stderr(stderr_stream):
            yield

    def write_chunk(self, stream_name: str, text: str) -> int:
        if not text:
            return 0
        if self._transcript_section is not None:
            self._transcript_section.write_chunk(stream_name, text)
        tail = self._stdout_tail if stream_name == "stdout" else self._stderr_tail
        tail.append(text)
        if self._console_renderer.wants_debug_stream():
            self._console_renderer.render_stream_chunk(text)
        elif self._console_renderer.wants_progress_lines():
            self._pending_lines[stream_name] += text
            self._drain_progress_lines(stream_name)
        return len(text)

    def flush(self, stream_name: str) -> None:
        if self._console_renderer.wants_progress_lines():
            self._drain_progress_lines(stream_name, flush_partial=True)

    def finalize(self) -> None:
        self.flush("stdout")
        self.flush("stderr")
        self._stdout_tail.finalize()
        self._stderr_tail.finalize()

    def last_line(self, stream_name: Literal["stdout", "stderr"]) -> str | None:
        tail = self._stdout_tail if stream_name == "stdout" else self._stderr_tail
        return tail.last_line()

    def _drain_progress_lines(self, stream_name: str, *, flush_partial: bool = False) -> None:
        pending = self._pending_lines[stream_name]
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            self._console_renderer.render_legacy_progress_line(line)
        if flush_partial and pending:
            self._console_renderer.render_legacy_progress_line(pending)
            pending = ""
        self._pending_lines[stream_name] = pending


class _CapturedStream(io.TextIOBase):
    def __init__(self, *, owner: ForeignOutputCapture, stream_name: str) -> None:
        super().__init__()
        self._owner = owner
        self._stream_name = stream_name

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        return self._owner.write_chunk(self._stream_name, text)

    def flush(self) -> None:
        self._owner.flush(self._stream_name)
