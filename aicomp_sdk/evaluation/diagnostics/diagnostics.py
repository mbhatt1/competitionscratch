from __future__ import annotations

import sys
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol, TextIO

from aicomp_sdk.agents.debug import AgentDebugEvent, AgentDebugSink, JsonlAgentDebugSink

from .capture import ForeignOutputCapture
from .event_log import open_event_log_sink
from .transcript import TailBuffer, TranscriptWriter


class EvaluatorVerbosity(StrEnum):
    SUMMARY = "summary"
    PROGRESS = "progress"
    DEBUG = "debug"


def coerce_evaluator_verbosity(value: str | EvaluatorVerbosity) -> EvaluatorVerbosity:
    try:
        return EvaluatorVerbosity(value)
    except ValueError as err:
        raise ValueError(f"Unsupported evaluator verbosity: {value}") from err


class ProgressReporter(Protocol):
    def info(self, event: str, message: str, **fields: object) -> None:
        """Record an informational evaluator event."""

    def progress(self, event: str, message: str, **fields: object) -> None:
        """Record a progress-oriented evaluator event."""

    def debug(self, event: str, message: str, **fields: object) -> None:
        """Record a debug-level evaluator event."""


_LEGACY_PROGRESS_PREFIXES: Final[tuple[str, ...]] = (
    "[GO-EXPLORE] Starting attack run:",
    "[GO-EXPLORE] Seed exemplar created",
    "[GO-EXPLORE] Step ",
    "[GO-EXPLORE] Attack run complete:",
    "  Productive steps:",
    "  Total branch attempts:",
    "  Archive size:",
    "  Novel cells discovered:",
    "  Predicates triggered:",
    "  Findings with predicates:",
    "  Depth distribution:",
)

EventLevel = Literal["debug", "info", "warning", "error", "progress"]
EventKind = Literal["phase_start", "phase_end", "message", "metric", "progress"]


@dataclass(frozen=True, slots=True)
class FrameworkEvent:
    at_utc: datetime
    run_id: str
    phase: str | None
    level: EventLevel
    kind: EventKind
    event: str
    message: str
    fields: Mapping[str, object] = field(default_factory=dict)


class _LegacyProgressClassifier:
    def matches(self, line: str) -> bool:
        return line.startswith(_LEGACY_PROGRESS_PREFIXES)


class ConsoleRenderer:
    def __init__(
        self,
        verbosity: EvaluatorVerbosity,
        *,
        stderr: TextIO | None = None,
        progress_classifier: _LegacyProgressClassifier | None = None,
    ) -> None:
        self.verbosity = verbosity
        self.stderr = stderr if stderr is not None else sys.stderr
        self._progress_classifier = (
            progress_classifier if progress_classifier is not None else _LegacyProgressClassifier()
        )

    def wants_debug_stream(self) -> bool:
        return self.verbosity is EvaluatorVerbosity.DEBUG

    def wants_progress_lines(self) -> bool:
        return self.verbosity is EvaluatorVerbosity.PROGRESS

    def render_event(self, event: FrameworkEvent) -> None:
        if not self._should_render_event(event):
            return
        self._write_line(event.message)

    def render_stream_chunk(self, text: str) -> None:
        if not self.wants_debug_stream():
            return
        self.stderr.write(text)
        self.stderr.flush()

    def render_legacy_progress_line(self, line: str) -> None:
        if not self.wants_progress_lines():
            return
        if not self._progress_classifier.matches(line):
            return
        self._write_line(line)

    def _should_render_event(self, event: FrameworkEvent) -> bool:
        if event.level in {"warning", "error"}:
            return True
        if self.verbosity is EvaluatorVerbosity.DEBUG:
            return True
        if self.verbosity is EvaluatorVerbosity.PROGRESS:
            return event.level in {"info", "progress"}
        return event.level == "info" and event.kind != "metric"

    def _write_line(self, line: str) -> None:
        self.stderr.write(line)
        if not line.endswith("\n"):
            self.stderr.write("\n")
        self.stderr.flush()


class PhaseDiagnostics:
    def __init__(self, owner: RunDiagnostics, phase: str) -> None:
        self._owner = owner
        self.phase = phase

    def info(self, event: str, message: str, **fields: object) -> None:
        self._owner.record_event(
            level="info",
            event=event,
            message=message,
            phase=self.phase,
            kind="message",
            fields=fields,
        )

    def progress(self, event: str, message: str, **fields: object) -> None:
        self._owner.record_event(
            level="progress",
            event=event,
            message=message,
            phase=self.phase,
            kind="progress",
            fields=fields,
        )

    def debug(self, event: str, message: str, **fields: object) -> None:
        self._owner.record_event(
            level="debug",
            event=event,
            message=message,
            phase=self.phase,
            kind="message",
            fields=fields,
        )

    def warning(self, event: str, message: str, **fields: object) -> None:
        self._owner.record_event(
            level="warning",
            event=event,
            message=message,
            phase=self.phase,
            kind="message",
            fields=fields,
        )

    def capture_stdio(self, label: str):
        return self._owner.capture_stdio(label, phase=self.phase)

    def progress_reporter(self) -> ProgressReporter:
        return self


class RunDiagnostics:
    def __init__(
        self,
        verbosity: EvaluatorVerbosity,
        *,
        stderr: TextIO | None = None,
        transcript_file: Path | None = None,
        event_log_file: Path | None = None,
        agent_debug_file: Path | None = None,
        run_id: str | None = None,
    ) -> None:
        self.verbosity = verbosity
        self.run_id = run_id if run_id is not None else uuid.uuid4().hex[:12]
        self.console = ConsoleRenderer(verbosity, stderr=stderr)
        self.transcript_file = Path(transcript_file) if transcript_file is not None else None
        self.event_log_file = Path(event_log_file) if event_log_file is not None else None
        self.agent_debug_file = Path(agent_debug_file) if agent_debug_file is not None else None
        self._transcript_writer = (
            TranscriptWriter(self.transcript_file) if self.transcript_file is not None else None
        )
        self._event_log_sink = (
            open_event_log_sink(self.event_log_file) if self.event_log_file is not None else None
        )
        self._agent_debug_sink: AgentDebugSink | None = None

    def __enter__(self) -> RunDiagnostics:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()

    def close(self) -> None:
        if self._event_log_sink is not None:
            self._event_log_sink.close()
            self._event_log_sink = None
        if self._transcript_writer is not None:
            self._transcript_writer.close()
            self._transcript_writer = None

    def phase(self, phase: str) -> PhaseDiagnostics:
        return PhaseDiagnostics(self, phase)

    def info(
        self,
        event: str,
        message: str,
        *,
        phase: str | None = None,
        kind: EventKind = "message",
        **fields: object,
    ) -> None:
        self.record_event(
            level="info",
            event=event,
            message=message,
            phase=phase,
            kind=kind,
            fields=fields,
        )

    def progress(
        self,
        event: str,
        message: str,
        *,
        phase: str | None = None,
        kind: EventKind = "progress",
        **fields: object,
    ) -> None:
        self.record_event(
            level="progress",
            event=event,
            message=message,
            phase=phase,
            kind=kind,
            fields=fields,
        )

    def debug(
        self,
        event: str,
        message: str,
        *,
        phase: str | None = None,
        kind: EventKind = "message",
        **fields: object,
    ) -> None:
        self.record_event(
            level="debug",
            event=event,
            message=message,
            phase=phase,
            kind=kind,
            fields=fields,
        )

    def warning(
        self,
        event: str,
        message: str,
        *,
        phase: str | None = None,
        kind: EventKind = "message",
        **fields: object,
    ) -> None:
        self.record_event(
            level="warning",
            event=event,
            message=message,
            phase=phase,
            kind=kind,
            fields=fields,
        )

    def record_event(
        self,
        *,
        level: EventLevel,
        event: str,
        message: str,
        phase: str | None,
        kind: EventKind,
        fields: Mapping[str, object] | None = None,
        render: bool = True,
    ) -> None:
        framework_event = FrameworkEvent(
            at_utc=datetime.now(timezone.utc),
            run_id=self.run_id,
            phase=phase,
            level=level,
            kind=kind,
            event=event,
            message=message,
            fields=dict(fields or {}),
        )
        if render:
            self.console.render_event(framework_event)
        if self._event_log_sink is not None:
            self._event_log_sink.record_event(framework_event)

    def progress_reporter(self, *, phase: str) -> ProgressReporter:
        return self.phase(phase)

    def make_agent_debug_sink(self) -> AgentDebugSink | None:
        if self.agent_debug_file is None:
            return None
        if self._agent_debug_sink is None:
            self._agent_debug_sink = CorrelatedAgentDebugSink(
                JsonlAgentDebugSink(self.agent_debug_file),
                run_id=self.run_id,
            )
        return self._agent_debug_sink

    @contextmanager
    def capture_stdio(self, label: str, *, phase: str | None = None):
        capture = ForeignOutputCapture(
            label=label,
            console_renderer=self.console,
            stdout_tail=TailBuffer(),
            stderr_tail=TailBuffer(),
            transcript_section=(
                self._transcript_writer.open_section(label)
                if self._transcript_writer is not None
                else None
            ),
        )
        try:
            with capture.redirect():
                yield
        except BaseException as err:
            capture.finalize()
            self._annotate_failure(err, label=label, capture=capture)
            raise
        else:
            capture.finalize()

    def _annotate_failure(
        self,
        err: BaseException,
        *,
        label: str,
        capture: ForeignOutputCapture,
    ) -> None:
        stdout_tail = capture.last_line("stdout")
        stderr_tail = capture.last_line("stderr")
        if stdout_tail is None and stderr_tail is None:
            return
        artifact_hint = "debug verbosity or a saved transcript artifact"
        if self.transcript_file is not None:
            artifact_hint = str(self.transcript_file)
        err.add_note(
            f"Captured evaluator output from {label} was suppressed; inspect {artifact_hint}."
        )
        preview_parts: list[str] = []
        if stdout_tail is not None:
            preview_parts.append(f"stdout tail: {stdout_tail}")
        if stderr_tail is not None:
            preview_parts.append(f"stderr tail: {stderr_tail}")
        if preview_parts:
            err.add_note(" | ".join(preview_parts))


class CorrelatedAgentDebugSink:
    def __init__(self, delegate: AgentDebugSink, *, run_id: str) -> None:
        self._delegate = delegate
        self._run_id = run_id

    def record(self, event: AgentDebugEvent) -> None:
        if event.run_id == self._run_id:
            self._delegate.record(event)
            return
        self._delegate.record(replace(event, run_id=self._run_id))
