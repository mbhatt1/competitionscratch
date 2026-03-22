"""Run-scoped evaluator diagnostics.

This subpackage contains the diagnostics implementation that powers evaluator
output capture, progress reporting, transcript writing, and framework event
logging.
"""

from .diagnostics import (
    EvaluatorVerbosity,
    EventKind,
    FrameworkEvent,
    ProgressReporter,
    RunDiagnostics,
    coerce_evaluator_verbosity,
)

__all__ = [
    "EvaluatorVerbosity",
    "EventKind",
    "FrameworkEvent",
    "ProgressReporter",
    "RunDiagnostics",
    "coerce_evaluator_verbosity",
]
