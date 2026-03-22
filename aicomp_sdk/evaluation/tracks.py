from __future__ import annotations

from enum import StrEnum


class EvaluationTrack(StrEnum):
    REDTEAM = "redteam"
    DEFENSE = "defense"
    DUAL = "dual"
