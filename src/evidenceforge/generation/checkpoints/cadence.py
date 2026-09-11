"""Cadence-only checkpoint scheduling across warm-up and collection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .models import CheckpointCursor


@dataclass(frozen=True)
class CheckpointCadence:
    """Select recovery points solely from completed simulated-hour multiples."""

    hours: int

    def __post_init__(self) -> None:
        if self.hours < 0:
            raise ValueError("checkpoint hours cannot be negative")

    @property
    def enabled(self) -> bool:
        """Return whether this run creates new recovery points."""

        return self.hours > 0

    def is_due(self, completed_simulated_hours: int) -> bool:
        """Return whether exactly this completed-hour position is scheduled."""

        if completed_simulated_hours < 0:
            raise ValueError("completed simulated hours cannot be negative")
        return (
            self.enabled
            and completed_simulated_hours > 0
            and (completed_simulated_hours % self.hours == 0)
        )

    def cursor_after_hour(
        self,
        *,
        completed_simulated_hours: int,
        next_hour: datetime,
        collection_start: datetime,
        collection_end: datetime,
    ) -> CheckpointCursor | None:
        """Build one post-transition cursor when this completed hour is due."""

        if not self.is_due(completed_simulated_hours):
            return None
        if next_hour < collection_start:
            phase = "warmup"
            encoded_next = next_hour.isoformat()
        elif next_hour < collection_end:
            phase = "collection"
            encoded_next = next_hour.isoformat()
        else:
            phase = "tail"
            encoded_next = None
        return CheckpointCursor(
            phase=phase,
            completed_simulated_hours=completed_simulated_hours,
            next_hour=encoded_next,
        )
