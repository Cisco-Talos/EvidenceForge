"""Intentional generation suspension control flow."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.generation.checkpoints.models import CheckpointCursor


class GenerationSuspendedError(Exception):
    """Signal successful cooperative suspension after a durable recovery commit."""

    def __init__(
        self,
        cursor: CheckpointCursor,
        *,
        requested_by_signal: bool = False,
    ) -> None:
        super().__init__(
            f"generation suspended at simulated hour {cursor.completed_simulated_hours}"
        )
        self.cursor = cursor
        self.requested_by_signal = requested_by_signal


__all__ = ["GenerationSuspendedError"]
