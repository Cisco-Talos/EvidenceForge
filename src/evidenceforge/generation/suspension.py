"""Intentional generation suspension control flow."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.generation.checkpoints.models import CheckpointCursor


class GenerationSuspendedError(Exception):
    """Signal successful planned suspension after a durable recovery commit."""

    def __init__(self, cursor: CheckpointCursor) -> None:
        super().__init__(
            f"generation suspended at simulated hour {cursor.completed_simulated_hours}"
        )
        self.cursor = cursor


__all__ = ["GenerationSuspendedError"]
