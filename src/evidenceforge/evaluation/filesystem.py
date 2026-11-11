"""Streaming directory traversal for evaluator-owned input inventories."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path


def directory_entries(directory: Path) -> Iterator[Path]:
    """Yield paths without materializing a complete directory's filename list."""
    with os.scandir(directory) as entries:
        for entry in entries:
            yield Path(entry.path)
