"""Machine-readable progress stream for long-running CLI operations."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, TextIO


def _json_default(value: object) -> str:
    """Serialize time values carried by generation progress events."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"Unsupported progress value: {type(value).__name__}")


class ProgressJSONLWriter:
    """Write one flushed JSON object for every engine progress callback."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._stream: TextIO | None = None

    def __enter__(self) -> ProgressJSONLWriter:
        self._stream = self.path.open("w", encoding="utf-8")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        """Append a versioned event and flush it for live readers."""
        if self._stream is None:
            raise RuntimeError("Progress JSONL writer is not open")
        payload = {"schema_version": 1, "event": event_type, "data": data}
        self._stream.write(json.dumps(payload, default=_json_default, separators=(",", ":")))
        self._stream.write("\n")
        self._stream.flush()
