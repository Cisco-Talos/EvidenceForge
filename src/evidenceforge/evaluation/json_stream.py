"""Bounded JSON value decoding for evaluator-owned streamed container formats."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, TextIO


class JsonStreamReader:
    """Decode individual JSON values while streaming the manifest's file mapping."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.buffer = ""
        self.eof = False
        self.decoder = json.JSONDecoder()

    def _fill(self) -> None:
        chunk = self.stream.read(64 * 1024)
        self.buffer += chunk
        self.eof = not chunk

    def peek(self) -> str:
        self.buffer = self.buffer.lstrip()
        while not self.buffer and not self.eof:
            self._fill()
            self.buffer = self.buffer.lstrip()
        return self.buffer[:1]

    def expect(self, token: str) -> None:
        if self.peek() != token:
            raise ValueError(f"Expected JSON {token!r}")
        self.buffer = self.buffer[1:]

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer)
            except json.JSONDecodeError:
                if self.eof:
                    raise
            else:
                # A scalar at a chunk boundary may still have more digits/exponent bytes.
                complete = end < len(self.buffer) or self.eof
                if isinstance(value, int | float) and not isinstance(value, bool):
                    # raw_decode accepts the prefix of incomplete numbers such as "1e+".
                    complete = self.eof or (
                        end < len(self.buffer) and self.buffer[end] in " \t\r\n,]}:"
                    )
                if complete:
                    if len(self.buffer[:end].encode("utf-8")) > 16 * 1024 * 1024:
                        from evidenceforge.models.exceptions import EvaluationLimitError

                        raise EvaluationLimitError(
                            "JSON value exceeds the per-record input protection"
                        )
                    self.buffer = self.buffer[end:]
                    return value
            if len(self.buffer) > 16 * 1024 * 1024:
                from evidenceforge.models.exceptions import EvaluationLimitError

                raise EvaluationLimitError("JSON value exceeds the per-record input protection")
            self._fill()

    def object_items(self) -> Iterator[tuple[str, Any]]:
        self.expect("{")
        if self.peek() == "}":
            self.expect("}")
            return
        while True:
            key = self.value()
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            self.expect(":")
            yield key, self.value()
            if self.peek() == "}":
                self.expect("}")
                return
            self.expect(",")

    def array_items(self) -> Iterator[Any]:
        self.expect("[")
        if self.peek() == "]":
            self.expect("]")
            return
        while True:
            yield self.value()
            if self.peek() == "]":
                self.expect("]")
                return
            self.expect(",")

    def object_keys(self) -> Iterator[str]:
        """Yield keys after their colon; the caller consumes each corresponding value."""
        self.expect("{")
        if self.peek() == "}":
            self.expect("}")
            return
        while True:
            key = self.value()
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            self.expect(":")
            yield key
            if self.peek() == "}":
                self.expect("}")
                return
            self.expect(",")

    def skip(self, depth: int = 0) -> None:
        """Skip an unrelated container without materializing its full contents."""
        if depth > 128:
            from evidenceforge.models.exceptions import EvaluationLimitError

            raise EvaluationLimitError("JSON nesting exceeds the per-record input protection")
        token = self.peek()
        if token == "{":
            for _ in self.object_keys():
                self.skip(depth + 1)
        elif token == "[":
            self.expect("[")
            if self.peek() == "]":
                self.expect("]")
                return
            while True:
                self.skip(depth + 1)
                if self.peek() == "]":
                    self.expect("]")
                    return
                self.expect(",")
        else:
            self.value()
