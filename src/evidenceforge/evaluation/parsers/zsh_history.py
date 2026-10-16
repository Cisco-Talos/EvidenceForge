# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Parse the bounded single-line zsh extended history export profile."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import LogParser, ParsedRecord, iter_bounded_text_lines, register_parser

_ENTRY = re.compile(r"^: ([0-9]+):([0-9]+);(.+)$")


@register_parser
class ZshHistoryParser(LogParser):
    """Normalize extended history; reject unsupported multiline records explicitly."""

    format_name = "zsh_history"

    def can_parse(self, path: Path) -> bool:
        """Recognize the canonical per-host history route."""
        return path.suffix == ".zsh_history" and path.parent.name == "zsh_history"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        """Yield records and bounded parse diagnostics without inventing timestamps."""
        for line_number, raw in iter_bounded_text_lines(path):
            line = raw.rstrip("\r\n")
            match = _ENTRY.fullmatch(line)
            fields: dict[str, object] = {
                "hostname": path.parent.parent.name,
                "username": path.stem,
            }
            errors: list[str] = []
            timestamp: datetime | None = None
            if match is None:
                errors.append("Unsupported zsh extended history record")
            else:
                epoch, duration, command = match.groups()
                fields["command"] = command
                try:
                    epoch_value = int(epoch)
                    timestamp = datetime.fromtimestamp(epoch_value, UTC)
                    fields["timestamp"] = epoch_value
                except (ValueError, OverflowError, OSError):
                    errors.append("Invalid zsh history epoch")
                try:
                    duration_value = int(duration)
                    if duration_value > (1 << 63) - 1:
                        raise ValueError("Duration exceeds the supported signed 64-bit range")
                    fields["duration_seconds"] = duration_value
                except ValueError:
                    errors.append("Invalid zsh history duration")
                if not command.isascii() or "\x00" in command or command.endswith("\\"):
                    errors.append("Unsupported zsh multiline or metafied command")
            yield ParsedRecord(
                source_format=self.format_name,
                raw=line,
                fields=fields,
                timestamp=timestamp,
                parse_errors=errors,
                line_number=line_number,
            )
