"""Parser for bash history files (per-user per-host)."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

TIMESTAMP_PATTERN = re.compile(r"^#(\d+)$")


@register_parser
class BashHistoryParser(LogParser):
    format_name = "bash_history"

    def can_parse(self, path: Path) -> bool:
        return path.suffix in (".history", ".bash_history") and "bash_history" in str(path)

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        """Parse a single bash history file.

        Supports path layouts:
        - bash_history/<hostname>/<username>.history  (old flat layout)
        - <host_fqdn>/bash_history/<username>.bash_history  (new per-host layout)
        Format: #<epoch> followed by command on next line.
        """
        # Extract hostname and username from path
        username = path.stem
        if path.parent.name == "bash_history":
            # New layout: <host_fqdn>/bash_history/<user>.bash_history
            hostname = path.parent.parent.name
        else:
            # Old layout: bash_history/<hostname>/<user>.history
            hostname = path.parent.name

        with path.open(encoding="utf-8") as f:
            lines = f.readlines()

        record_num = 0
        i = 0
        while i < len(lines):
            line = lines[i].rstrip("\n")
            ts_match = TIMESTAMP_PATTERN.match(line)
            if ts_match:
                epoch = int(ts_match.group(1))
                # Next line is the command
                command = ""
                if i + 1 < len(lines):
                    command = lines[i + 1].rstrip("\n")
                    i += 2
                else:
                    i += 1

                record_num += 1
                timestamp = None
                errors: list[str] = []
                try:
                    timestamp = datetime.fromtimestamp(epoch, tz=UTC)
                except (ValueError, OSError):
                    errors.append(f"Invalid epoch: {epoch}")

                raw = f"#{epoch}\n{command}" if command else f"#{epoch}"
                yield ParsedRecord(
                    source_format=self.format_name,
                    raw=raw,
                    fields={
                        "timestamp": epoch,
                        "username": username,
                        "hostname": hostname,
                        "command": command,
                    },
                    timestamp=timestamp,
                    parse_errors=errors,
                    line_number=record_num,
                )
            else:
                # Orphan command line without timestamp
                if line.strip():
                    record_num += 1
                    yield ParsedRecord(
                        source_format=self.format_name,
                        raw=line,
                        fields={
                            "username": username,
                            "hostname": hostname,
                            "command": line,
                        },
                        timestamp=None,
                        parse_errors=["Command without preceding timestamp"],
                        line_number=record_num,
                    )
                i += 1
