# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

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
