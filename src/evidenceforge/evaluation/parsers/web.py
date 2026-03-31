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

"""Parser for W3C web access log files."""

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# Apache/Nginx combined log format:
# client_ip - username [timestamp] "method path protocol" status bytes "referer" "user_agent"
WEB_ACCESS_PATTERN = re.compile(
    r"^(\S+)\s+"  # client_ip
    r"\S+\s+"  # ident (always -)
    r"(\S+)\s+"  # username (or -)
    r"\[([^\]]+)\]\s+"  # [timestamp]
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # "method path protocol"
    r"(\d+)\s+"  # status_code
    r"(\S+)\s+"  # bytes_sent (or -)
    r'"([^"]*)"\s+'  # "referer"
    r'"([^"]*)"'  # "user_agent"
)


@register_parser
class WebAccessParser(LogParser):
    format_name = "web_access"

    def can_parse(self, path: Path) -> bool:
        return path.name == "web_access.log"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        with path.open(encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                yield self._parse_line(line, line_num)

    def _parse_line(self, raw: str, line_num: int) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        match = WEB_ACCESS_PATTERN.match(raw)
        if not match:
            errors.append("Line does not match web access log format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields={},
                timestamp=None,
                parse_errors=errors,
                line_number=line_num,
            )

        (
            client_ip,
            username,
            ts_str,
            method,
            path_str,
            protocol,
            status,
            bytes_sent,
            referer,
            user_agent,
        ) = match.groups()

        # Parse CLF timestamp: dd/Mon/YYYY:HH:MM:SS +ZZZZ
        try:
            timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            # Try without timezone
            try:
                timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                errors.append(f"Invalid timestamp: {ts_str}")

        fields["client_ip"] = client_ip
        if username != "-":
            fields["username"] = username
        fields["method"] = method
        fields["path"] = path_str
        fields["protocol"] = protocol
        fields["status_code"] = int(status)

        if bytes_sent != "-":
            try:
                fields["bytes_sent"] = int(bytes_sent)
            except ValueError:
                fields["bytes_sent"] = bytes_sent

        if referer != "-":
            fields["referer"] = referer
        if user_agent != "-":
            fields["user_agent"] = user_agent

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )
