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

"""Parser for HTTP/HTTPS forward proxy access logs (W3C Extended format)."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# W3C Extended format:
# date time c-ip cs-username cs-method cs-uri cs-version sc-status sc-bytes cs-bytes time-taken cs-host cs(User-Agent) cs(Referer) rs(Content-Type) s-cache-result
_PROXY_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"  # client_ip
    r"(\S+)\s+"  # username
    r"(\S+)\s+"  # method
    r"(\S+)\s+"  # url
    r"(\S+)\s+"  # protocol
    r"(\d+)\s+"  # status_code
    r"(\d+)\s+"  # sc_bytes
    r"(\d+)\s+"  # cs_bytes
    r"(\d+)\s+"  # time_taken
    r"(\S+)\s+"  # host
    r"(\S+)\s+"  # user_agent
    r"(\S+)\s+"  # referrer
    r"(\S+)\s+"  # content_type
    r"(\S+)"  # cache_result
)


@register_parser
class ProxyAccessParser(LogParser):
    format_name = "proxy_access"

    def can_parse(self, path: Path) -> bool:
        return path.name == "proxy_access.log"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        with open(path) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield self._parse_line(line, i)

    def _parse_line(self, line: str, line_number: int) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        match = _PROXY_PATTERN.match(line)
        if not match:
            errors.append("Line does not match proxy access format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=line,
                fields=fields,
                timestamp=None,
                parse_errors=errors,
                line_number=line_number,
            )

        ts_str = match.group(1)
        try:
            timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            errors.append(f"Invalid timestamp: {ts_str}")

        fields["timestamp"] = ts_str
        fields["client_ip"] = match.group(2)
        username = match.group(3)
        if username != "-":
            fields["username"] = username
        fields["method"] = match.group(4)
        fields["url"] = match.group(5)
        protocol = match.group(6)
        if protocol != "-":
            fields["protocol"] = protocol
        fields["status_code"] = int(match.group(7))
        fields["sc_bytes"] = int(match.group(8))
        fields["cs_bytes"] = int(match.group(9))
        fields["time_taken"] = int(match.group(10))
        fields["host"] = match.group(11)
        ua = match.group(12)
        if ua != "-":
            fields["user_agent"] = ua.replace("+", " ")
        referrer = match.group(13)
        if referrer != "-":
            fields["referrer"] = referrer
        ct = match.group(14)
        if ct != "-":
            fields["content_type"] = ct
        cr = match.group(15)
        if cr != "-":
            fields["cache_result"] = cr

        return ParsedRecord(
            source_format=self.format_name,
            raw=line,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_number,
        )
