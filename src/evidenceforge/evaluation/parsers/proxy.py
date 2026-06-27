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

"""Parser for HTTP/HTTPS forward proxy access logs."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from . import LogParser, ParsedRecord, register_parser

# Apache/Nginx combined format:
# client_ip - username [timestamp] "method url protocol" status bytes "referer" "user_agent"
_COMBINED_PROXY_PATTERN = re.compile(
    r"^(\S+)\s+"  # client_ip
    r"\S+\s+"  # ident (always -)
    r"(\S+)\s+"  # username (or -)
    r"\[([^\]]+)\]\s+"  # [timestamp]
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # "method url protocol"
    r"(\d+)\s+"  # status_code
    r"(\S+)\s+"  # bytes_sent (or -)
    r'"([^"]*)"\s+'  # "referer"
    r'"([^"]*)"'  # "user_agent"
)

# Legacy W3C Extended format:
# date time c-ip cs-username cs-method cs-uri cs-version sc-status sc-bytes cs-bytes time-taken cs-host cs(User-Agent) cs(Referer) rs(Content-Type) s-cache-result [x-proxy-action]
_LEGACY_W3C_PROXY_PATTERN = re.compile(
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
    r"(?:\s+(\S+))?"  # optional proxy_action
)


def _proxy_host_from_request_target(method: str, request_target: str) -> str | None:
    """Return destination host from a proxy request target when it is present."""
    if method.upper() == "CONNECT":
        authority = request_target.rsplit("@", 1)[-1]
        host, _separator, _port = authority.partition(":")
        return host or None

    try:
        parsed = urlsplit(request_target)
    except ValueError:
        return None
    return parsed.hostname


@register_parser
class ProxyAccessParser(LogParser):
    format_name = "proxy_access"

    def can_parse(self, path: Path) -> bool:
        return path.name == "proxy_access.log"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        hostname = self._source_host_from_path(path)
        with open(path) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield self._parse_line(line, i, hostname=hostname)

    @staticmethod
    def _source_host_from_path(path: Path) -> str | None:
        parent = path.parent
        if parent.name in {"data", "logs", "output"}:
            return None
        return parent.name

    def _parse_line(self, line: str, line_number: int, hostname: str | None = None) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        match = _COMBINED_PROXY_PATTERN.match(line)
        if match:
            (
                client_ip,
                username,
                ts_str,
                method,
                request_target,
                protocol,
                status,
                bytes_sent,
                referrer,
                user_agent,
            ) = match.groups()

            try:
                timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                try:
                    timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=UTC)
                except ValueError:
                    errors.append(f"Invalid timestamp: {ts_str}")

            fields["timestamp"] = ts_str
            fields["client_ip"] = client_ip
            if username != "-":
                fields["username"] = username
            fields["method"] = method
            fields["url"] = request_target
            fields["path"] = request_target
            fields["protocol"] = protocol
            fields["status_code"] = int(status)
            if bytes_sent != "-":
                try:
                    parsed_bytes = int(bytes_sent)
                    fields["bytes_sent"] = parsed_bytes
                    fields["sc_bytes"] = parsed_bytes
                except ValueError:
                    fields["bytes_sent"] = bytes_sent
            if referrer != "-":
                fields["referrer"] = referrer
            if user_agent != "-":
                fields["user_agent"] = user_agent
            host = _proxy_host_from_request_target(method, request_target)
            if host:
                fields["host"] = host

            return ParsedRecord(
                source_format=self.format_name,
                raw=line,
                fields=fields,
                timestamp=timestamp,
                parse_errors=errors,
                line_number=line_number,
                source_host=hostname,
            )

        match = _LEGACY_W3C_PROXY_PATTERN.match(line)
        if not match:
            errors.append("Line does not match proxy access format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=line,
                fields=fields,
                timestamp=None,
                parse_errors=errors,
                line_number=line_number,
                source_host=hostname,
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
        action = match.group(16)
        if action and action != "-":
            fields["proxy_action"] = action

        return ParsedRecord(
            source_format=self.format_name,
            raw=line,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_number,
            source_host=hostname,
        )
