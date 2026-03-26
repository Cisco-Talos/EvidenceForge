"""Parser for HTTP/HTTPS forward proxy access logs (W3C Extended format)."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# W3C Extended format:
# date time c-ip cs-username cs-method cs-uri sc-status sc-bytes cs-bytes time-taken "cs(User-Agent)" cs-host rs(Content-Type) s-cache-result
_PROXY_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"  # client_ip
    r"(\S+)\s+"  # username
    r"(\S+)\s+"  # method
    r"(\S+)\s+"  # url
    r"(\d+)\s+"  # status_code
    r"(\d+)\s+"  # sc_bytes
    r"(\d+)\s+"  # cs_bytes
    r"(\d+)\s+"  # time_taken
    r'"([^"]*)"\s+'  # user_agent
    r"(\S+)\s+"  # host
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
        fields["username"] = username if username != "-" else None
        fields["method"] = match.group(4)
        fields["url"] = match.group(5)
        fields["status_code"] = int(match.group(6))
        fields["sc_bytes"] = int(match.group(7))
        fields["cs_bytes"] = int(match.group(8))
        fields["time_taken"] = int(match.group(9))
        ua = match.group(10)
        fields["user_agent"] = ua if ua != "-" else None
        fields["host"] = match.group(11)
        ct = match.group(12)
        fields["content_type"] = ct if ct != "-" else None
        cr = match.group(13)
        fields["cache_result"] = cr if cr != "-" else None

        return ParsedRecord(
            source_format=self.format_name,
            raw=line,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_number,
        )
