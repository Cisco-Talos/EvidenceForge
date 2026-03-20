"""Parser for syslog (RFC 5424 / BSD) text files."""

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# BSD syslog format: "Mon DD HH:MM:SS hostname app[pid]: message"
# Also handles "Mon DD HH:MM:SS hostname app: message" (no PID, e.g., kernel)
SYSLOG_PATTERN = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp (BSD)
    r"(\S+)\s+"                                   # hostname
    r"(\S+?)(?:\[([^\]]*)\])?:\s+"                # app_name[pid]: or app_name:
    r"(.*)$"                                       # message
)

# ISO 8601 variant: "2026-03-15T10:15:00Z hostname app[pid]: message"
SYSLOG_ISO_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+"  # ISO timestamp
    r"(\S+)\s+"                                          # hostname
    r"(\S+?)(?:\[([^\]]*)\])?:\s+"                       # app_name[pid]: or app_name:
    r"(.*)$"                                              # message
)


@register_parser
class SyslogParser(LogParser):
    format_name = "syslog"

    def can_parse(self, path: Path) -> bool:
        return path.name == "syslog.log"

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

        # Try ISO format first, then BSD
        match = SYSLOG_ISO_PATTERN.match(raw)
        if match:
            ts_str, hostname, app_name, pid_str, message = match.groups()
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"Invalid ISO timestamp: {ts_str}")
        else:
            match = SYSLOG_PATTERN.match(raw)
            if match:
                ts_str, hostname, app_name, pid_str, message = match.groups()
                # BSD timestamps lack year — best-effort parse
                try:
                    # Use current year as fallback
                    ts_with_year = f"{datetime.now().year} {ts_str}"
                    timestamp = datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")
                except ValueError:
                    errors.append(f"Invalid BSD timestamp: {ts_str}")
            else:
                errors.append("Line does not match syslog format")
                return ParsedRecord(
                    source_format=self.format_name,
                    raw=raw,
                    fields={},
                    timestamp=None,
                    parse_errors=errors,
                    line_number=line_num,
                )

        fields["timestamp"] = str(timestamp) if timestamp else ts_str
        fields["hostname"] = hostname
        fields["app_name"] = app_name
        fields["message"] = message

        if pid_str is not None and pid_str != "-":
            try:
                fields["pid"] = int(pid_str)
            except ValueError:
                fields["pid"] = pid_str

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )
