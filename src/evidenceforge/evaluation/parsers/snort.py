"""Parser for Snort/Suricata fast alert files."""

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# Snort fast alert format:
# MM/DD-HH:MM:SS.ffffff [**] [sid:rev:gid] message [**] [Classification: class] [Priority: pri] {PROTO} src:port -> dst:port
SNORT_PATTERN = re.compile(
    r"^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"  # timestamp
    r"\[\*\*\]\s+\[(\d+):\d+:\d+\]\s+"  # [sid:rev:gid]
    r"(.*?)\s+\[\*\*\]\s+"  # message
    r"\[Classification:\s*(.*?)\]\s+"  # classification
    r"\[Priority:\s*(\d+)\]\s+"  # priority
    r"\{(\w+)\}\s+"  # {protocol}
    r"(\S+)\s+->\s+(\S+)$"  # src -> dst
)


@register_parser
class SnortAlertParser(LogParser):
    format_name = "snort_alert"

    def can_parse(self, path: Path) -> bool:
        return path.name == "snort_alert.alert"

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

        match = SNORT_PATTERN.match(raw)
        if not match:
            errors.append("Line does not match Snort alert format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields={},
                timestamp=None,
                parse_errors=errors,
                line_number=line_num,
            )

        ts_str, sid, message, classification, priority, protocol, src, dst = match.groups()

        # Parse timestamp (MM/DD-HH:MM:SS.ffffff — no year)
        try:
            ts_with_year = f"{datetime.now().year}/{ts_str}"
            timestamp = datetime.strptime(ts_with_year, "%Y/%m/%d-%H:%M:%S.%f")
        except ValueError:
            errors.append(f"Invalid timestamp: {ts_str}")

        fields["timestamp"] = ts_str
        fields["sid"] = int(sid)
        fields["message"] = message.strip()
        fields["classification"] = classification.strip()
        fields["priority"] = int(priority)
        fields["protocol"] = protocol

        # Parse src ip:port
        src_ip, src_port = self._parse_endpoint(src)
        fields["src_ip"] = src_ip
        if src_port is not None:
            fields["src_port"] = src_port

        # Parse dst ip:port
        dst_ip, dst_port = self._parse_endpoint(dst)
        fields["dst_ip"] = dst_ip
        if dst_port is not None:
            fields["dst_port"] = dst_port

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int | None]:
        """Parse 'ip:port' or just 'ip'."""
        if ":" in endpoint:
            parts = endpoint.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return endpoint, None
        return endpoint, None
