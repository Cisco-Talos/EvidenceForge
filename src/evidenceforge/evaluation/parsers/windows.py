"""Parser for Windows Event Security XML logs."""

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# Namespace used in Windows Event XML
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Regex to split XML into individual <Event> blocks
EVENT_PATTERN = re.compile(r"<Event\s[^>]*>.*?</Event>", re.DOTALL)


@register_parser
class WindowsEventParser(LogParser):
    format_name = "windows_event_security"

    def can_parse(self, path: Path) -> bool:
        return path.name == "windows_event_security.xml"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        content = path.read_text(encoding="utf-8")
        for i, match in enumerate(EVENT_PATTERN.finditer(content), 1):
            raw = match.group(0)
            yield self._parse_event(raw, i)

    def _parse_event(self, raw: str, index: int) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        try:
            root = ET.fromstring(raw)

            # System fields
            system = root.find(f"{{{NS}}}System")
            if system is not None:
                eid_el = system.find(f"{{{NS}}}EventID")
                if eid_el is not None and eid_el.text:
                    fields["EventID"] = int(eid_el.text)

                tc_el = system.find(f"{{{NS}}}TimeCreated")
                if tc_el is not None:
                    ts_str = tc_el.get("SystemTime", "")
                    fields["TimeCreated"] = ts_str
                    try:
                        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except ValueError:
                        errors.append(f"Invalid timestamp: {ts_str}")

                comp_el = system.find(f"{{{NS}}}Computer")
                if comp_el is not None and comp_el.text:
                    fields["Computer"] = comp_el.text

                chan_el = system.find(f"{{{NS}}}Channel")
                if chan_el is not None and chan_el.text:
                    fields["Channel"] = chan_el.text

                level_el = system.find(f"{{{NS}}}Level")
                if level_el is not None and level_el.text:
                    fields["Level"] = int(level_el.text)

                erid_el = system.find(f"{{{NS}}}EventRecordID")
                if erid_el is not None and erid_el.text:
                    fields["EventRecordID"] = int(erid_el.text)

                exec_el = system.find(f"{{{NS}}}Execution")
                if exec_el is not None:
                    pid = exec_el.get("ProcessID")
                    tid = exec_el.get("ThreadID")
                    if pid:
                        fields["ExecutionProcessID"] = int(pid)
                    if tid:
                        fields["ExecutionThreadID"] = int(tid)

            # EventData fields (most event types)
            event_data = root.find(f"{{{NS}}}EventData")
            if event_data is not None:
                for data_el in event_data.findall(f"{{{NS}}}Data"):
                    name = data_el.get("Name", "")
                    value = data_el.text or ""
                    if name:
                        # Try to coerce known integer fields
                        if name in (
                            "LogonType",
                            "IpPort",
                            "KeyLength",
                            "PreAuthType",
                            "NetworkPort",
                            "SourcePort",
                            "DestPort",
                            "Protocol",
                            "FilterRTID",
                            "LayerRTID",
                            "ProcessID",
                        ):
                            try:
                                fields[name] = int(value)
                            except ValueError:
                                fields[name] = value
                        else:
                            fields[name] = value

            # UserData fields (1102 LogFileCleared and similar)
            user_data = root.find(f"{{{NS}}}UserData")
            if user_data is not None:
                # UserData contains a wrapper element (e.g., LogFileCleared)
                # with child elements as fields
                for wrapper in user_data:
                    for child in wrapper:
                        # Strip namespace from tag name
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if child.text:
                            fields[tag] = child.text

        except ET.ParseError as e:
            errors.append(f"XML parse error: {e}")

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=index,
        )
