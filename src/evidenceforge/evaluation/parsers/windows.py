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

"""Parser for Windows Event Security XML logs."""

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.generation.emitters.windows_snare import (
    WINDOWS_SECURITY_SNARE_FILENAME,
    WINDOWS_SYSMON_SNARE_FILENAME,
)

from . import LogParser, ParsedRecord, register_parser
from .syslog import _infer_seed_year, _resolve_bsd_year

# Namespace used in Windows Event XML
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Regex boundaries used for streaming extraction of individual <Event> blocks
EVENT_START_PATTERN = re.compile(r"<Event(?:\s|>)")
EVENT_END_PATTERN = re.compile(r"</Event>")
SNARE_SYSLOG_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<payload>.*)$"
)
EXPANDED_FIELD_PATTERN = re.compile(r"(?P<name>[^:]+):\s+(?P<value>.*?)(?=\s{2}[^:]+:\s+|\s*$)")


class _WindowsXmlParser(LogParser):
    """Shared streaming parser for Windows Event XML files."""

    xml_filename = ""

    _INTEGER_EVENT_DATA_FIELDS = frozenset(
        {
            "LogonType",
            "IpPort",
            "KeyLength",
            "PreAuthType",
            "NetworkPort",
            "SessionId",
            "SourcePort",
            "DestPort",
            "Protocol",
            "FilterRTID",
            "LayerRTID",
            "ProcessID",
        }
    )

    def can_parse(self, path: Path) -> bool:
        return path.name == self.xml_filename

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        event_index = 0
        in_event = False
        event_lines: list[str] = []

        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not in_event and EVENT_START_PATTERN.search(line):
                    in_event = True
                    event_lines = [line]
                    if EVENT_END_PATTERN.search(line):
                        event_index += 1
                        yield self._parse_event("".join(event_lines), event_index)
                        in_event = False
                        event_lines = []
                    continue

                if in_event:
                    event_lines.append(line)
                    if EVENT_END_PATTERN.search(line):
                        event_index += 1
                        yield self._parse_event("".join(event_lines), event_index)
                        in_event = False
                        event_lines = []

    def _parse_event(self, raw: str, index: int) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        try:
            if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
                raise ET.ParseError("DOCTYPE and ENTITY declarations are not allowed")

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
                        fields[name] = self._coerce_event_data_field(name, value)

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

    def _coerce_event_data_field(self, name: str, value: str) -> str | int:
        """Coerce source-native integer EventData fields for validation."""
        if name in self._INTEGER_EVENT_DATA_FIELDS:
            try:
                return int(value)
            except ValueError:
                return value
        return value


class _WindowsSnareParser(_WindowsXmlParser):
    """Shared parser for Snare-over-RFC3164 Windows event files."""

    snare_filename = ""
    xml_filename = ""

    def can_parse(self, path: Path) -> bool:
        return path.name in {self.xml_filename, self.snare_filename}

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        if path.name == self.snare_filename:
            yield from self._parse_snare_file(path)
            return
        yield from super().parse_file(path)

    def _parse_snare_file(self, path: Path) -> Iterator[ParsedRecord]:
        seed_year = _infer_seed_year(path, getattr(self, "scenario", None))
        last_ts: datetime | None = None
        with path.open("r", encoding="utf-8") as handle:
            for line_num, line in enumerate(handle, 1):
                raw = line.rstrip("\n")
                if not raw:
                    continue
                record = self._parse_snare_line(raw, line_num, seed_year, last_ts)
                if record.timestamp is not None:
                    last_ts = record.timestamp
                yield record

    def _parse_snare_line(
        self,
        raw: str,
        line_num: int,
        seed_year: int,
        last_ts: datetime | None,
    ) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None
        source_host = None

        match = SNARE_SYSLOG_PATTERN.match(raw)
        if match is None:
            errors.append("Line does not match Snare RFC3164 syslog format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields=fields,
                timestamp=None,
                parse_errors=errors,
                line_number=line_num,
            )

        groups = match.groupdict()
        source_host = groups["hostname"]
        timestamp = _resolve_bsd_year(groups["timestamp"], seed_year, last_ts)
        if timestamp is None:
            errors.append(f"Invalid Snare syslog timestamp: {groups['timestamp']}")
        else:
            timestamp = timestamp.replace(tzinfo=UTC)

        fields["pri"] = int(groups["pri"])
        fields["Computer"] = source_host
        fields["TimeCreated"] = timestamp.isoformat() if timestamp else groups["timestamp"]

        columns = groups["payload"].split("\t")
        if len(columns) < 14:
            errors.append(f"Snare payload has {len(columns)} columns; expected at least 14")
        else:
            (
                computer,
                marker,
                criticality,
                channel,
                event_record_id,
                snare_time,
                event_id,
                provider,
                username,
                _sid,
                logtype,
                _computer_repeat,
                category,
                full_data,
                *_extra,
            ) = columns
            if marker != "MSWinEventLog":
                errors.append(f"Unexpected Snare marker: {marker}")
            fields.update(
                {
                    "Computer": computer or source_host,
                    "Channel": channel,
                    "Provider": provider,
                    "User": username,
                    "LogType": logtype,
                    "Category": category,
                    "Message": full_data,
                    "SnareTimeCreated": snare_time,
                }
            )
            for key, value, converter in (
                ("EventRecordID", event_record_id, int),
                ("EventID", event_id, int),
                ("Criticality", criticality, int),
            ):
                try:
                    fields[key] = converter(value)
                except ValueError:
                    fields[key] = value
                    errors.append(f"Invalid integer field {key}: {value}")
            fields.update(
                {
                    name: self._coerce_event_data_field(name, value)
                    for name, value in _parse_expanded_snare_fields(full_data).items()
                }
            )

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
            source_host=source_host,
        )


def _parse_expanded_snare_fields(full_data: str) -> dict[str, str]:
    """Extract Snare's flattened ``Name: value`` field suffix."""
    parsed: dict[str, str] = {}
    tail = full_data.split(":  ", 1)[1] if ":  " in full_data else full_data
    for match in EXPANDED_FIELD_PATTERN.finditer(tail):
        name = _snare_field_name(match.group("name").strip())
        value = match.group("value").strip()
        if name and value:
            parsed[name] = value
    return parsed


def _snare_field_name(name: str) -> str:
    """Return a stable eval-friendly field name for a Snare expanded label."""
    if not name:
        return ""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return name
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")


@register_parser
class WindowsEventParser(_WindowsSnareParser):
    """Parser for Windows Security XML or SOF-ELK Snare target files."""

    format_name = "windows_event_security"
    xml_filename = "windows_event_security.xml"
    snare_filename = WINDOWS_SECURITY_SNARE_FILENAME


@register_parser
class SysmonEventParser(_WindowsSnareParser):
    """Parser for Sysmon XML or SOF-ELK Snare target files."""

    format_name = "windows_event_sysmon"
    xml_filename = "windows_event_sysmon.xml"
    snare_filename = WINDOWS_SYSMON_SNARE_FILENAME
    _INTEGER_EVENT_DATA_FIELDS = _WindowsXmlParser._INTEGER_EVENT_DATA_FIELDS | frozenset(
        {
            "DestinationPort",
            "NewThreadId",
            "ParentProcessId",
            "ProcessId",
            "SourceProcessId",
            "SourceThreadId",
            "SourcePort",
            "TargetProcessId",
            "TerminalSessionId",
        }
    )
