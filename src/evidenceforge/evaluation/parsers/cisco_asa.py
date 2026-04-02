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

"""Parser for Cisco ASA firewall syslog files."""

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

# ASA syslog header: <pri>Mon DD HH:MM:SS hostname %ASA-sev-msgid: message
ASA_HEADER = re.compile(
    r"^<(\d+)>"  # <pri>
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"  # hostname
    r"%ASA-(\d)-(\d+):\s+"  # %ASA-severity-msgid:
    r"(.*)$"  # message body
)

# Built connection: "Built {inbound/outbound} TCP connection 12345 for inside:10.0.10.50/54321 ..."
BUILT_TCP_UDP = re.compile(
    r"Built\s+(?:inbound|outbound)\s+(?:TCP|UDP)\s+connection\s+(\d+)\s+for\s+"
    r"(\w+):(\S+)/(\d+)\s+\(\S+\)\s+to\s+"
    r"(\w+):(\S+)/(\d+)"
)

# Built ICMP: "Built {inbound/outbound} ICMP connection for faddr iface:ip/type ..."
BUILT_ICMP = re.compile(
    r"Built\s+(?:inbound|outbound)\s+ICMP\s+connection\s+for\s+faddr\s+"
    r"(\w+):(\S+)/(\d+)"
)

# Teardown connection: "Teardown TCP connection 12345 for inside:10.0.10.50/54321 to ..."
TEARDOWN_TCP_UDP = re.compile(
    r"Teardown\s+(?:TCP|UDP)\s+connection\s+(\d+)\s+for\s+"
    r"(\w+):(\S+)/(\d+)\s+to\s+"
    r"(\w+):(\S+)/(\d+)\s+"
    r"duration\s+(\S+)\s+bytes\s+(\d+)"
)

# Teardown ICMP: "Teardown ICMP connection for faddr iface:ip/type ..."
TEARDOWN_ICMP = re.compile(
    r"Teardown\s+ICMP\s+connection\s+for\s+faddr\s+"
    r"(\w+):(\S+)/(\d+)"
)

# Deny: "Deny tcp src outside:198.51.100.1/44231 dst inside:10.0.10.50/445 ..."
DENY = re.compile(
    r"Deny\s+(\w+)\s+src\s+(\w+):(\S+?)(?:/(\d+))?\s+"
    r"dst\s+(\w+):(\S+?)(?:/(\d+))?\s+"
    r"(?:\(type\s+(\d+),\s*code\s+(\d+)\)\s+)?"
    r'by\s+access-group\s+"([^"]+)"'
)


@register_parser
class CiscoAsaParser(LogParser):
    format_name = "cisco_asa"

    def can_parse(self, path: Path) -> bool:
        return path.name == "cisco_asa.log"

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

        header = ASA_HEADER.match(raw)
        if not header:
            errors.append("Line does not match ASA syslog format")
            return ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields={},
                timestamp=None,
                parse_errors=errors,
                line_number=line_num,
            )

        pri_str, ts_str, hostname, severity_str, msg_id_str, message = header.groups()

        # Parse timestamp (no year — use current year, same as syslog/snort)
        try:
            ts_with_year = f"{datetime.now().year} {ts_str}"
            timestamp = datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            errors.append(f"Invalid timestamp: {ts_str}")

        fields["pri"] = int(pri_str)
        fields["hostname"] = hostname
        fields["severity"] = int(severity_str)
        fields["msg_id"] = int(msg_id_str)
        fields["message"] = message

        # Extract src/dst IPs from message body based on msg_id
        msg_id = int(msg_id_str)
        self._extract_network_fields(msg_id, message, fields, errors)

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )

    @staticmethod
    def _extract_network_fields(msg_id: int, message: str, fields: dict, errors: list[str]) -> None:
        """Extract source/dest IPs and ports from the ASA message body."""
        if msg_id in (302013, 302015):
            match = BUILT_TCP_UDP.search(message)
            if match:
                fields["connection_id"] = int(match.group(1))
                fields["src_interface"] = match.group(2)
                fields["src_ip"] = match.group(3)
                fields["src_port"] = int(match.group(4))
                fields["dst_interface"] = match.group(5)
                fields["dst_ip"] = match.group(6)
                fields["dst_port"] = int(match.group(7))
        elif msg_id in (302020,):
            match = BUILT_ICMP.search(message)
            if match:
                fields["dst_interface"] = match.group(1)
                fields["dst_ip"] = match.group(2)
                fields["icmp_type"] = int(match.group(3))
        elif msg_id in (302014, 302016):
            match = TEARDOWN_TCP_UDP.search(message)
            if match:
                fields["connection_id"] = int(match.group(1))
                fields["src_interface"] = match.group(2)
                fields["src_ip"] = match.group(3)
                fields["src_port"] = int(match.group(4))
                fields["dst_interface"] = match.group(5)
                fields["dst_ip"] = match.group(6)
                fields["dst_port"] = int(match.group(7))
                fields["duration"] = match.group(8)
                fields["bytes"] = int(match.group(9))
        elif msg_id in (302021,):
            match = TEARDOWN_ICMP.search(message)
            if match:
                fields["dst_interface"] = match.group(1)
                fields["dst_ip"] = match.group(2)
                fields["icmp_type"] = int(match.group(3))
        elif msg_id == 106023:
            match = DENY.search(message)
            if match:
                fields["protocol"] = match.group(1)
                fields["src_interface"] = match.group(2)
                fields["src_ip"] = match.group(3)
                if match.group(4):
                    fields["src_port"] = int(match.group(4))
                fields["dst_interface"] = match.group(5)
                fields["dst_ip"] = match.group(6)
                if match.group(7):
                    fields["dst_port"] = int(match.group(7))
                if match.group(8):
                    fields["icmp_type"] = int(match.group(8))
                    fields["icmp_code"] = int(match.group(9))
                fields["access_group"] = match.group(10)
