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

"""The one table of collection source formats, their families and their owners.

The source catalog builds its descriptors from this table, and the scenario model derives its
authored observation vocabulary from it. Adding a source format here is the only way to make it
known to both. The module is dependency-free so either side can import it without a cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

SourceOwner = Literal["host", "sensor"]

# Ordered for stable public schema enums: endpoint families, then network sensors.
SOURCE_FORMATS: Final[Mapping[str, tuple[str, SourceOwner]]] = MappingProxyType(
    {
        "windows_event_security": ("windows_security", "host"),
        "windows_event_sysmon": ("sysmon", "host"),
        "ecar": ("ecar", "host"),
        "syslog": ("syslog", "host"),
        "bash_history": ("bash_history", "host"),
        "zsh_history": ("zsh_history", "host"),
        "macos_endpoint_security": ("macos_endpoint_security", "host"),
        "macos_unified_log": ("macos_unified_log", "host"),
        "zeek_conn": ("zeek", "sensor"),
        "zeek_dns": ("zeek", "sensor"),
        "zeek_http": ("zeek", "sensor"),
        "zeek_smtp": ("zeek", "sensor"),
        "zeek_ssl": ("zeek", "sensor"),
        "zeek_files": ("zeek", "sensor"),
        "zeek_smb_files": ("zeek", "sensor"),
        "zeek_smb_mapping": ("zeek", "sensor"),
        "zeek_x509": ("zeek", "sensor"),
        "zeek_dhcp": ("zeek", "sensor"),
        "zeek_ntp": ("zeek", "sensor"),
        "zeek_weird": ("zeek", "sensor"),
        "zeek_ocsp": ("zeek", "sensor"),
        "zeek_pe": ("zeek", "sensor"),
        "zeek_packet_filter": ("zeek", "sensor"),
        "zeek_reporter": ("zeek", "sensor"),
        "proxy_access": ("proxy", "host"),
        "web_access": ("web", "host"),
        "cisco_asa": ("asa", "sensor"),
        "snort_alert": ("ids", "sensor"),
    }
)

SOURCE_FORMAT_NAMES: Final[tuple[str, ...]] = tuple(SOURCE_FORMATS)
SOURCE_FAMILY_NAMES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(family for family, _owner in SOURCE_FORMATS.values())
)
FORMAT_FAMILIES: Final[Mapping[str, str]] = MappingProxyType(
    {name: family for name, (family, _owner) in SOURCE_FORMATS.items()}
)
HOST_SOURCE_FAMILIES: Final[frozenset[str]] = frozenset(
    family for family, owner in SOURCE_FORMATS.values() if owner == "host"
)
