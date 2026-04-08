# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Extract hostnames from process command lines for validation."""

from __future__ import annotations

import re

# Match URLs in command lines (http/https with a hostname)
_URL_RE = re.compile(r"https?://([A-Za-z0-9][\w.-]+\.[A-Za-z]{2,})")


def extract_hostnames_from_command(command_line: str) -> set[str]:
    """Extract domain hostnames from a process command line.

    Finds URLs embedded in common patterns: Invoke-WebRequest -Uri,
    curl, wget, DownloadString, DownloadFile, and bare https:// URLs.
    Ignores raw IP addresses (no domain to resolve).

    Returns:
        Set of lowercase domain hostnames found.
    """
    hostnames: set[str] = set()
    for match in _URL_RE.finditer(command_line):
        host = match.group(1).lower()
        # Skip raw IPs — they don't need DNS resolution
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            continue
        hostnames.add(host)
    return hostnames
