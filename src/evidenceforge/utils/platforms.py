# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Classification of modeled operating systems, independent of the execution host."""

import re


def platform_for_os(os_name: str) -> str:
    """Resolve a scenario OS label without inspecting the running computer."""
    normalized = os_name.strip().casefold()
    if "windows" in normalized:
        return "windows"
    if any(
        marker in normalized
        for marker in ("linux", "ubuntu", "centos", "debian", "rhel", "red hat")
    ):
        return "linux"
    # Keep legacy OS X recognizable without matching the interior of Cisco IOS XE/XR.
    if any(marker in normalized for marker in ("macos", "mac os", "darwin")) or re.search(
        r"\bos x\b", normalized
    ):
        return "macos"
    return "unknown"
