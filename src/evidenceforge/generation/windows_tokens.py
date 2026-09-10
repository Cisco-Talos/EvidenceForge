# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Windows process-token projection helpers."""

_SYSTEM_ACCOUNTS = frozenset({"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"})


def windows_process_token_profile(
    username: str,
    integrity_level: str,
) -> tuple[str, str, str]:
    """Return canonical integrity, elevation type, and mandatory-label SID.

    User-owned High-integrity processes represent a completed UAC elevation and
    therefore carry a Full token. Built-in service identities retain their
    unsplit default System token.
    """

    normalized = username.upper().split("\\")[-1]
    if normalized in _SYSTEM_ACCOUNTS:
        return "System", "%%1936", "S-1-16-16384"
    if integrity_level == "High":
        return "High", "%%1937", "S-1-16-12288"
    if integrity_level == "Low":
        return "Low", "%%1938", "S-1-16-4096"
    return "Medium", "%%1938", "S-1-16-8192"
