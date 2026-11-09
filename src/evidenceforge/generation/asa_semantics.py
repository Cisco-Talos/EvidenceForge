# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""ASA security-side meanings shared by observation and native projection."""

from collections.abc import Mapping
from typing import Literal


def asa_security_level(interface: str, configured: Mapping[str, int]) -> int | None:
    """Resolve a declared level or the conventional interface-name convention."""
    conventional = {"outside": 0, "dmz": 50, "inside": 100}
    return configured.get(interface, conventional.get(interface.casefold()))


def asa_connection_direction(
    source: str, destination: str, configured: Mapping[str, int]
) -> Literal["inbound", "outbound"]:
    """Project initiation across security levels, retaining legacy equal-side direction."""
    source_level = asa_security_level(source, configured)
    destination_level = asa_security_level(destination, configured)
    if (
        source_level is not None
        and destination_level is not None
        and source_level != destination_level
    ):
        return "inbound" if source_level < destination_level else "outbound"
    return "inbound" if source.casefold() == "outside" else "outbound"


def asa_tcp_close_reason(
    state: str,
    history: str,
    source: str,
    destination: str,
    configured: Mapping[str, int],
) -> str:
    """Map a canonical reset sender to ASA inside/outside, never orig/resp."""
    originator_reset = state in {"RSTO", "RSTOS0"}
    responder_reset = state in {"RSTR", "RSTRH", "REJ"}
    if state == "OTH":
        originator_reset = "R" in history and "r" not in history
        responder_reset = "r" in history and "R" not in history
    if not originator_reset and not responder_reset:
        return "Unknown" if state == "OTH" else "TCP FINs"
    source_level = asa_security_level(source, configured)
    destination_level = asa_security_level(destination, configured)
    if source_level is None or destination_level is None or source_level == destination_level:
        return "Unknown"
    sender_is_inside = (source_level > destination_level) == originator_reset
    return "TCP Reset-I" if sender_is_inside else "TCP Reset-O"
