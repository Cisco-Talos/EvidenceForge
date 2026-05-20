# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Linux network-interface naming helpers for source-native log rendering."""

from __future__ import annotations

from typing import Protocol

from evidenceforge.utils.rng import _stable_seed


class LinuxInterfaceSystem(Protocol):
    """Subset of scenario system fields needed for interface naming."""

    hostname: str
    ip: str
    os: str
    type: str | None


def linux_primary_interface(system: LinuxInterfaceSystem) -> str:
    """Return a deterministic primary Linux interface name for one host."""
    os_lower = (system.os or "").lower()
    system_type = (system.type or "").lower()
    host_key = f"{system.hostname.lower()}:{system.ip}:{os_lower}:{system_type}"

    if any(token in os_lower for token in ("rhel", "red hat", "rocky", "alma", "centos")):
        candidates = ("ens192", "ens160", "eno1")
    elif "debian" in os_lower or "ubuntu" in os_lower:
        candidates = ("ens160", "ens192", "enp0s3")
    else:
        candidates = ("eth0", "ens160", "enp0s3")

    return candidates[_stable_seed(f"linux_primary_interface:{host_key}") % len(candidates)]
