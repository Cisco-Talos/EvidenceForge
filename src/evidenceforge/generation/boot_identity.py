# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared deterministic identity for one modeled host boot."""

from datetime import datetime

from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc


def modeled_boot_id(hostname: str, boot_time: datetime) -> str:
    """Preserve the existing boot namespace across service and native log consumers."""
    return stable_uuid(
        "lifecycle-service-boot",
        hostname.strip().casefold(),
        ensure_utc(boot_time).isoformat(),
    )
