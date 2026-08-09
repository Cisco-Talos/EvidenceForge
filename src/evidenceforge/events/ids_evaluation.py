# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical normalization for IDS evaluation fingerprints."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from evidenceforge.config.snort_classifications import snort_classification_description


def normalize_ids_alert(sensor: str, fields: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, source-native IDS fields covered by integrity evaluation."""

    timestamp = fields.get("timestamp") or fields.get("ts")
    if not isinstance(timestamp, datetime):
        timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    timestamp = (
        timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
    )

    return {
        "sensor": sensor,
        "timestamp": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "gid": int(fields.get("gid", 1)),
        "sid": int(fields["sid"]),
        "rev": int(fields.get("rev", 1)),
        "message": str(fields.get("message") or "").strip(),
        "classification": snort_classification_description(
            str(fields.get("classification") or "").strip()
        ),
        "priority": int(fields.get("priority", 0)),
        "protocol": str(fields.get("protocol") or fields.get("proto") or "").upper(),
        "src_ip": _normalize_ip(fields.get("src_ip") or fields.get("id.orig_h")),
        "src_port": _normalize_port(fields.get("src_port") or fields.get("id.orig_p")),
        "dst_ip": _normalize_ip(fields.get("dst_ip") or fields.get("id.resp_h")),
        "dst_port": _normalize_port(fields.get("dst_port") or fields.get("id.resp_p")),
    }


def update_ids_digest(hasher: Any, sensor: str, fields: dict[str, Any]) -> None:
    """Append one normalized alert to an ordered SHA-256 digest."""

    payload = json.dumps(
        normalize_ids_alert(sensor, fields),
        sort_keys=True,
        separators=(",", ":"),
    )
    hasher.update(payload.encode("utf-8"))
    hasher.update(b"\n")


def new_ids_digest() -> Any:
    """Return a fresh SHA-256 hash object without exposing hashlib to callers."""

    return hashlib.sha256()


def _normalize_ip(value: Any) -> str:
    text = str(value or "")
    try:
        return ipaddress.ip_address(text.strip("[]")).compressed
    except ValueError:
        return text


def _normalize_port(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    return int(value)
