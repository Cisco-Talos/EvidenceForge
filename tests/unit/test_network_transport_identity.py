# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for finalized network transport occurrence identity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from evidenceforge.generation.actions.network_identity import (
    _network_transport_occurrence_stable_id,
)


def _transport_id(**overrides: object) -> str:
    values: dict[str, object] = {
        "intent_stable_id": "network-connection-intent",
        "src_ip": "10.0.0.10",
        "src_port": 50_001,
        "dst_ip": "203.0.113.20",
        "dst_port": 443,
        "protocol": "tcp",
        "opened_at": datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return _network_transport_occurrence_stable_id(
        cast(str, values["intent_stable_id"]),
        src_ip=cast(str, values["src_ip"]),
        src_port=cast(int, values["src_port"]),
        dst_ip=cast(str, values["dst_ip"]),
        dst_port=cast(int, values["dst_port"]),
        protocol=cast(str, values["protocol"]),
        opened_at=cast(datetime, values["opened_at"]),
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("intent_stable_id", "network-connection-other-intent"),
        ("src_ip", "10.0.0.11"),
        ("src_port", 50_002),
        ("dst_ip", "203.0.113.21"),
        ("dst_port", 80),
        ("protocol", "udp"),
        ("opened_at", datetime(2026, 8, 16, 12, 0, tzinfo=UTC) + timedelta(seconds=1)),
    ),
)
def test_transport_occurrence_identity_covers_intent_and_full_five_tuple(
    field: str,
    replacement: object,
) -> None:
    """Every intent or final tuple component participates in identity."""

    assert _transport_id(**{field: replacement}) != _transport_id()


def test_transport_occurrence_identity_is_deterministic() -> None:
    """The same resolved occurrence receives the same full-width identifier."""

    assert _transport_id() == _transport_id()
    assert _transport_id().startswith("network-connection-")


def test_transport_occurrence_identity_normalizes_ipv4_mapped_addresses() -> None:
    """Equivalent IPv4 spellings receive one canonical occurrence identity."""

    assert _transport_id(src_ip="::ffff:10.0.0.10") == _transport_id()
