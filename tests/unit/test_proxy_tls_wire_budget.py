# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Inspected-client TLS accounting separates plaintext from physical payload."""

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import TlsWireBudgetConfig
from evidenceforge.generation.activity.tls_realism import (
    inspected_tls_handshake_budget,
    tls13_application_payload_budget,
)


@pytest.mark.parametrize("size,records", [(0, 0), (1, 1), (16384, 1), (16385, 2), (32768, 2)])
def test_tls_application_fragment_and_aead_budget(size: int, records: int) -> None:
    assert tls13_application_payload_budget(size) == size + records * 22


def test_aggregate_reservation_covers_individual_fragmentation() -> None:
    sizes = [16385, 17, 20000, 153]
    reserved = tls13_application_payload_budget(sum(sizes), message_count=len(sizes))
    admitted = sum(tls13_application_payload_budget(size) for size in sizes)
    assert reserved >= admitted > sum(sizes)
    assert reserved - admitted <= (len(sizes) - 1) * 22


def test_handshake_budget_is_scoped_to_physical_transport() -> None:
    values = [inspected_tls_handshake_budget(f"physical-{index}") for index in range(30)]
    assert len(set(values)) > 25
    assert values == [inspected_tls_handshake_budget(f"physical-{index}") for index in range(30)]
    assert all(400 <= client <= 1800 and 1800 <= server <= 6500 for client, server in values)


@pytest.mark.parametrize("size,count", [(-1, 1), (1, 0), (1, -1), (True, 1), (1, False)])
def test_reject_invalid_application_reservations(size: int, count: int) -> None:
    with pytest.raises(ValueError):
        tls13_application_payload_budget(size, message_count=count)


def test_reject_inverted_client_handshake_profile() -> None:
    with pytest.raises(ValidationError, match="inspected_client_handshake_bytes_min"):
        TlsWireBudgetConfig(
            inspected_client_handshake_bytes_min=2000,
            inspected_client_handshake_bytes_max=1000,
        )
