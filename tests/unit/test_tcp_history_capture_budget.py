# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Observed TCP history constrains retained packet selection and admission."""

import random
from dataclasses import replace

import pytest

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    tcp_history_packet_minima,
    validate_tcp_history_packets,
)
from evidenceforge.generation.activity.timing_profiles import network_sensor_observation_timing
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    PersistentSmbTrafficRebindAuthority,
)
from tests.unit.test_network_observation import (
    _persistent_smb_observation,
    _persistent_smb_transport,
)


@pytest.mark.parametrize(
    ("history", "expected"),
    [
        ("ShADadFf", (4, 4)),
        ("ShADadrG", (3, 4)),
        ("S", (1, 0)),
        ("Sr", (1, 1)),
        ("D^dGgTtCcwW", (1, 1)),
        ("SHADFRIQshadfriq", (8, 8)),
        ("", (0, 0)),
    ],
)
def test_history_bound_counts_only_exclusive_packet_categories(
    history: str, expected: tuple[int, int]
) -> None:
    assert tcp_history_packet_minima(history) == expected
    validate_tcp_history_packets(history, *expected)


def test_control_complete_small_flow_cannot_lose_a_required_packet() -> None:
    timing = replace(
        network_sensor_observation_timing("default"),
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=100,
    )
    ledger = DirectionalTrafficLedger(463, 4, 679)
    observed, missed = NetworkObservationPlanner._lose_direction(
        ledger, timing, random.Random(2), minimum_packets=4
    )
    assert observed is ledger and missed == 0


def test_larger_flow_retains_history_and_physical_loss_partition() -> None:
    timing = replace(
        network_sensor_observation_timing("default"),
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.2,
        capture_loss_max_fraction=0.6,
        capture_loss_max_missed_bytes=1000,
    )
    direction = DirectionalTrafficLedger(1200, 12, 1728)
    canonical = NetworkTrafficLedger(direction, direction)
    gaps = 0
    for seed in range(40):
        observed = NetworkObservationPlanner._observed_traffic(
            canonical, timing, "sensor", f"transaction-{seed}", "tcp", "ShADadFf"
        )
        validate_tcp_history_packets("ShADadFf", observed.orig.packets, observed.resp.packets)
        for old, new, missed in [
            (direction, observed.orig, observed.missed_orig_bytes),
            (direction, observed.resp, observed.missed_resp_bytes),
        ]:
            assert new.payload_bytes + missed == old.payload_bytes
            if not missed:
                continue
            gaps += 1
            lost = old.packets - new.packets
            assert missed + 40 * lost <= old.ip_bytes - new.ip_bytes <= 1500 * lost
            assert new.payload_bytes + 40 * new.packets <= new.ip_bytes <= 1500 * new.packets
    assert gaps > 20


def test_impossible_typed_capture_is_rejected_directly_and_on_restore() -> None:
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor")
    impossible = replace(
        transport.traffic, orig=DirectionalTrafficLedger(900, 2, 980), missed_orig_bytes=100
    )
    with pytest.raises(ValueError, match="history requires at least"):
        replace(observation, traffic=impossible)
    # A forged graph bypassing the public constructor cannot cross codec or
    # retained scalar admission either.
    object.__setattr__(observation, "traffic", impossible)
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encode_state_value(observation))
    with pytest.raises(ValueError, match="history requires at least"):
        PersistentSmbTrafficRebindAuthority().issue_binding(transport, (observation,))
