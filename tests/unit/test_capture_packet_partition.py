# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import random
from dataclasses import replace

import pytest

from evidenceforge.events.network import DirectionalTrafficLedger
from evidenceforge.generation.activity.timing_profiles import network_sensor_observation_timing
from evidenceforge.generation.network_observation import NetworkObservationPlanner


@pytest.mark.parametrize(
    "ledger",
    [
        DirectionalTrafficLedger(463, 4, 679),
        DirectionalTrafficLedger(460, 4, 676),
        DirectionalTrafficLedger(146000, 100, 150000),
        DirectionalTrafficLedger(50000, 58, 54008),
        DirectionalTrafficLedger(200, 8, 932),
    ],
)
def test_tcp_loss_partitions_retained_and_missing_packet_budgets(
    ledger: DirectionalTrafficLedger,
) -> None:
    timing = replace(
        network_sensor_observation_timing("default"),
        capture_loss_min_fraction=0.01,
        capture_loss_max_fraction=0.2,
        capture_loss_max_missed_bytes=100000,
    )
    for seed in range(60):
        observed, missed = NetworkObservationPlanner._lose_direction(
            ledger, timing, random.Random(seed)
        )
        assert observed.payload_bytes + missed == ledger.payload_bytes
        if not missed:
            assert observed == ledger
            continue
        lost_packets = ledger.packets - observed.packets
        lost_ip = ledger.ip_bytes - observed.ip_bytes
        assert 0 < lost_packets < ledger.packets
        assert missed + 40 * lost_packets <= lost_ip <= 1500 * lost_packets
        assert observed.payload_bytes + 40 * observed.packets <= observed.ip_bytes
        assert observed.ip_bytes <= 1500 * observed.packets
        assert (
            observed
            == NetworkObservationPlanner._lose_direction(ledger, timing, random.Random(seed))[0]
        )


def test_tiny_partial_capture_retains_data_and_tcp_control_budget() -> None:
    timing = replace(
        network_sensor_observation_timing("default"),
        capture_loss_min_fraction=0.006,
        capture_loss_max_fraction=0.006,
        capture_loss_max_missed_bytes=100,
    )
    canonical = DirectionalTrafficLedger(463, 4, 679)
    observed, missed = NetworkObservationPlanner._lose_direction(
        canonical, timing, random.Random(2)
    )
    assert missed == 3
    assert canonical.packets - observed.packets == 1
    assert canonical.ip_bytes - observed.ip_bytes >= 43
