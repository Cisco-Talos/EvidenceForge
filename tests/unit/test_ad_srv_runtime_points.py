# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Focused AD SRV discovery ownership and bounded-retention tests."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.network_runtime import NetworkRuntimePointFamily
from evidenceforge.generation.process_runtime_cache import _DEFINITE_GROWING_FIELDS
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 3, 15, 10, 0, tzinfo=UTC)
_SOURCE_IP = "10.0.1.50"
_DNS_SERVER_IP = "10.0.0.10"
_DOMAIN = "corp.example"


def _activity_generator() -> ActivityGenerator:
    state_manager = StateManager()
    state_manager.set_current_time(_START)
    emitters = {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "zeek_ssl": Mock(),
        "zeek_x509": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "proxy_access": Mock(),
    }
    generator = ActivityGenerator(
        state_manager,
        emitters,
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(days=31),
    )
    generator._dc_systems = [
        System(
            hostname="DC-01",
            ip=_DNS_SERVER_IP,
            os="Windows Server 2022",
            type="domain_controller",
        )
    ]
    generator._allocate_ephemeral_port = Mock(return_value=53_000)
    return generator


def _emit_discovery(
    generator: ActivityGenerator,
    *,
    at: datetime,
    rng: random.Random,
) -> None:
    generator._emit_ad_srv_discovery(
        src_ip=_SOURCE_IP,
        dns_server_ip=_DNS_SERVER_IP,
        time=at,
        src_os="windows",
        domain=_DOMAIN,
        rng=rng,
        query_process=None,
    )


def _query_from_call(call: object) -> str:
    dns = call.kwargs["dns"]  # type: ignore[attr-defined]
    return str(dns.query)


def test_ad_srv_success_commits_per_query_markers_and_duplicate_is_rng_neutral() -> None:
    generator = _activity_generator()
    connection = Mock(return_value="CAdSrvSuccessful1")
    generator.generate_connection = connection
    rng = random.Random(117)

    _emit_discovery(generator, at=_START, rng=rng)

    assert connection.call_count == 2
    queries = tuple(_query_from_call(call) for call in connection.call_args_list)
    assert len(set(queries)) == 2
    assert NetworkRuntimePointFamily.AD_SRV_DISCOVERY.value == "ad_srv_discovery"
    runtime = generator._network_transaction_runtime
    for query in queries:
        key, marker, expiry = generator._ad_srv_discovery_runtime_identity(
            src_ip=f"::ffff:{_SOURCE_IP}",
            domain=f"{_DOMAIN.upper()}.",
            time=_START,
            query=f"{query.upper()}.",
        )
        assert key[0] == _SOURCE_IP
        assert key[1] == _DOMAIN
        assert key[3] == query.lower()
        assert expiry == marker + timedelta(hours=1)
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
                key,
                at=_START,
            )
            == marker
        )
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
                key,
                None,
                at=expiry,
            )
            is None
        )

    after_first = runtime.census()
    rng_state = rng.getstate()
    _emit_discovery(generator, at=_START + timedelta(minutes=5), rng=rng)

    assert connection.call_count == 2
    assert rng.getstate() == rng_state
    assert runtime.census() == after_first
    assert not hasattr(generator, "_ad_srv_discovery_cache")
    assert "_ad_srv_discovery_cache" not in _DEFINITE_GROWING_FIELDS


def test_ad_srv_partial_network_rejection_retains_only_successful_query_and_retries_gap() -> None:
    generator = _activity_generator()
    rejection = StateError("injected second SRV network rejection")
    first_attempt = Mock(side_effect=["CAdSrvFirstQuery1", rejection])
    generator.generate_connection = first_attempt
    rng = random.Random(391)

    with pytest.raises(StateError, match="second SRV network rejection"):
        _emit_discovery(generator, at=_START, rng=rng)

    assert first_attempt.call_count == 2
    first_query, rejected_query = (_query_from_call(call) for call in first_attempt.call_args_list)
    runtime = generator._network_transaction_runtime
    first_key, first_marker, _ = generator._ad_srv_discovery_runtime_identity(
        src_ip=_SOURCE_IP,
        domain=_DOMAIN,
        time=_START,
        query=first_query,
    )
    rejected_key, _, _ = generator._ad_srv_discovery_runtime_identity(
        src_ip=_SOURCE_IP,
        domain=_DOMAIN,
        time=_START,
        query=rejected_query,
    )
    assert runtime.get_point(NetworkRuntimePointFamily.AD_SRV_DISCOVERY, first_key) == first_marker
    assert runtime.get_point(NetworkRuntimePointFamily.AD_SRV_DISCOVERY, rejected_key) is None
    failed_census = runtime.census()
    assert failed_census.live_points == 1
    assert failed_census.open_preparations == 0
    assert failed_census.prepared_transactions == 0
    assert failed_census.claimed_transactions == 0
    assert failed_census.reserved_points == 0
    assert failed_census.preparation_fences == 0
    assert failed_census.reserved_deadlines == 0

    retry = Mock(return_value="CAdSrvRetryQuery1")
    generator.generate_connection = retry
    _emit_discovery(generator, at=_START + timedelta(minutes=4), rng=rng)

    assert retry.call_count == 1
    assert _query_from_call(retry.call_args_list[0]) == rejected_query
    assert runtime.get_point(NetworkRuntimePointFamily.AD_SRV_DISCOVERY, first_key) == first_marker
    assert runtime.get_point(NetworkRuntimePointFamily.AD_SRV_DISCOVERY, rejected_key) is not None
    assert runtime.census().live_points == 2


def test_ad_srv_malformed_marker_fails_closed_without_network_or_reservation_residue() -> None:
    generator = _activity_generator()
    probe = Mock(return_value="CAdSrvProbeQuery1")
    generator.generate_connection = probe
    _emit_discovery(generator, at=_START, rng=random.Random(73))
    first_query = _query_from_call(probe.call_args_list[0])

    next_hour = _START + timedelta(hours=1)
    key, _, expiry = generator._ad_srv_discovery_runtime_identity(
        src_ip=_SOURCE_IP,
        domain=_DOMAIN,
        time=next_hour,
        query=first_query,
    )
    runtime = generator._network_transaction_runtime
    runtime.set_point(
        NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
        key,
        "legacy-set-marker",
        expires_at=expiry,
    )
    rejected = Mock(return_value="CAdSrvMustNotPublish1")
    generator.generate_connection = rejected

    with pytest.raises(StateError, match="malformed bucket marker"):
        _emit_discovery(generator, at=next_hour, rng=random.Random(73))

    assert rejected.call_count == 0
    assert runtime.get_point(NetworkRuntimePointFamily.AD_SRV_DISCOVERY, key) == (
        "legacy-set-marker"
    )
    census = runtime.census()
    assert census.open_preparations == 0
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert census.preparation_fences == 0
    assert census.reserved_deadlines == 0


def test_ad_srv_hourly_point_backing_plateaus_from_seven_to_thirty_days() -> None:
    generator = _activity_generator()
    generator.generate_connection = Mock(return_value="CAdSrvDurationProbe1")
    runtime = generator._network_transaction_runtime
    seven_day_shape: tuple[int, int, int, int] | None = None

    for hour in range(30 * 24):
        current = _START + timedelta(hours=hour)
        page = runtime.advance_watermark_page(current)
        assert not page.has_more
        _emit_discovery(generator, at=current, rng=random.Random(hour))
        if hour == 7 * 24 - 1:
            census = runtime.census()
            seven_day_shape = (
                census.live_points,
                census.tombstone_points,
                census.active_deadlines,
                census.expiry_backing,
            )

    census = runtime.census()
    thirty_day_shape = (
        census.live_points,
        census.tombstone_points,
        census.active_deadlines,
        census.expiry_backing,
    )
    assert seven_day_shape == thirty_day_shape
    assert thirty_day_shape == (2, 48, 50, 50)
    assert census.open_preparations == 0
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert census.preparation_fences == 0
    assert census.reserved_deadlines == 0
