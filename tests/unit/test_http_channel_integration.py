# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production integration contracts for persistent direct-HTTP channels."""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import HttpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import (
    ObservationDecision,
    ObservationPolicy,
)
from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.http_channels import HttpChannelAffinity
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import _thread_local

_START = datetime(2026, 8, 1, 12, tzinfo=UTC)
_END = _START + timedelta(days=31)
_AUTHENTICATED_REUSE_LOOKUP_CANDIDATE_CEILING = 12


class _CollectorEmitter:
    """Minimal source renderer that retains admitted canonical events."""

    def __init__(self, predicate: Callable[[CanonicalOccurrence], bool]) -> None:
        self._predicate = predicate
        self.events: list[CanonicalOccurrence] = []

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Return whether this source projects the event."""

        return self._predicate(event)

    def emit(self, event: CanonicalOccurrence) -> None:
        """Retain one frozen source projection."""

        self.events.append(event)


class _DropApplicationChildrenPolicy(ObservationPolicy):
    """Drop later direct-HTTP observations without mutating canonical state."""

    def decide(self, format_name: str, event: CanonicalOccurrence) -> ObservationDecision:
        """Drop every application-only projection and preserve physical parents."""

        del format_name
        if event.network is not None and event.network.application_layer_only:
            return ObservationDecision(status="dropped")
        return ObservationDecision(status="visible")


def _generator(
    *,
    start: datetime = _START,
    end: datetime = _END,
    observation_policy: ObservationPolicy | None = None,
    formats: tuple[str, ...] = ("zeek_conn", "zeek_http", "ecar"),
) -> tuple[
    ActivityGenerator,
    StateManager,
    dict[str, _CollectorEmitter],
]:
    state_manager = StateManager()
    emitters: dict[str, _CollectorEmitter] = {}
    if "zeek_conn" in formats:
        emitters["zeek_conn"] = _CollectorEmitter(
            lambda event: (
                event.event_type == "connection"
                and event.network is not None
                and not event.network.application_layer_only
            )
        )
    if "zeek_http" in formats:
        emitters["zeek_http"] = _CollectorEmitter(
            lambda event: event.event_type == "connection" and event.protocol.http is not None
        )
    if "zeek_ssl" in formats:
        emitters["zeek_ssl"] = _CollectorEmitter(
            lambda event: event.event_type == "connection" and event.protocol.ssl is not None
        )
    if "ecar" in formats:
        emitters["ecar"] = _CollectorEmitter(
            lambda event: (
                event.event_type == "connection"
                and event.network is not None
                and not event.network.application_layer_only
            )
        )
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters=emitters,
        output_start_time=start,
        output_end_time=end,
        observation_policy=observation_policy,
    )
    generator = ActivityGenerator(
        state_manager,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=start,
        generation_window_end=end,
    )
    state_manager.set_current_time(start)
    return generator, state_manager, emitters


def _emit_http(
    generator: ActivityGenerator,
    *,
    timestamp: datetime,
    trans_depth: int,
    uri: str,
    src_ip: str = "10.0.0.10",
    dst_ip: str = "10.0.0.20",
    dst_port: int = 80,
    host: str = "Portal.Example.Test.",
    user_agent: str = "Mozilla/5.0",
    request_body_len: int = 10,
    response_body_len: int = 1_000,
    duration: float | None = None,
) -> str:
    first = trans_depth == 1
    return generator.generate_connection(
        src_ip=src_ip,
        dst_ip=dst_ip,
        time=timestamp,
        dst_port=dst_port,
        proto="tcp",
        service="http",
        duration=4.0 if first and duration is None else duration or 0.2,
        orig_bytes=1_000 if first else 300,
        resp_bytes=3_500 if first else 1_100,
        conn_state="SF",
        hostname=host,
        http=HttpContext(
            method="POST" if request_body_len else "GET",
            host=host,
            uri=uri,
            user_agent=user_agent,
            request_body_len=request_body_len,
            response_body_len=response_body_len,
            flow_request_body_len=100 if first else None,
            flow_response_body_len=3_000 if first else None,
            flow_transaction_count=3 if first else 1,
            trans_depth=trans_depth,
            status_code=200,
            status_msg="OK",
        ),
        emit_dns=False,
        suppress_prereq_dns=True,
    )


def test_activity_generator_injects_one_registry_into_protocol_managers() -> None:
    """Direct compatibility construction still has one canonical application authority."""

    generator, _state, _emitters = _generator()

    shared = generator._application_channel_registry
    assert generator._http_channel_manager.application_registry is shared
    assert generator._proxy_channel_manager.application_registry is shared
    assert shared.window_start == _START
    assert shared.window_end == _END


def test_identical_auto_port_http_intents_receive_distinct_transport_identities() -> None:
    """Resolved source ports distinguish repeated physical HTTP occurrences."""

    generator, _state, emitters = _generator()

    first_uid = _emit_http(
        generator,
        timestamp=_START,
        trans_depth=1,
        uri="/repeat",
    )
    second_uid = _emit_http(
        generator,
        timestamp=_START,
        trans_depth=1,
        uri="/repeat",
    )

    physical_events = [
        event
        for event in emitters["zeek_http"].events
        if event.network is not None and not event.network.application_layer_only
    ]
    assert len(physical_events) == 2
    assert first_uid != second_uid
    assert physical_events[0].network.src_port != physical_events[1].network.src_port
    assert physical_events[0].network.stable_id != physical_events[1].network.stable_id
    channel_ids = {
        generator._http_channel_manager._channel_id(
            HttpChannelAffinity.from_request(
                src_ip=event.network.src_ip,
                dst_ip=event.network.dst_ip,
                dst_port=event.network.dst_port,
                http_host=event.protocol.http.host,
                user_agent=event.protocol.http.user_agent,
                transport_security="cleartext",
            ),
            event.network.stable_id,
        )
        for event in physical_events
    }
    assert len(channel_ids) == 2


def _manager_snapshot(
    generator: ActivityGenerator,
    parent: CanonicalOccurrence,
):
    affinity = HttpChannelAffinity.from_request(
        src_ip=parent.network.src_ip,
        dst_ip=parent.network.dst_ip,
        dst_port=parent.network.dst_port,
        http_host=parent.protocol.http.host,
        user_agent=parent.protocol.http.user_agent,
        transport_security="tls" if parent.network.service == "ssl" else "cleartext",
    )
    channel_id = generator._http_channel_manager._channel_id(
        affinity,
        parent.network.stable_id,
    )
    return generator._http_channel_manager.channel_snapshot(channel_id)


def test_direct_http_reuse_owns_one_parent_and_bounded_application_children() -> None:
    """One exact parent owns N ordered children without duplicate transport projections."""

    generator, state_manager, emitters = _generator()
    first_uid = _emit_http(
        generator,
        timestamp=_START,
        trans_depth=1,
        uri="/",
    )
    second_uid = _emit_http(
        generator,
        timestamp=_START + timedelta(milliseconds=700),
        trans_depth=2,
        uri="/asset-a.js",
        host="portal.example.test",
        user_agent="mozilla/5.0",
    )
    third_uid = _emit_http(
        generator,
        timestamp=_START + timedelta(milliseconds=500),
        trans_depth=3,
        uri="/asset-b.js",
        host="portal.example.test",
        user_agent="mozilla/5.0",
    )

    http_events = emitters["zeek_http"].events
    assert first_uid == second_uid == third_uid
    assert len(emitters["zeek_conn"].events) == 1
    assert len(emitters["ecar"].events) == 1
    assert len(http_events) == 3
    assert {event.network.zeek_uid for event in http_events} == {first_uid}
    assert len({event.network.conn_id for event in http_events}) == 1
    assert len({event.network.src_port for event in http_events}) == 1
    assert [event.network.application_layer_only for event in http_events] == [False, True, True]
    assert [event.protocol.http.trans_depth for event in http_events] == [1, 2, 3]
    request_times = [event.protocol.http.canonical_request_time for event in http_events]
    assert request_times == sorted(request_times)
    assert request_times[2] > request_times[1]

    parent = http_events[0]
    connection = state_manager.get_connection(parent.network.conn_id)
    assert connection is not None
    assert connection.bytes_sent == sum(event.network.orig_bytes for event in http_events)
    assert connection.bytes_received == sum(event.network.resp_bytes for event in http_events)

    snapshot = _manager_snapshot(generator, parent)
    assert snapshot is not None
    assert snapshot.reserved_operations == 3
    assert snapshot.completed_operations == 3
    assert snapshot.active_operations == 0
    assert snapshot.reserved_initiator_bytes == sum(
        event.protocol.http.request_body_len for event in http_events
    )
    assert snapshot.reserved_responder_bytes == sum(
        event.protocol.http.response_body_len for event in http_events
    )
    assert snapshot.reserved_initiator_bytes <= snapshot.identity.budget.initiator_bytes
    assert snapshot.reserved_responder_bytes <= snapshot.identity.budget.responder_bytes
    census = generator._http_channel_manager.census()
    assert census.open_transport_views == 1
    # Composite authentication rechecks the same exact hash-routed owner while
    # holding each authority fence. The work remains bounded independently of
    # retained owner state; the dedicated scale-shape test below proves that.
    assert (
        census.application.lookup_candidates_inspected
        <= _AUTHENTICATED_REUSE_LOOKUP_CANDIDATE_CEILING
    )
    assert census.application.maximum_affinity_bucket == 1


def _authenticated_reuse_lookup_delta(unrelated_affinities: int) -> int:
    """Return lookup work for one parent and two children after owner-state seeding."""

    generator, _state_manager, _emitters = _generator(formats=("zeek_http",))
    for index in range(unrelated_affinities):
        _emit_http(
            generator,
            timestamp=_START + timedelta(milliseconds=index * 10),
            trans_depth=1,
            uri=f"/seed/{index}",
            host=f"seed-{index}.example.test",
        )
    before = generator._http_channel_manager.census().application.lookup_candidates_inspected
    parent_uid = _emit_http(
        generator,
        timestamp=_START + timedelta(seconds=10),
        trans_depth=1,
        uri="/target/parent",
        host="target.example.test",
    )
    _emit_http(
        generator,
        timestamp=_START + timedelta(seconds=11),
        trans_depth=2,
        uri="/target/child-1",
        host="target.example.test",
    )
    _emit_http(
        generator,
        timestamp=_START + timedelta(seconds=12),
        trans_depth=3,
        uri="/target/child-2",
        host="target.example.test",
    )
    parent = next(
        event for event in _emitters["zeek_http"].events if event.network.zeek_uid == parent_uid
    )
    assert _manager_snapshot(generator, parent) is not None
    after = generator._http_channel_manager.census().application.lookup_candidates_inspected
    return after - before


def test_authenticated_http_reuse_lookup_work_is_owner_state_invariant() -> None:
    """Composite receipt validation stays constant with many retained affinities."""

    small = _authenticated_reuse_lookup_delta(0)
    large = _authenticated_reuse_lookup_delta(32)

    assert small == large
    assert small <= _AUTHENTICATED_REUSE_LOOKUP_CANDIDATE_CEILING


@pytest.mark.parametrize(
    "changed",
    [
        {"src_ip": "10.0.0.11"},
        {"dst_ip": "10.0.0.21"},
        {"dst_port": 8080},
        {"host": "other.example.test"},
        {"user_agent": "curl/8.0"},
    ],
)
def test_direct_http_affinity_miss_opens_a_new_parent(changed: dict[str, object]) -> None:
    """Every legacy affinity dimension is exact on the production planner path."""

    generator, _state_manager, emitters = _generator()
    first_uid = _emit_http(generator, timestamp=_START, trans_depth=1, uri="/")
    second_uid = _emit_http(
        generator,
        timestamp=_START + timedelta(milliseconds=700),
        trans_depth=2,
        uri="/asset.js",
        **changed,
    )

    assert second_uid != first_uid
    assert len(emitters["zeek_conn"].events) == 2
    assert len(emitters["ecar"].events) == 2
    assert [event.protocol.http.trans_depth for event in emitters["zeek_http"].events] == [1, 1]
    assert all(not event.network.application_layer_only for event in emitters["zeek_http"].events)


def test_observation_loss_does_not_orphan_canonical_http_channel_state() -> None:
    """Dropped child evidence still commits operation budgets and parent state exactly once."""

    generator, state_manager, emitters = _generator(
        observation_policy=_DropApplicationChildrenPolicy("complete")
    )
    first_uid = _emit_http(generator, timestamp=_START, trans_depth=1, uri="/")
    second_uid = _emit_http(
        generator,
        timestamp=_START + timedelta(milliseconds=700),
        trans_depth=2,
        uri="/hidden.js",
    )

    assert second_uid == first_uid
    assert len(emitters["zeek_conn"].events) == 1
    assert len(emitters["ecar"].events) == 1
    assert len(emitters["zeek_http"].events) == 1
    parent = emitters["zeek_http"].events[0]
    snapshot = _manager_snapshot(generator, parent)
    assert snapshot is not None
    assert snapshot.reserved_operations == 2
    connection = state_manager.get_connection(parent.network.conn_id)
    assert connection is not None
    assert connection.bytes_sent > parent.network.orig_bytes
    assert connection.bytes_received > parent.network.resp_bytes


def test_direct_https_reuses_one_immutable_tls_parent_for_bounded_http_children() -> None:
    """HTTPS page assets share one TLS parent without duplicate transport evidence."""

    generator, state_manager, emitters = _generator(
        formats=("zeek_conn", "zeek_http", "zeek_ssl", "ecar")
    )
    common = {
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "dst_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 4.0,
        "orig_bytes": 500,
        "resp_bytes": 4_000,
        "conn_state": "SF",
        "hostname": "portal.example.test",
        "emit_dns": False,
        "suppress_prereq_dns": True,
    }
    parent_capture = NetworkConnectionIdentityCapture()
    first_uid = generator.generate_connection(
        time=_START,
        identity_capture=parent_capture,
        http=HttpContext(
            method="GET",
            host="portal.example.test",
            uri="/",
            user_agent="Mozilla/5.0",
            response_body_len=1_000,
            trans_depth=1,
        ),
        **common,
    )
    parent = emitters["zeek_http"].events[0]
    parent_connection = state_manager.get_connection(parent.network.conn_id)
    assert parent_connection is not None
    parent_interval = (parent_connection.start_time, parent_connection.close_time)
    child_capture = NetworkConnectionIdentityCapture()
    second_uid = generator.generate_connection(
        time=_START + timedelta(milliseconds=700),
        identity_capture=child_capture,
        http=HttpContext(
            method="GET",
            host="portal.example.test",
            uri="/asset.js",
            user_agent="Mozilla/5.0",
            response_body_len=1_000,
            trans_depth=2,
        ),
        **{**common, "duration": 0.2},
    )

    http_events = emitters["zeek_http"].events
    assert second_uid == first_uid
    assert len(emitters["zeek_conn"].events) == 1
    assert len(emitters["zeek_ssl"].events) == 1
    assert len(emitters["ecar"].events) == 1
    assert len(http_events) == 2
    assert {event.network.zeek_uid for event in http_events} == {first_uid}
    assert len({event.network.conn_id for event in http_events}) == 1
    assert len({event.network.src_port for event in http_events}) == 1
    assert [event.protocol.http.trans_depth for event in http_events] == [1, 2]
    assert [event.network.application_layer_only for event in http_events] == [False, True]
    assert parent_capture.require_lifecycle_mode() == "network"
    assert child_capture.require_lifecycle_mode() == "application_child"
    assert http_events[0].protocol.ssl is not None
    assert http_events[1].protocol.ssl is None
    assert http_events[1].network.closed_at <= http_events[0].network.closed_at
    retained_connection = state_manager.get_connection(parent.network.conn_id)
    assert retained_connection is not None
    assert (retained_connection.start_time, retained_connection.close_time) == parent_interval
    assert generator._http_channel_manager.census().open_transport_views == 1


def test_tls_and_cleartext_http_affinities_cannot_cross_reuse() -> None:
    """Transport security is an exact affinity dimension even on the same port."""

    common = {
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "dst_port": 8443,
        "http_host": "portal.example.test",
        "user_agent": "Mozilla/5.0",
    }
    cleartext = HttpChannelAffinity.from_request(
        **common,
        transport_security="cleartext",
    )
    tls = HttpChannelAffinity.from_request(
        **common,
        transport_security="tls",
    )

    assert cleartext != tls
    assert cleartext.digest != tls.digest


def test_direct_http_child_span_must_fit_immutable_parent_transport() -> None:
    """An otherwise exact hit opens a new parent when its full child span would escape."""

    generator, _state_manager, emitters = _generator()
    first_uid = _emit_http(
        generator,
        timestamp=_START,
        trans_depth=1,
        uri="/",
        duration=2.0,
    )
    parent = emitters["zeek_http"].events[0]
    second_uid = _emit_http(
        generator,
        timestamp=parent.network.started_at + timedelta(seconds=1),
        trans_depth=2,
        uri="/slow-child",
        duration=1.2,
    )

    assert second_uid != first_uid
    assert len(emitters["zeek_conn"].events) == 2
    assert len(emitters["ecar"].events) == 2
    assert [event.protocol.http.trans_depth for event in emitters["zeek_http"].events] == [1, 1]
    assert all(not event.network.application_layer_only for event in emitters["zeek_http"].events)


def test_direct_http_child_may_end_exactly_at_parent_close() -> None:
    """A child ending on the immutable close fence remains an application-only reuse."""

    generator, _state_manager, emitters = _generator()
    first_uid = _emit_http(
        generator,
        timestamp=_START,
        trans_depth=1,
        uri="/",
        request_body_len=0,
        response_body_len=100,
        duration=4.0,
    )
    parent = emitters["zeek_http"].events[0]
    second_uid = _emit_http(
        generator,
        timestamp=parent.network.started_at + timedelta(seconds=1),
        trans_depth=2,
        uri="/bounded-child",
        request_body_len=0,
        response_body_len=100,
        duration=3.0,
    )

    assert second_uid == first_uid
    assert len(emitters["zeek_conn"].events) == 1
    assert len(emitters["ecar"].events) == 1
    children = emitters["zeek_http"].events
    assert [event.protocol.http.trans_depth for event in children] == [1, 2]
    assert children[1].network.application_layer_only
    assert children[1].network.closed_at == parent.network.closed_at


def test_production_http_watermarks_plateau_and_exclude_the_window_boundary() -> None:
    """Thirty elapsed days do not retain channels, including an event at the end fence."""

    generator, state_manager, emitters = _generator()
    snapshots = {}
    for day in range(30):
        timestamp = _START + timedelta(days=day, minutes=1)
        state_manager.set_current_time(timestamp)
        _emit_http(
            generator,
            timestamp=timestamp,
            trans_depth=1,
            uri=f"/day/{day}",
            host=f"day-{day}.example.test",
            duration=2.0,
        )
        generator.advance_application_channel_watermark(timestamp + timedelta(minutes=1))
        census = generator._http_channel_manager.census()
        assert census.open_transport_views == 0
        assert census.application.retained_channels == 0
        if day + 1 in {1, 7, 30}:
            snapshots[day + 1] = census

    assert snapshots[30].estimated_bytes <= snapshots[7].estimated_bytes * 1.1
    assert snapshots[30].application.estimated_index_bytes <= max(
        1,
        snapshots[7].application.estimated_index_bytes,
    )
    calls_before_boundary = {name: len(emitter.events) for name, emitter in emitters.items()}
    state_manager.set_current_time(_END)
    boundary_uid = _emit_http(
        generator,
        timestamp=_END,
        trans_depth=1,
        uri="/outside",
        duration=0.2,
    )
    assert boundary_uid
    assert {name: len(emitter.events) for name, emitter in emitters.items()} == (
        calls_before_boundary
    )
    assert generator._http_channel_manager.census().open_transport_views == 0


def _deterministic_projection_signature(formats: tuple[str, ...]) -> tuple[tuple[object, ...], ...]:
    if hasattr(_thread_local, "rng"):
        del _thread_local.rng
    random.seed(42)
    generator, _state_manager, emitters = _generator(formats=formats)
    _emit_http(generator, timestamp=_START, trans_depth=1, uri="/")
    _emit_http(
        generator,
        timestamp=_START + timedelta(milliseconds=700),
        trans_depth=2,
        uri="/asset.js",
    )
    return tuple(
        (
            event.network.stable_id,
            event.network.zeek_uid,
            event.network.conn_id,
            event.network.src_port,
            event.network.application_layer_only,
            event.protocol.http.trans_depth,
            event.protocol.http.canonical_request_time,
        )
        for event in emitters["zeek_http"].events
    )


def test_http_channel_identity_is_independent_of_unrelated_output_filters() -> None:
    """Filtering physical projections cannot perturb frozen HTTP child identities."""

    full = _deterministic_projection_signature(("zeek_conn", "zeek_http", "ecar"))
    http_only = _deterministic_projection_signature(("zeek_http",))
    assert full == http_only
