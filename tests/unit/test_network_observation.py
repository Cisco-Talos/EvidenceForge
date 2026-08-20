# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical network-sensor observation and lifecycle admission."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import statistics
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events import HostContext
from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder, RawProjectionRequest
from evidenceforge.events.contexts import (
    DnsContext,
    FileTransferContext,
    HttpContext,
    IdsAlertPlan,
    NatContext,
    SyslogContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.formats import load_format
from evidenceforge.generation import network_observation as network_observation_module
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    PersistentSmbTrafficRebindAuthority,
    PersistentSmbTrafficRebindBinding,
)
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
)
from tests.network_factories import network_plan

T0 = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)


def _assert_published_once(mock: MagicMock, builder: OccurrenceBuilder) -> CanonicalOccurrence:
    """Assert one call received the sealed occurrence derived from ``builder``."""

    mock.assert_called_once()
    occurrence = mock.call_args.args[0]
    assert isinstance(occurrence, CanonicalOccurrence)
    assert occurrence.occurrence_id == builder.occurrence_id
    return occurrence


def _visibility_engine(
    *,
    source_profile: str = "",
    destination_profile: str = "",
) -> NetworkVisibilityEngine:
    config = NetworkConfig(
        segments=[
            NetworkSegment(
                name="workstations",
                cidr="10.0.1.0/24",
                exposure="internal",
            ),
            NetworkSegment(
                name="servers",
                cidr="10.0.2.0/24",
                exposure="internal",
            ),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="source-tap",
                monitoring_segments=["workstations"],
                capture_profile=source_profile,
                log_formats=["zeek"],
            ),
            NetworkSensor(
                type="network",
                name="destination-tap",
                monitoring_segments=["servers"],
                capture_profile=destination_profile,
                log_formats=["zeek"],
            ),
        ],
    )
    return NetworkVisibilityEngine(config, systems=[])


def _network_event(
    *,
    start: datetime = T0,
    stable_id: str = "network:test-transaction",
    protocol: str = "udp",
    zeek_uid: str = "CObservationTest1",
) -> OccurrenceBuilder:
    duration = 2.5
    network = network_plan(
        src_ip="10.0.1.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=53,
        protocol=protocol,
        service="dns",
        zeek_uid=zeek_uid,
        conn_id="conn-observation-test",
        duration=duration,
        source_visible_start_time=start,
        source_visible_close_time=start + timedelta(seconds=duration),
        orig_bytes=1200,
        resp_bytes=8400,
        orig_pkts=12,
        resp_pkts=24,
        orig_ip_bytes=1536,
        resp_ip_bytes=9072,
        conn_state="SF",
        history="Dd",
        ip_proto=6 if protocol == "tcp" else 17,
    )
    transaction = replace(
        network,
        stable_id=stable_id,
        hostname="resolver.corp.local",
        phase_times=(
            ("transport_start", start),
            ("transport_close", start + timedelta(seconds=duration)),
        ),
    )
    event = OccurrenceBuilder(
        timestamp=start,
        event_type="connection",
        network=transaction,
        dns=DnsContext(
            query="updates.example.com",
            answers=["10.0.2.40"],
            TTLs=[300.0],
            trans_id=4242,
            rtt=0.04,
        ),
        lifecycle=ActionLifecycleContext(
            group_id=transaction.stable_id,
            canonical_start=transaction.started_at,
            phase="start",
        ),
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap", "destination-tap"],
        "zeek_dns": ["source-tap", "destination-tap"],
    }
    return event


def _observation_by_sensor(
    observations: tuple[NetworkSensorObservation, ...],
) -> dict[str, NetworkSensorObservation]:
    return {observation.sensor_identity: observation for observation in observations}


def _persistent_smb_transport() -> NetworkTransactionPlan:
    return network_plan(
        src_ip="10.0.1.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid="CSmbPersistent1",
        conn_id="conn-smb-persistent",
        duration=2.5,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=2.5),
        orig_bytes=1_000,
        resp_bytes=500,
        orig_pkts=10,
        resp_pkts=5,
        orig_ip_bytes=1_280,
        resp_ip_bytes=640,
        conn_state="SF",
        history="ShADadFf",
        ip_proto=6,
    )


def _persistent_smb_observation(
    traffic: NetworkTrafficLedger,
    *,
    sensor_identity: str,
    history: str = "ShADadFf",
) -> NetworkSensorObservation:
    connection_uid = network_observation_module.derive_sensor_identifier(
        "CSmbPersistent1",
        sensor_identity,
    )
    return NetworkSensorObservation(
        sensor_identity=sensor_identity,
        path_role="destination_side",
        capture_profile="complete",
        tuple_view=NetworkTuple("10.0.1.25", 51000, "10.0.2.40", 445, "tcp"),
        connection_uid=connection_uid,
        connection_ids=(("CSmbPersistent1", connection_uid),),
        file_ids=(),
        local_orig=True,
        local_resp=False,
        observed_start_time=T0,
        observed_close_time=T0 + timedelta(seconds=2.5),
        traffic=traffic,
        visible_formats=frozenset({"zeek_conn", "zeek_smb_files"}),
        history=history,
        source_times=(("zeek_conn", T0 + timedelta(milliseconds=5)),),
        source_durations=(("zeek_conn", 2.4),),
    )


def _lossy_smb_traffic() -> NetworkTrafficLedger:
    return NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=900, packets=9, ip_bytes=1_150),
        resp=DirectionalTrafficLedger(payload_bytes=450, packets=4, ip_bytes=570),
        missed_orig_bytes=100,
        missed_resp_bytes=50,
    )


def _final_smb_traffic() -> NetworkTrafficLedger:
    return NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=1_300, packets=13, ip_bytes=1_660),
        resp=DirectionalTrafficLedger(payload_bytes=700, packets=7, ip_bytes=900),
    )


def _final_lossy_smb_traffic() -> NetworkTrafficLedger:
    return NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=1_170, packets=12, ip_bytes=1_500),
        resp=DirectionalTrafficLedger(payload_bytes=630, packets=6, ip_bytes=810),
        missed_orig_bytes=130,
        missed_resp_bytes=70,
    )


@dataclass(frozen=True, slots=True)
class _TestPersistentSmbCloseProof:
    authority_id: str
    binding_id: str
    close_facts_digest: str
    integrity: str


class _TestPersistentSmbCloseProofAuthority:
    """Private test double for the future dispatcher/State close cross-binding."""

    __slots__ = ("_authority_id", "_secret")

    def __init__(self) -> None:
        self._authority_id = secrets.token_hex(16)
        self._secret = secrets.token_bytes(32)

    def _integrity(self, binding_id: str, close_facts_digest: str) -> str:
        payload = (
            len(self._authority_id).to_bytes(8, "big")
            + self._authority_id.encode("ascii")
            + len(binding_id).to_bytes(8, "big")
            + binding_id.encode("ascii")
            + len(close_facts_digest).to_bytes(8, "big")
            + close_facts_digest.encode("ascii")
        )
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def issue(
        self,
        binding_id: str,
        close_facts_digest: str,
    ) -> _TestPersistentSmbCloseProof:
        return _TestPersistentSmbCloseProof(
            authority_id=self._authority_id,
            binding_id=binding_id,
            close_facts_digest=close_facts_digest,
            integrity=self._integrity(binding_id, close_facts_digest),
        )

    def authenticates_persistent_smb_close_proof(
        self,
        proof: object,
        binding_id: str,
        close_facts_digest: str,
    ) -> bool:
        if type(proof) is not _TestPersistentSmbCloseProof:
            return False
        authority_id = object.__getattribute__(proof, "authority_id")
        proof_binding_id = object.__getattribute__(proof, "binding_id")
        proof_digest = object.__getattribute__(proof, "close_facts_digest")
        integrity = object.__getattribute__(proof, "integrity")
        if not all(
            type(value) is str
            for value in (authority_id, proof_binding_id, proof_digest, integrity)
        ):
            return False
        expected = self._integrity(proof_binding_id, proof_digest)
        return bool(
            authority_id == self._authority_id
            and proof_binding_id == binding_id
            and proof_digest == close_facts_digest
            and hmac.compare_digest(integrity, expected)
        )


def _authenticated_persistent_smb_rebind(
    authority: PersistentSmbTrafficRebindAuthority,
    binding: PersistentSmbTrafficRebindBinding,
    transport: NetworkTransactionPlan,
    final_traffic: NetworkTrafficLedger,
    observations: tuple[NetworkSensorObservation, ...],
    final_observation_traffic: tuple[NetworkTrafficLedger, ...],
) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
    close_facts_digest = authority._prepare_close_proof_digest(
        binding,
        final_traffic,
        final_observation_traffic,
    )
    proof_authority = _TestPersistentSmbCloseProofAuthority()
    proof = proof_authority.issue(binding.binding_id, close_facts_digest)
    return authority._rebind_authenticated_close(
        binding,
        transport,
        final_traffic,
        observations,
        final_observation_traffic,
        proof,
        proof_authority,
    )


def _unproven_persistent_smb_rebind(
    authority: PersistentSmbTrafficRebindAuthority,
    binding: PersistentSmbTrafficRebindBinding,
    transport: NetworkTransactionPlan,
    final_traffic: NetworkTrafficLedger,
    observations: tuple[NetworkSensorObservation, ...],
    final_observation_traffic: tuple[NetworkTrafficLedger, ...],
) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
    """Exercise an earlier validation gate with a proof that can never authenticate."""

    return authority._rebind_authenticated_close(
        binding,
        transport,
        final_traffic,
        observations,
        final_observation_traffic,
        object(),
        _TestPersistentSmbCloseProofAuthority(),
    )


def test_persistent_smb_rebind_uses_signed_ordinals_and_manual_frozen_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close-time rebinding is pure and preserves the signed sensor decisions."""

    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    first = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    second = _persistent_smb_observation(
        _lossy_smb_traffic(),
        sensor_identity="sensor-b",
        history="ShADadFf",
    )
    binding = authority.issue_binding(transport, (first, second))
    canonical_final = _final_smb_traffic()
    observed_final = (canonical_final, _final_lossy_smb_traffic())

    def forbid_replan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("persistent traffic rebinding must not replan")

    monkeypatch.setattr(NetworkObservationPlanner, "plan", forbid_replan)
    monkeypatch.setattr(NetworkObservationPlanner, "_observed_traffic", forbid_replan)
    rebound_transport, rebound_observations = _authenticated_persistent_smb_rebind(
        authority,
        binding,
        transport,
        canonical_final,
        (first, second),
        observed_final,
    )

    assert rebound_transport.traffic is not canonical_final
    assert rebound_transport.traffic == canonical_final
    assert rebound_observations[0].traffic is rebound_transport.traffic
    assert rebound_observations[1].traffic == observed_final[1]
    assert rebound_observations[1].traffic is not observed_final[1]
    assert rebound_observations[0].history == "ShADadFf"
    assert rebound_observations[1].history == "ShADadFfGg"
    assert rebound_transport.zeek_uid == transport.zeek_uid
    assert rebound_transport.conn_id == transport.conn_id
    assert rebound_transport.phase_times == transport.phase_times
    assert rebound_transport.outcome == transport.outcome
    assert rebound_observations[0].tuple_view == first.tuple_view
    assert rebound_observations[0].connection_uid == first.connection_uid
    assert rebound_observations[0].source_times == first.source_times
    assert rebound_observations[0].visible_formats == first.visible_formats


def test_persistent_smb_rebind_rejects_non_smb_and_unsuccessful_transport() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()

    for invalid in (
        replace(transport, dst_port=53, service="dns"),
        replace(transport, protocol="udp", ip_proto=17),
        replace(transport, conn_state="S0", outcome="failure"),
        replace(transport, outcome="failure"),
    ):
        with pytest.raises(ValueError, match="successful SMB TCP/445"):
            authority.issue_binding(invalid, ())


def test_persistent_smb_binding_rejects_nonfinal_physical_transport_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()

    invalid_interval = replace(transport)
    object.__setattr__(invalid_interval, "duration", 2.4)
    zero_response = replace(
        transport,
        traffic=replace(transport.traffic, resp=DirectionalTrafficLedger()),
    )
    zero_response_packets = replace(transport)
    forged_response = DirectionalTrafficLedger()
    object.__setattr__(forged_response, "payload_bytes", 500)
    object.__setattr__(forged_response, "ip_bytes", 640)
    object.__setattr__(
        zero_response_packets,
        "traffic",
        replace(transport.traffic, resp=forged_response),
    )
    assert transport.closed_at is not None
    late_phase = replace(
        transport,
        phase_times=(
            *transport.phase_times,
            ("after-close", transport.closed_at + timedelta(microseconds=1)),
        ),
    )

    def forbidden_token(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("invalid final transport reached binding-ID allocation")

    monkeypatch.setattr(network_observation_module.secrets, "token_hex", forbidden_token)

    with pytest.raises(ValueError, match="phase follows its declared close"):
        authority.issue_binding(late_phase, ())

    for invalid in (
        replace(transport, application_layer_only=True),
        replace(transport, closed_at=None, duration=None),
        replace(transport, src_port=0),
        replace(transport, history=""),
        replace(transport, history="ShADadFfZ"),
        replace(transport, history="ShAFf"),
        invalid_interval,
        zero_response,
        zero_response_packets,
    ):
        with pytest.raises(ValueError):
            authority.issue_binding(invalid, ())


def test_persistent_smb_binding_rejects_nonfinal_sensor_timing_and_ports() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(
        transport.traffic,
        sensor_identity="sensor-a",
    )
    nat = NatSensorObservation(
        nat_type="dynamic_pat",
        direction="source",
        local_ip="10.0.1.25",
        local_port=0,
        global_ip="198.51.100.25",
        global_port=62_000,
        built_time=T0,
        teardown_time=T0 + timedelta(seconds=2.5),
    )

    invalid_observations = (
        replace(observation, tuple_view=replace(observation.tuple_view, src_port=0)),
        replace(observation, nat=nat),
        replace(observation, observed_close_time=None),
        replace(observation, visible_formats=frozenset()),
        replace(observation, visible_formats=frozenset({" zeek_conn"})),
        replace(observation, history=""),
        replace(observation, history="ShADadFfZ"),
        replace(observation, history="ShAFf"),
        replace(observation, source_times=(("zeek_dns", T0),)),
        replace(observation, source_times=((" zeek_conn", T0),)),
        replace(observation, source_durations=(("zeek_dns", 0.1),)),
        replace(observation, source_durations=(("zeek_conn", 3.0),)),
        replace(
            observation,
            source_times=(("zeek_smb_files", T0),),
            source_durations=(("zeek_conn", 0.1),),
        ),
    )
    for invalid in invalid_observations:
        with pytest.raises(ValueError):
            authority.issue_binding(transport, (invalid,))

    prefixed_key = "zeek_smb_files:file-1"
    prefixed = replace(
        observation,
        source_times=((prefixed_key, T0 + timedelta(seconds=1)),),
        source_durations=((prefixed_key, 0.5),),
    )
    authority.issue_binding(transport, (prefixed,))


def test_persistent_smb_rebind_rejects_shrink_missing_and_impossible_ledgers() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    binding = authority.issue_binding(transport, (observation,))
    smaller = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=1, packets=1, ip_bytes=40),
        resp=DirectionalTrafficLedger(payload_bytes=1, packets=1, ip_bytes=40),
    )

    with pytest.raises(ValueError, match="canonical traffic cannot shrink"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            smaller,
            (observation,),
            (observation.traffic,),
        )
    with pytest.raises(ValueError, match="Every persistent network observation"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            transport.traffic,
            (observation,),
            (),
        )

    payload_over_ip = DirectionalTrafficLedger(10, 1, 10)
    object.__setattr__(payload_over_ip, "ip_bytes", 9)
    invalid_payload = replace(transport.traffic, orig=payload_over_ip)
    with pytest.raises(ValueError, match="IP bytes"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            invalid_payload,
            (observation,),
            (invalid_payload,),
        )

    zero_packet_ip = DirectionalTrafficLedger(0, 0, 0)
    object.__setattr__(zero_packet_ip, "ip_bytes", 40)
    invalid_packets = replace(transport.traffic, orig=zero_packet_ip)
    with pytest.raises(ValueError, match="at least one packet"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            invalid_packets,
            (observation,),
            (invalid_packets,),
        )

    huge = replace(transport.traffic)
    object.__setattr__(huge.orig, "payload_bytes", 1 << 100_000)
    with pytest.raises(ValueError, match="signed 63-bit"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            huge,
            (observation,),
            (huge,),
        )


def test_persistent_smb_binding_rejects_sensor_traffic_above_canonical() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    tiny = replace(
        transport,
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(11, 1, 40),
            resp=DirectionalTrafficLedger(11, 1, 40),
        ),
    )
    sensor_10k = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(10_000, 10, 10_400),
        resp=DirectionalTrafficLedger(10, 1, 40),
    )
    observation = _persistent_smb_observation(sensor_10k, sensor_identity="sensor-a")

    with pytest.raises(ValueError, match="exceeds canonical"):
        authority.issue_binding(tiny, (observation,))


def test_persistent_smb_binding_preserves_lossless_alias_topology() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    equal_distinct = replace(transport.traffic)
    observation = _persistent_smb_observation(equal_distinct, sensor_identity="sensor-a")

    with pytest.raises(ValueError, match="must alias canonical traffic"):
        authority.issue_binding(transport, (observation,))

    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    binding = authority.issue_binding(transport, (observation,))
    final_traffic = _final_smb_traffic()
    with pytest.raises(ValueError, match="must alias final canonical traffic"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            final_traffic,
            (observation,),
            (replace(final_traffic),),
        )


def test_persistent_smb_binding_authenticates_sensor_order_tuple_and_uid() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    foreign = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    first = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    second = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-b")
    binding = authority.issue_binding(transport, (first, second))
    final = _final_smb_traffic()

    copied_binding = replace(binding)
    copied_transport, copied_observations = _authenticated_persistent_smb_rebind(
        authority,
        copied_binding,
        transport,
        final,
        (first, second),
        (final, final),
    )
    assert copied_observations[0].traffic is copied_transport.traffic
    assert copied_observations[1].traffic is copied_transport.traffic

    with pytest.raises(ValueError, match="foreign or tampered"):
        _unproven_persistent_smb_rebind(
            foreign,
            binding,
            transport,
            final,
            (first, second),
            (final, final),
        )
    tampered_binding = replace(binding)
    object.__setattr__(tampered_binding, "_integrity", "0" * 64)
    with pytest.raises(ValueError, match="foreign or tampered"):
        _unproven_persistent_smb_rebind(
            authority,
            tampered_binding,
            transport,
            final,
            (first, second),
            (final, final),
        )
    with pytest.raises(ValueError, match="signed sensor ordinal"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            final,
            (second, first),
            (final, final),
        )
    with pytest.raises(ValueError, match="derived connection UID|signed sensor ordinal"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            final,
            (replace(first, connection_uid="C-tampered"), second),
            (final, final),
        )
    with pytest.raises(ValueError, match="signed sensor ordinal"):
        _unproven_persistent_smb_rebind(
            authority,
            binding,
            transport,
            final,
            (replace(first, tuple_view=replace(first.tuple_view, src_port=51001)), second),
            (final, final),
        )


def test_persistent_smb_binding_recomputes_directional_gap_history() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(
        _lossy_smb_traffic(),
        sensor_identity="sensor-a",
        history="ShADadFfggGG",
    )
    binding = authority.issue_binding(transport, (observation,))

    rebound, observations = _authenticated_persistent_smb_rebind(
        authority,
        binding,
        transport,
        _final_smb_traffic(),
        (observation,),
        (_final_lossy_smb_traffic(),),
    )

    assert rebound.history == "ShADadFf"
    assert observations[0].history == "ShADadFfGg"


def test_persistent_smb_binding_rejects_non_neutral_file_and_http_derivatives() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")

    with pytest.raises(ValueError, match="SMB-neutral"):
        authority.issue_binding(
            transport,
            (replace(observation, file_ids=(("canonical", "observed"),)),),
        )
    with pytest.raises(ValueError, match="SMB-neutral"):
        authority.issue_binding(
            transport,
            (replace(observation, http_request_body_len=1),),
        )


def test_persistent_smb_binding_default_denies_future_observation_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    changed_schema = dict(NetworkSensorObservation.__dataclass_fields__)
    changed_schema["future_traffic_derivative"] = next(iter(changed_schema.values()))
    monkeypatch.setattr(NetworkSensorObservation, "__dataclass_fields__", changed_schema)

    with pytest.raises(RuntimeError, match="schema changed"):
        authority.issue_binding(transport, (observation,))

    monkeypatch.setattr(
        NetworkSensorObservation,
        "__dataclass_fields__",
        {key: value for key, value in changed_schema.items() if key != "future_traffic_derivative"},
    )
    changed_binding_schema = dict(PersistentSmbTrafficRebindBinding.__dataclass_fields__)
    changed_binding_schema["future_binding_field"] = next(iter(changed_binding_schema.values()))
    monkeypatch.setattr(
        PersistentSmbTrafficRebindBinding,
        "__dataclass_fields__",
        changed_binding_schema,
    )

    with pytest.raises(RuntimeError, match="schema changed"):
        authority.issue_binding(transport, (observation,))


def test_persistent_smb_binding_preflight_never_invokes_hostile_field_callbacks() -> None:
    class Trap:
        calls = 0

        def _raise(self) -> object:
            type(self).calls += 1
            raise AssertionError("hostile callback executed")

        def __eq__(self, _other: object) -> object:
            return self._raise()

        def __ne__(self, _other: object) -> object:
            return self._raise()

        def __lt__(self, _other: object) -> object:
            return self._raise()

        def __gt__(self, _other: object) -> object:
            return self._raise()

        def __hash__(self) -> object:
            return self._raise()

        def __index__(self) -> object:
            return self._raise()

        def __int__(self) -> object:
            return self._raise()

        def __repr__(self) -> object:
            return self._raise()

        def __str__(self) -> object:
            return self._raise()

    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    object.__setattr__(transport, "protocol", Trap())
    with pytest.raises(TypeError, match="transport.protocol"):
        authority.issue_binding(transport, ())
    assert Trap.calls == 0

    transport = _persistent_smb_transport()
    object.__setattr__(transport, "src_port", Trap())
    with pytest.raises(TypeError, match="transport.src_port"):
        authority.issue_binding(transport, ())
    assert Trap.calls == 0

    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(
        transport.traffic,
        sensor_identity="sensor-a",
    )
    object.__setattr__(observation, "sensor_identity", Trap())
    with pytest.raises(TypeError, match="sensor_identity"):
        authority.issue_binding(transport, (observation,))
    assert Trap.calls == 0

    observation = _persistent_smb_observation(
        transport.traffic,
        sensor_identity="sensor-a",
    )
    binding = authority.issue_binding(transport, (observation,))
    object.__setattr__(binding, "authority_id", Trap())
    with pytest.raises(TypeError, match="binding.authority_id"):
        authority._prepare_close_proof_digest(
            binding,
            _final_smb_traffic(),
            (_final_smb_traffic(),),
        )
    assert Trap.calls == 0


def test_persistent_smb_close_proof_binds_exact_final_canonical_and_sensor_facts() -> None:
    """Only the future dispatcher/State cross-binding may authenticate final facts."""

    assert not hasattr(PersistentSmbTrafficRebindAuthority, "rebind")
    assert not hasattr(PersistentSmbTrafficRebindAuthority, "issue_close_proof")

    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    binding = authority.issue_binding(transport, (observation,))
    high = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(2_000, 20, 2_560),
        resp=DirectionalTrafficLedger(2_000, 20, 2_560),
    )
    low = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(1_100, 10, 1_280),
        resp=DirectionalTrafficLedger(600, 5, 640),
    )
    high_digest = authority._prepare_close_proof_digest(
        binding,
        high,
        (high,),
    )
    proof_authority = _TestPersistentSmbCloseProofAuthority()
    proof = proof_authority.issue(binding.binding_id, high_digest)

    first = authority._rebind_authenticated_close(
        binding,
        transport,
        high,
        (observation,),
        (high,),
        proof,
        proof_authority,
    )
    low_digest = authority._prepare_close_proof_digest(
        binding,
        low,
        (low,),
    )
    assert low_digest != high_digest
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            low,
            (observation,),
            (low,),
            proof,
            proof_authority,
        )
    replay = authority._rebind_authenticated_close(
        binding,
        transport,
        high,
        (observation,),
        (high,),
        proof,
        proof_authority,
    )
    assert first == replay
    assert first is not replay

    lossy = _persistent_smb_observation(
        _lossy_smb_traffic(),
        sensor_identity="sensor-lossy",
    )
    lossy_binding = authority.issue_binding(transport, (lossy,))
    seen_a = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(1_800, 18, 2_300),
        resp=DirectionalTrafficLedger(1_800, 18, 2_300),
        missed_orig_bytes=200,
        missed_resp_bytes=200,
    )
    seen_b = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(1_700, 17, 2_170),
        resp=DirectionalTrafficLedger(1_900, 19, 2_430),
        missed_orig_bytes=300,
        missed_resp_bytes=100,
    )
    seen_a_digest = authority._prepare_close_proof_digest(
        lossy_binding,
        high,
        (seen_a,),
    )
    seen_a_proof = proof_authority.issue(lossy_binding.binding_id, seen_a_digest)
    authority._rebind_authenticated_close(
        lossy_binding,
        transport,
        high,
        (lossy,),
        (seen_a,),
        seen_a_proof,
        proof_authority,
    )
    seen_b_digest = authority._prepare_close_proof_digest(
        lossy_binding,
        high,
        (seen_b,),
    )
    assert seen_b_digest != seen_a_digest
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            lossy_binding,
            transport,
            high,
            (lossy,),
            (seen_b,),
            seen_a_proof,
            proof_authority,
        )

    foreign_proof_authority = _TestPersistentSmbCloseProofAuthority()
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            high,
            (observation,),
            (high,),
            proof,
            foreign_proof_authority,
        )
    tampered_proof = replace(proof)
    object.__setattr__(tampered_proof, "integrity", "0" * 64)
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            high,
            (observation,),
            (high,),
            tampered_proof,
            proof_authority,
        )

    class BoolTrap:
        calls = 0

        def __bool__(self) -> bool:
            type(self).calls += 1
            raise AssertionError("untrusted proof result truthiness executed")

    class NonBooleanAuthenticator:
        def authenticates_persistent_smb_close_proof(
            self,
            _proof: object,
            _binding_id: str,
            _close_facts_digest: str,
        ) -> object:
            return BoolTrap()

    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            high,
            (observation,),
            (high,),
            proof,
            NonBooleanAuthenticator(),
        )
    assert BoolTrap.calls == 0


def test_persistent_smb_close_proof_crossbinds_whole_opening_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    foreign_authority = PersistentSmbTrafficRebindAuthority()
    proof_authority = _TestPersistentSmbCloseProofAuthority()
    transport_a = _persistent_smb_transport()
    observation_a = _persistent_smb_observation(
        transport_a.traffic,
        sensor_identity="sensor-a",
    )
    observation_b = _persistent_smb_observation(
        transport_a.traffic,
        sensor_identity="sensor-b",
    )
    transport_c = replace(transport_a, src_port=51_001)
    observation_c = replace(
        observation_a,
        tuple_view=replace(observation_a.tuple_view, src_port=51_001),
    )
    monkeypatch.setattr(
        network_observation_module.secrets,
        "token_hex",
        lambda _size: "f" * 32,
    )
    binding_a = authority.issue_binding(transport_a, (observation_a,))
    binding_b = authority.issue_binding(transport_a, (observation_b,))
    binding_c = authority.issue_binding(transport_c, (observation_c,))
    foreign_binding = foreign_authority.issue_binding(transport_a, (observation_a,))
    assert (
        binding_a.binding_id
        == binding_b.binding_id
        == binding_c.binding_id
        == foreign_binding.binding_id
    )
    assert binding_a.transport_digest == binding_b.transport_digest
    assert binding_a.observation_digests != binding_b.observation_digests
    assert binding_a.transport_digest != binding_c.transport_digest

    final = _final_smb_traffic()
    digest_a = authority._prepare_close_proof_digest(binding_a, final, (final,))
    digest_b = authority._prepare_close_proof_digest(binding_b, final, (final,))
    digest_c = authority._prepare_close_proof_digest(binding_c, final, (final,))
    foreign_digest = foreign_authority._prepare_close_proof_digest(
        foreign_binding,
        final,
        (final,),
    )
    assert len({digest_a, digest_b, digest_c, foreign_digest}) == 4
    proof_a = proof_authority.issue(binding_a.binding_id, digest_a)

    authority._rebind_authenticated_close(
        binding_a,
        transport_a,
        final,
        (observation_a,),
        (final,),
        proof_a,
        proof_authority,
    )
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding_b,
            transport_a,
            final,
            (observation_b,),
            (final,),
            proof_a,
            proof_authority,
        )
    with pytest.raises(ValueError, match="close proof"):
        foreign_authority._rebind_authenticated_close(
            foreign_binding,
            transport_a,
            final,
            (observation_a,),
            (final,),
            proof_a,
            proof_authority,
        )
    with pytest.raises(ValueError, match="close proof"):
        authority._rebind_authenticated_close(
            binding_c,
            transport_c,
            final,
            (observation_c,),
            (final,),
            proof_a,
            proof_authority,
        )

    tampered = replace(binding_a)
    object.__setattr__(tampered, "_integrity", "0" * 64)
    with pytest.raises(ValueError, match="foreign or tampered"):
        authority._prepare_close_proof_digest(tampered, final, (final,))


@pytest.mark.parametrize(
    ("budget_name", "limit"),
    (
        ("_PERSISTENT_SMB_MAX_AGGREGATE_ITEMS", 1),
        ("_PERSISTENT_SMB_MAX_AGGREGATE_TEXT_BYTES", 1),
        ("_PERSISTENT_SMB_MAX_AGGREGATE_WORK_UNITS", 1),
    ),
)
def test_persistent_smb_aggregate_preflight_rejects_before_copy_or_digest(
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
    limit: int,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    monkeypatch.setattr(network_observation_module, budget_name, limit, raising=False)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("aggregate rejection must precede snapshot copy and digest")

    monkeypatch.setattr(network_observation_module, "_snapshot_persistent_smb_transport", forbidden)
    monkeypatch.setattr(network_observation_module, "_persistent_smb_transport_digest", forbidden)
    with pytest.raises(ValueError, match="aggregate"):
        authority.issue_binding(transport, (observation,))


def test_persistent_smb_close_aggregate_preflight_precedes_copy_and_proof_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    binding = authority.issue_binding(transport, (observation,))
    final = _final_smb_traffic()
    monkeypatch.setattr(
        network_observation_module,
        "_PERSISTENT_SMB_MAX_AGGREGATE_WORK_UNITS",
        1,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("aggregate rejection must precede copies and proof callbacks")

    class TrapAuthenticator:
        def authenticates_persistent_smb_close_proof(
            self,
            _proof: object,
            _binding_id: str,
            _close_facts_digest: str,
        ) -> bool:
            forbidden()
            return False

    monkeypatch.setattr(network_observation_module, "_snapshot_persistent_smb_binding", forbidden)
    with pytest.raises(ValueError, match="aggregate"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            final,
            (observation,),
            (final,),
            object(),
            TrapAuthenticator(),
        )


def test_persistent_smb_snapshot_recharges_after_post_preflight_tamper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    original_preflight = network_observation_module._preflight_persistent_smb_opening
    monkeypatch.setattr(
        network_observation_module,
        "_PERSISTENT_SMB_MAX_AGGREGATE_TEXT_BYTES",
        1_000,
    )

    def preflight_then_tamper(candidate_transport: object, observations: object) -> None:
        original_preflight(candidate_transport, observations)
        object.__setattr__(observation, "sensor_identity", "x" * 2_000)

    def forbidden_digest(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("post-preflight tamper must reject before digest")

    monkeypatch.setattr(
        network_observation_module,
        "_preflight_persistent_smb_opening",
        preflight_then_tamper,
    )
    monkeypatch.setattr(
        network_observation_module,
        "_persistent_smb_transport_digest",
        forbidden_digest,
    )
    monkeypatch.setattr(
        network_observation_module,
        "_persistent_smb_observation_digest",
        forbidden_digest,
    )
    with pytest.raises(ValueError, match="aggregate"):
        authority.issue_binding(transport, (observation,))


def test_persistent_smb_close_recharges_post_preflight_tamper_before_any_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    binding = authority.issue_binding(transport, (observation,))
    final = _final_smb_traffic()
    original_preflight = network_observation_module._preflight_persistent_smb_close_inputs
    monkeypatch.setattr(
        network_observation_module,
        "_PERSISTENT_SMB_MAX_AGGREGATE_TEXT_BYTES",
        1_000,
    )

    def preflight_then_tamper(*args: object) -> None:
        original_preflight(*args)
        object.__setattr__(observation, "sensor_identity", "x" * 2_000)

    def forbidden_digest(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("post-preflight close tamper must reject before digest")

    monkeypatch.setattr(
        network_observation_module,
        "_preflight_persistent_smb_close_inputs",
        preflight_then_tamper,
    )
    monkeypatch.setattr(PersistentSmbTrafficRebindAuthority, "_integrity", forbidden_digest)
    monkeypatch.setattr(
        network_observation_module,
        "_persistent_smb_transport_digest",
        forbidden_digest,
    )
    monkeypatch.setattr(
        network_observation_module,
        "_persistent_smb_observation_digest",
        forbidden_digest,
    )
    with pytest.raises(ValueError, match="aggregate"):
        authority._rebind_authenticated_close(
            binding,
            transport,
            final,
            (observation,),
            (final,),
            object(),
            _TestPersistentSmbCloseProofAuthority(),
        )


def test_persistent_smb_text_has_character_and_encoded_byte_caps() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()

    with pytest.raises(ValueError, match="text bound"):
        authority.issue_binding(replace(transport, hostname="a" * 4_097), ())
    with pytest.raises(ValueError, match="text bound"):
        authority.issue_binding(replace(transport, hostname="\N{SNOWMAN}" * 2_000), ())


def test_persistent_smb_binding_rejects_ambiguous_sensor_and_uid_cohorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    first = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    case_variant = _persistent_smb_observation(
        transport.traffic,
        sensor_identity="SENSOR-A",
    )

    with pytest.raises(ValueError, match="sensor identity"):
        authority.issue_binding(transport, (first, case_variant))
    with pytest.raises(ValueError, match="canonical sensor identity"):
        authority.issue_binding(
            transport,
            (_persistent_smb_observation(transport.traffic, sensor_identity=" sensor-a"),),
        )

    arbitrary_uid = "CArbitrarySensorUid"
    with pytest.raises(ValueError, match="derived connection UID"):
        authority.issue_binding(
            transport,
            (
                replace(
                    first,
                    connection_uid=arbitrary_uid,
                    connection_ids=((transport.zeek_uid, arbitrary_uid),),
                ),
            ),
        )
    with pytest.raises(ValueError, match="canonical connection mapping"):
        authority.issue_binding(
            transport,
            (replace(first, connection_ids=((transport.conn_id, first.connection_uid),)),),
        )

    second = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-b")
    forced_uid = "CForcedSensorUid"
    forced_first = replace(
        first,
        connection_uid=forced_uid,
        connection_ids=((transport.zeek_uid, forced_uid),),
    )
    forced_second = replace(
        second,
        connection_uid=forced_uid,
        connection_ids=((transport.zeek_uid, forced_uid),),
    )
    monkeypatch.setattr(
        network_observation_module,
        "derive_sensor_identifier",
        lambda _canonical_id, _sensor_identity: forced_uid,
    )
    with pytest.raises(ValueError, match="unique connection UID"):
        authority.issue_binding(transport, (forced_first, forced_second))


def test_persistent_smb_binding_enforces_exact_sensor_cohort_cap() -> None:
    authority = PersistentSmbTrafficRebindAuthority()
    transport = _persistent_smb_transport()
    observations = tuple(
        _persistent_smb_observation(
            transport.traffic,
            sensor_identity=f"sensor-{ordinal}",
        )
        for ordinal in range(4_096)
    )

    binding = authority.issue_binding(transport, observations)
    assert len(binding.observation_digests) == 4_096
    with pytest.raises(ValueError, match="cohort bound"):
        authority.issue_binding(transport, (*observations, observations[0]))


def test_lossless_and_nat_only_observations_retain_canonical_accounting() -> None:
    """Lossless mirrors may change tuple view and identity, never traffic truth."""

    event = _network_event()
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    planner = NetworkObservationPlanner(
        _visibility_engine(source_profile="well_synced", destination_profile="well_synced")
    )

    first = planner.plan(event, {"zeek_conn", "zeek_dns"})
    second = planner.plan(event, {"zeek_conn", "zeek_dns"})
    observations = _observation_by_sensor(first)

    assert first == second
    assert observations["source-tap"].path_role == "source_side"
    assert observations["destination-tap"].path_role == "destination_side"
    assert observations["source-tap"].traffic is event.network.traffic
    assert observations["destination-tap"].traffic is event.network.traffic
    assert observations["source-tap"].traffic == observations["destination-tap"].traffic
    assert observations["source-tap"].tuple_view.src_ip == "10.0.1.25"
    assert observations["destination-tap"].tuple_view.src_ip == "198.51.100.25"
    assert observations["destination-tap"].tuple_view.src_port == 62000
    assert (
        observations["source-tap"].connection_uid != observations["destination-tap"].connection_uid
    )
    for observation in observations.values():
        assert observation.visible_formats == frozenset({"zeek_conn", "zeek_dns"})
        assert observation.connection_id(event.network.zeek_uid) == observation.connection_uid
        assert observation.traffic.missed_bytes == 0
        assert observation.observed_duration >= event.network.duration


def test_capture_loss_projects_file_and_http_completeness_with_gap_history() -> None:
    """Sensor loss must propagate beyond conn.log without changing canonical truth."""

    event = _network_event(protocol="tcp")
    event.http = HttpContext(
        method="GET",
        host="files.example.com",
        uri="/payload.bin",
        response_body_len=8_000,
    )
    event.file_transfer = FileTransferContext(
        fuid="FObservationFile1",
        source="HTTP",
        analyzers=("SHA256",),
        is_orig=False,
        seen_bytes=8_000,
        total_bytes=8_000,
        sha256="a" * 64,
    )
    observed = NetworkTrafficLedger(
        orig=event.network.traffic.orig,
        resp=DirectionalTrafficLedger(payload_bytes=4_200, packets=12, ip_bytes=4_536),
        missed_resp_bytes=4_200,
    )

    history, files, request_body, response_body = NetworkObservationPlanner._observed_protocol(
        event,
        observed,
    )

    assert history.endswith("g")
    assert request_body == 0
    assert response_body == 4_000
    assert files[0].seen_bytes == 4_000
    assert files[0].missing_bytes == 4_000
    assert not files[0].analyzers_visible
    assert event.file_transfer.seen_bytes == 8_000


def test_capture_loss_projects_originator_http_file_from_originator_traffic() -> None:
    """Request entities use originator capture ratios and retain canonical totals."""

    event = _network_event(protocol="tcp")
    event.http = HttpContext(
        method="PUT",
        host="ingest.example.com",
        uri="/telemetry",
        request_body_len=8_000,
        orig_fuids=("FUploadObservation1",),
        orig_mime_types=("application/octet-stream",),
    )
    event.file_transfer = FileTransferContext(
        fuid="FUploadObservation1",
        source="HTTP",
        analyzers=("SHA1",),
        is_orig=True,
        seen_bytes=8_000,
        total_bytes=8_000,
        sha1="a" * 40,
    )
    observed = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=600, packets=6, ip_bytes=768),
        resp=event.network.traffic.resp,
        missed_orig_bytes=600,
    )

    history, files, request_body, response_body = NetworkObservationPlanner._observed_protocol(
        event, observed
    )

    assert history.endswith("G")
    assert request_body == 4_000
    assert response_body == 0
    assert files[0].seen_bytes == 4_000
    assert files[0].missing_bytes == 4_000
    assert not files[0].analyzers_visible
    assert event.file_transfer.total_bytes == 8_000


def test_inbound_static_nat_sensor_views_come_from_topology_and_nat_context() -> None:
    """Inside and outside tuple views need no mutable event-side swap map."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
            NetworkSegment(name="servers", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="outside-tap",
                monitoring_segments=["outside"],
                log_formats=["zeek"],
            ),
            NetworkSensor(
                type="network",
                name="inside-tap",
                monitoring_segments=["servers"],
                log_formats=["zeek"],
            ),
        ],
    )
    network = network_plan(
        src_ip="198.51.100.25",
        src_port=51000,
        dst_ip="203.0.113.80",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CInboundNatView1",
        conn_id="conn-inbound-nat-view",
        duration=2.0,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=2),
        orig_bytes=200,
        resp_bytes=800,
        orig_pkts=3,
        resp_pkts=4,
        orig_ip_bytes=320,
        resp_ip_bytes=960,
        conn_state="SF",
        history="ShADadFf",
        local_orig=False,
        local_resp=True,
    )
    network = replace(
        network,
        stable_id="network:inbound-nat-view",
        hostname="web.corp.local",
        phase_times=(("transport_start", T0), ("transport_close", T0 + timedelta(seconds=2))),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="static",
            mapped_src_ip="198.51.100.25",
            mapped_src_port=51000,
            mapped_dst_ip="10.0.2.40",
            mapped_dst_port=443,
        ),
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["outside-tap", "inside-tap"],
    }

    observations = _observation_by_sensor(
        NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
            event,
            {"zeek_conn"},
        )
    )

    assert observations["outside-tap"].tuple_view.dst_ip == "203.0.113.80"
    assert observations["outside-tap"].tuple_view.dst_port == 443
    assert observations["inside-tap"].tuple_view.dst_ip == "10.0.2.40"
    assert observations["inside-tap"].tuple_view.dst_port == 443
    assert observations["inside-tap"].local_resp is True


def test_distributed_taps_have_sensor_local_timing_and_accounting_texture() -> None:
    """Distributed taps vary accounting while nearby clock offsets stay coherent."""

    planner = NetworkObservationPlanner(_visibility_engine())
    differing_traffic = 0
    relative_offsets: list[float] = []
    for index in range(200):
        event = _network_event(
            start=T0 + timedelta(seconds=index * 3),
            stable_id=f"network:distributed-texture:{index}",
            protocol="tcp",
            zeek_uid=f"CDistributedTexture{index}",
        )
        observations = _observation_by_sensor(planner.plan(event, {"zeek_conn", "zeek_dns"}))
        source = observations["source-tap"]
        destination = observations["destination-tap"]
        differing_traffic += source.traffic != destination.traffic
        relative_offsets.append(
            (destination.observed_start_time - source.observed_start_time).total_seconds()
        )

    assert differing_traffic >= 20
    assert statistics.pstdev(relative_offsets) < 0.005
    assert max(relative_offsets) - min(relative_offsets) < 0.015


def test_clock_wander_is_shared_by_nearby_flows_and_changes_slowly() -> None:
    """A sensor clock follows time, not independent transaction identities."""

    planner = NetworkObservationPlanner(_visibility_engine())
    observed_offsets: list[float] = []
    for index in range(60):
        event = _network_event(
            start=T0 + timedelta(seconds=index),
            stable_id=f"network:clock-coherence:{index}",
            zeek_uid=f"CClockCoherence{index}",
        )
        observation = _observation_by_sensor(planner.plan(event, {"zeek_conn", "zeek_dns"}))[
            "source-tap"
        ]
        observed_offsets.append((observation.observed_start_time - event.timestamp).total_seconds())

    assert max(observed_offsets) - min(observed_offsets) < 0.001
    consecutive_changes = [
        abs(current - previous)
        for previous, current in zip(observed_offsets, observed_offsets[1:], strict=False)
    ]
    assert max(consecutive_changes) < 0.0001


def test_same_connection_observations_preserve_canonical_request_order() -> None:
    """Per-sensor timing texture cannot reorder transactions on one TCP stream."""

    planner = NetworkObservationPlanner(_visibility_engine())
    first_event = _network_event(
        start=T0,
        stable_id="network:http-parent",
        protocol="tcp",
    )
    second_event = _network_event(
        start=T0 + timedelta(milliseconds=1),
        stable_id="network:http-child",
        protocol="tcp",
    )
    second_event.network = replace(second_event.network, application_layer_only=True)

    first = _observation_by_sensor(planner.plan(first_event, {"zeek_conn", "zeek_dns"}))
    second = _observation_by_sensor(planner.plan(second_event, {"zeek_conn", "zeek_dns"}))

    for sensor_identity in first:
        observed_delta = (
            second[sensor_identity].observed_start_time - first[sensor_identity].observed_start_time
        )
        assert timedelta(microseconds=990) <= observed_delta <= timedelta(microseconds=1010)


def test_explicit_loss_profile_is_deterministic_bounded_and_auditable(monkeypatch) -> None:
    """Only an explicit capture-loss profile may change observed counters."""

    forced_loss = NetworkSensorObservationTiming(
        profile_name="lossy_span",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=10_000,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation.network_sensor_observation_timing",
        lambda _profile_name: forced_loss,
    )
    event = _network_event(protocol="tcp")
    event._sensor_hostnames_by_format = {"zeek_conn": ["destination-tap"]}
    planner = NetworkObservationPlanner(_visibility_engine(destination_profile="lossy_span"))

    first = planner.plan(event, {"zeek_conn"})[0]
    second = planner.plan(event, {"zeek_conn"})[0]
    canonical = event.network.traffic

    assert first == second
    assert first.capture_profile == "lossy_span"
    assert first.traffic.missed_bytes > 0
    assert (
        first.traffic.orig.payload_bytes < canonical.orig.payload_bytes
        or first.traffic.resp.payload_bytes < canonical.resp.payload_bytes
    )
    assert (
        canonical.orig.payload_bytes - first.traffic.orig.payload_bytes
        == first.traffic.missed_orig_bytes
    )
    assert (
        canonical.resp.payload_bytes - first.traffic.resp.payload_bytes
        == first.traffic.missed_resp_bytes
    )


def test_capture_loss_directionality_has_asymmetric_and_paired_shapes(monkeypatch) -> None:
    """Loss profiles should not stamp bidirectional gaps onto nearly every flow."""
    forced_loss = NetworkSensorObservationTiming(
        profile_name="lossy_span",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=10_000,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation.network_sensor_observation_timing",
        lambda _profile_name: forced_loss,
    )
    planner = NetworkObservationPlanner(_visibility_engine(destination_profile="lossy_span"))
    shapes: dict[str, int] = {"orig": 0, "resp": 0, "both": 0}

    for index in range(300):
        event = _network_event(
            protocol="tcp",
            stable_id=f"network:directional-loss:{index}",
            start=T0 + timedelta(seconds=index),
        )
        event._sensor_hostnames_by_format = {"zeek_conn": ["destination-tap"]}
        traffic = planner.plan(event, {"zeek_conn"})[0].traffic
        if traffic.missed_orig_bytes and traffic.missed_resp_bytes:
            shapes["both"] += 1
        elif traffic.missed_orig_bytes:
            shapes["orig"] += 1
        elif traffic.missed_resp_bytes:
            shapes["resp"] += 1

    assert all(count > 0 for count in shapes.values())
    assert shapes["both"] < 75
    assert shapes["orig"] > shapes["both"]
    assert shapes["resp"] > shapes["both"]


@pytest.mark.parametrize("protocol", ["udp", "icmp"])
def test_non_tcp_capture_loss_requires_packet_level_truth(protocol: str) -> None:
    """Datagram views cannot invent fractional loss without a packet sequence."""

    timing = NetworkSensorObservationTiming(
        profile_name="lossy_datagrams",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=10_000,
    )
    canonical = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=1_000, packets=10, ip_bytes=1_280),
        resp=DirectionalTrafficLedger(payload_bytes=500, packets=5, ip_bytes=640),
    )

    observed = NetworkObservationPlanner._observed_traffic(
        canonical, timing, "zeek-core", f"{protocol}-loss", protocol
    )

    assert observed is canonical
    assert observed.orig.payload_bytes == canonical.orig.payload_bytes
    assert observed.resp.payload_bytes == canonical.resp.payload_bytes
    assert observed.orig.packets == canonical.orig.packets
    assert observed.resp.packets == canonical.resp.packets
    assert observed.missed_bytes == 0


def test_sensor_clock_offset_drift_and_route_delay_are_stable(monkeypatch) -> None:
    """One sensor keeps a stable clock model while drift evolves with time."""

    timing = NetworkSensorObservationTiming(
        profile_name="clock-test",
        clock_offset_min_us=1000,
        clock_offset_max_us=1000,
        clock_drift_min_ppm=2,
        clock_drift_max_ppm=2,
        route_delay_min_us=3000,
        route_delay_max_us=3000,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=0.0,
        capture_loss_min_fraction=0.0,
        capture_loss_max_fraction=0.0,
        capture_loss_max_missed_bytes=0,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation.network_sensor_observation_timing",
        lambda _profile_name: timing,
    )
    planner = NetworkObservationPlanner(_visibility_engine())
    first_event = _network_event(start=T0, stable_id="network:clock-first")
    second_event = _network_event(
        start=T0 + timedelta(hours=1),
        stable_id="network:clock-second",
    )
    for event in (first_event, second_event):
        event._sensor_hostnames_by_format = {"zeek_conn": ["source-tap"]}

    first = planner.plan(first_event, {"zeek_conn"})[0]
    second = planner.plan(second_event, {"zeek_conn"})[0]

    assert first.observed_start_time - first_event.timestamp == timedelta(microseconds=76_000)
    assert second.observed_start_time - second_event.timestamp == timedelta(microseconds=83_200)
    assert second.observed_start_time - first.observed_start_time == timedelta(
        hours=1,
        microseconds=7200,
    )


def test_protocol_siblings_share_one_sensor_identity_and_tuple(tmp_path) -> None:
    """conn.log and dns.log consume the same frozen observation projection."""

    event = _network_event()
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    event.network_observations = NetworkObservationPlanner(
        _visibility_engine(source_profile="well_synced", destination_profile="well_synced")
    ).plan(event, {"zeek_conn", "zeek_dns"})
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )
    dns_emitter = ZeekDnsEmitter(
        load_format("zeek_dns"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    rows: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for sensor in ("source-tap", "destination-tap"):
        conn = json.loads((tmp_path / sensor / "conn.json").read_text())
        dns = json.loads((tmp_path / sensor / "dns.json").read_text())
        observation = _observation_by_sensor(event.network_observations)[sensor]
        rows[sensor] = conn, dns
        assert conn["uid"] == dns["uid"]
        assert conn["id.orig_h"] == dns["id.orig_h"]
        assert conn["id.orig_p"] == dns["id.orig_p"]
        assert conn["id.resp_h"] == dns["id.resp_h"]
        assert conn["id.resp_p"] == dns["id.resp_p"]
        assert conn["orig_bytes"] == 1200
        assert conn["resp_bytes"] == 8400
        assert conn["missed_bytes"] == 0
        assert conn["ts"] == pytest.approx(observation.observed_start_time.timestamp())
        assert dns["ts"] >= conn["ts"]
        assert dns["ts"] + dns["rtt"] <= conn["ts"] + conn["duration"]
    assert rows["source-tap"][0]["uid"] != rows["destination-tap"][0]["uid"]
    assert rows["destination-tap"][0]["id.orig_h"] == "198.51.100.25"


def test_short_dns_companion_stays_inside_planned_sensor_interval(tmp_path) -> None:
    """DNS query and response timing stays within a very short parent flow."""

    event = _network_event(start=T0, stable_id="network:short-dns")
    event.timestamp = T0 + timedelta(milliseconds=2)
    short_close = T0 + timedelta(seconds=0.000744)
    event.network = replace(
        event.network,
        stable_id="network:short-dns",
        hostname="resolver.corp.local",
        duration=0.000744,
        closed_at=short_close,
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(52, 1, 80),
            resp=DirectionalTrafficLedger(83, 1, 111),
        ),
        phase_times=(
            ("transport_start", T0),
            ("transport_close", short_close),
        ),
    )
    event.dns.rtt = 0.000744
    event.lifecycle = ActionLifecycleContext(
        group_id="network:short-dns",
        canonical_start=T0,
        phase="start",
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap"],
        "zeek_dns": ["source-tap"],
    }
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"zeek_conn", "zeek_dns"},
    )
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap"],
    )
    dns_emitter = ZeekDnsEmitter(
        load_format("zeek_dns"),
        tmp_path,
        sensor_hostnames=["source-tap"],
    )

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    conn = json.loads((tmp_path / "source-tap" / "conn.json").read_text())
    dns = json.loads((tmp_path / "source-tap" / "dns.json").read_text())
    assert dns["ts"] == pytest.approx(conn["ts"])
    assert dns["ts"] + dns["rtt"] <= conn["ts"] + conn["duration"]


def test_http_companion_never_precedes_planned_sensor_connection(tmp_path) -> None:
    """A sensor-local HTTP row cannot precede its same-UID connection start."""

    event = _network_event(stable_id="network:http-observation-order")
    event.dns = None
    event.network = replace(event.network, service="http")
    event.http = HttpContext(
        method="GET",
        host="updates.example.com",
        uri="/manifest.json",
        canonical_request_time=event.timestamp,
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap", "destination-tap"],
        "zeek_http": ["source-tap", "destination-tap"],
    }
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"zeek_conn", "zeek_http"},
    )
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )
    http_emitter = ZeekHttpEmitter(
        load_format("zeek_http"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )

    conn_emitter.emit(event)
    http_emitter.emit(event)
    conn_emitter.close()
    http_emitter.close()

    observations = _observation_by_sensor(event.network_observations)
    for sensor in ("source-tap", "destination-tap"):
        conn = json.loads((tmp_path / sensor / "conn.json").read_text())
        http = json.loads((tmp_path / sensor / "http.json").read_text())
        assert conn["ts"] == pytest.approx(observations[sensor].observed_start_time.timestamp())
        assert http["ts"] >= conn["ts"]


def test_snort_consumes_planned_sensor_timestamp_and_tuple(tmp_path) -> None:
    """Snort renders observation-owned clock and NAT views without local jitter."""

    event = _network_event()
    event.ids_alerts = (
        IdsAlertPlan(
            sid=2_000_001,
            message="Planned observation alert",
            classification="Attempted Information Leak",
        ),
    )
    event._sensor_hostnames_by_format = {"snort_alert": ["destination-tap"]}
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"snort_alert"},
    )
    event.network_observations_planned = True
    observation = event.network_observations[0]
    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path,
        sensor_hostnames=["destination-tap"],
    )

    emitter.emit(event)
    emitter.close()

    line = (tmp_path / "destination-tap" / "snort_alert.log").read_text()
    expected_timestamp = observation.observed_start_time.strftime("%m/%d-%H:%M:%S.%f")
    assert line.startswith(expected_timestamp)
    assert "198.51.100.25:62000 -> 10.0.2.40:53" in line


def test_firewall_observation_owns_syn_timeout_with_processing_texture() -> None:
    """One firewall policy supplies the timeout plus typed source processing."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
            NetworkSegment(name="servers", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="fw-perimeter",
                monitoring_segments=["outside", "servers"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    network = network_plan(
        src_ip="198.51.100.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CFirewallTimeout1",
        conn_id="conn-firewall-timeout",
        conn_state="S0",
        history="S",
        orig_pkts=1,
        orig_ip_bytes=40,
        source_visible_start_time=T0,
    )
    network = replace(
        network,
        stable_id="network:firewall-timeout",
        hostname="web.corp.local",
        outcome="failure",
        phase_times=(("transport_start", T0),),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.firewall_teardown_reason == "SYN Timeout"
    assert observation.firewall_teardown_time is not None
    teardown_delay = observation.firewall_teardown_time - observation.observed_start_time
    assert timedelta(seconds=30) < teardown_delay < timedelta(seconds=30.019)


def test_firewall_observation_keeps_dynamic_pat_alive_through_syn_timeout() -> None:
    """A dynamic translation cannot close before its S0 connection lifecycle."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="inside", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw-perimeter",
                monitoring_segments=["inside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    network = network_plan(
        src_ip="10.0.2.40",
        src_port=51000,
        dst_ip="198.51.100.25",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CNatTimeout1",
        conn_id="conn-nat-timeout",
        conn_state="S0",
        history="S",
        orig_pkts=1,
        orig_ip_bytes=40,
        source_visible_start_time=T0,
    )
    network = replace(
        network,
        stable_id="network:nat-timeout",
        hostname="edge.example",
        outcome="failure",
        phase_times=(("transport_start", T0),),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="dynamic_pat",
            mapped_src_ip="203.0.113.10",
            mapped_src_port=62001,
            mapped_dst_ip="198.51.100.25",
            mapped_dst_port=443,
        ),
    )
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.nat is not None
    assert observation.nat.direction == "source"
    assert observation.nat.local_ip == "10.0.2.40"
    assert observation.nat.global_ip == "203.0.113.10"
    assert observation.nat.teardown_time == observation.firewall_teardown_time
    teardown_delay = observation.nat.teardown_time - observation.observed_start_time
    assert timedelta(seconds=30) < teardown_delay < timedelta(seconds=30.019)


def test_firewall_observation_owns_inbound_static_nat_address_roles() -> None:
    """Inbound translation records distinguish the public VIP from the local host."""

    network = network_plan(
        src_ip="198.51.100.25",
        src_port=0,
        dst_ip="203.0.113.5",
        dst_port=8,
        protocol="icmp",
        duration=1.0,
        zeek_uid="CInboundIcmp1",
        conn_id="conn-inbound-icmp",
        conn_state="SF",
        history="Dd",
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=84,
        resp_ip_bytes=84,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=1),
    )
    network = replace(
        network,
        stable_id="network:inbound-icmp",
        hostname="web.corp.local",
        outcome="success",
        phase_times=(
            ("transport_start", T0),
            ("transport_close", T0 + timedelta(seconds=1)),
        ),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="static",
            mapped_src_ip="198.51.100.25",
            mapped_src_port=0,
            mapped_dst_ip="10.0.2.40",
            mapped_dst_port=8,
        ),
    )
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(None).plan(event, {"cisco_asa"})[0]

    assert observation.nat is not None
    assert observation.nat.direction == "destination"
    assert observation.nat.global_ip == "203.0.113.5"
    assert observation.nat.local_ip == "10.0.2.40"


def test_subsecond_midstream_fragment_is_not_labeled_connection_timeout() -> None:
    """A short OTH/Cc observation cannot expire an ASA idle timer immediately."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="dmz", cidr="10.0.3.0/24", exposure="both"),
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="fw-perimeter",
                monitoring_segments=["dmz", "outside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    close = T0 + timedelta(milliseconds=250)
    network = network_plan(
        src_ip="10.0.3.20",
        src_port=51000,
        dst_ip="198.51.100.40",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CFirewallFragment1",
        conn_id="conn-firewall-fragment",
        duration=0.25,
        conn_state="OTH",
        history="Cc",
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=52,
        resp_ip_bytes=52,
        source_visible_start_time=T0,
        source_visible_close_time=close,
    )
    network = replace(
        network,
        stable_id="network:firewall-fragment",
        hostname="edge.example",
        outcome="success",
        phase_times=(("transport_start", T0), ("transport_close", close)),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.firewall_teardown_reason == "TCP Reset-O"
    assert observation.firewall_teardown_reason != "Conn-timeout"
    assert observation.observed_close_time < observation.firewall_teardown_time
    assert observation.firewall_teardown_time - observation.observed_close_time < timedelta(
        milliseconds=12.5
    )


def test_firewall_teardown_after_export_window_is_marked_unobserved() -> None:
    """Perimeter lifecycle fan-out respects the half-open collection boundary."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="inside", cidr="10.0.1.0/24", exposure="internal"),
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw-perimeter",
                monitoring_segments=["inside", "outside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    close = T0 + timedelta(minutes=10)
    network = network_plan(
        src_ip="10.0.1.20",
        src_port=51000,
        dst_ip="198.51.100.40",
        dst_port=22,
        protocol="tcp",
        zeek_uid="CFirewallBoundary1",
        conn_id="conn-firewall-boundary",
        duration=600.0,
        conn_state="SF",
        history="ShADadFf",
        orig_pkts=4,
        resp_pkts=4,
        orig_ip_bytes=500,
        resp_ip_bytes=500,
        source_visible_start_time=T0,
        source_visible_close_time=close,
    )
    network = replace(
        network,
        stable_id="network:firewall-boundary",
        hostname="edge.example",
        outcome="success",
        phase_times=(("transport_start", T0), ("transport_close", close)),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(
        NetworkVisibilityEngine(config, systems=[]),
        output_end_time=T0 + timedelta(minutes=5),
    ).plan(event, {"cisco_asa"})[0]

    assert observation.firewall_teardown_time is not None
    assert observation.firewall_teardown_time >= T0 + timedelta(minutes=5)
    assert observation.firewall_teardown_observed is False


def test_capture_profile_accepts_blank_and_rejects_unknown_names() -> None:
    """Scenario sensors inherit the default profile but fail fast on typos."""

    sensor = NetworkSensor(
        type="network",
        name="default-tap",
        monitoring_segments=["workstations"],
        capture_profile="   ",
    )
    assert sensor.capture_profile == ""
    with pytest.raises(ValueError, match="Unknown network sensor capture_profile"):
        NetworkSensor(
            type="network",
            name="typo-tap",
            monitoring_segments=["workstations"],
            capture_profile="lossy-spna",
        )


def _mock_emitter() -> MagicMock:
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    return emitter


def _lifecycle_event(
    *,
    timestamp: datetime,
    group_id: str,
    canonical_start: datetime,
    phase: str,
    parent_group_id: str | None = None,
) -> OccurrenceBuilder:
    """Return a contract-valid source-local event for admission-boundary tests."""

    return OccurrenceBuilder(
        timestamp=timestamp,
        event_type="syslog",
        src_host=HostContext(
            hostname="server-01",
            ip="10.0.2.40",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        ),
        syslog=SyslogContext(
            app_name="systemd",
            pid=1,
            facility=3,
            severity=6,
            message="lifecycle admission test",
        ),
        lifecycle=ActionLifecycleContext(
            group_id=group_id,
            canonical_start=canonical_start,
            phase=phase,
            parent_group_id=parent_group_id,
        ),
    )


def test_half_open_end_suppresses_group_start_and_dependents_but_updates_state() -> None:
    """Source-visible starts and dependent rows at ``end`` are excluded."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    start = _lifecycle_event(
        timestamp=output_end,
        group_id="session-at-end",
        canonical_start=output_end,
        phase="start",
    )
    dependent = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=1),
        group_id="session-before-end",
        canonical_start=output_end - timedelta(seconds=10),
        phase="dependent",
    )

    dispatcher.dispatch_builder(start)
    dispatcher.dispatch_builder(dependent)

    assert state_manager.apply.call_count == 2
    emitter.emit.assert_not_called()


def test_closure_after_end_is_suppressed_even_when_group_started_before_end() -> None:
    """A still-open action does not leak a discrete closure beyond the slice."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    admitted = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=30),
        group_id="session-before-end",
        canonical_start=output_end - timedelta(minutes=1),
        phase="closure",
    )
    suppressed = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=30),
        group_id="session-at-end",
        canonical_start=output_end,
        phase="closure",
    )

    dispatcher.dispatch_builder(admitted)
    dispatcher.dispatch_builder(suppressed)

    emitter.emit.assert_not_called()
    assert state_manager.apply.call_count == 2


def test_nested_parent_closure_and_child_start_at_end_are_both_suppressed() -> None:
    """Both closure and child records respect the half-open source interval."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    parent_closure = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=2),
        group_id="proxy-parent",
        canonical_start=output_end - timedelta(seconds=10),
        phase="closure",
    )
    child_start = _lifecycle_event(
        timestamp=output_end,
        group_id="origin-child",
        canonical_start=output_end,
        phase="start",
        parent_group_id="proxy-parent",
    )

    dispatcher.dispatch_builder(parent_closure)
    dispatcher.dispatch_builder(child_start)

    emitter.emit.assert_not_called()


def test_sensor_observation_at_end_is_suppressed_without_emitter_fallback() -> None:
    """An empty admitted observation set cannot fall back to configured sensor routing."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    event = _network_event(start=output_end - timedelta(seconds=1))
    planned = NetworkObservationPlanner(_visibility_engine()).plan(event, {"zeek_conn"})[0]
    planned_at_end = NetworkSensorObservation(
        sensor_identity=planned.sensor_identity,
        path_role=planned.path_role,
        capture_profile=planned.capture_profile,
        tuple_view=planned.tuple_view,
        connection_uid=planned.connection_uid,
        connection_ids=planned.connection_ids,
        file_ids=planned.file_ids,
        local_orig=planned.local_orig,
        local_resp=planned.local_resp,
        observed_start_time=output_end,
        observed_close_time=output_end + timedelta(seconds=2),
        traffic=planned.traffic,
        visible_formats=frozenset({"zeek_conn"}),
    )
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"zeek_conn": emitter},
        output_end_time=output_end,
    )
    dispatcher.network_observation_planner.plan = MagicMock(return_value=(planned_at_end,))

    identifiers = dispatcher.dispatch_builder(event)

    _assert_published_once(state_manager.apply, event)
    emitter.emit.assert_not_called()
    assert identifiers == {"zeek_conn": ""}


def test_raw_entry_at_end_is_suppressed() -> None:
    """Raw source admission follows the same half-open interval."""

    emitter = _mock_emitter()
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"syslog": emitter},
        output_end_time=T0,
    )

    dispatcher.dispatch_raw(RawProjectionRequest(T0, "syslog", {"message": "at end"}))

    emitter.emit_raw.assert_not_called()
