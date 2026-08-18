# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production gates for runtime-owned network sensor and Zeek timing."""

from __future__ import annotations

import inspect
import json
import os
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder
from evidenceforge.events.collection_policy import (
    CollectionCapability,
    CollectionWindow,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.contexts import (
    DhcpContext,
    DnsContext,
    FileTransferContext,
    HttpContext,
    NtpContext,
    OcspContext,
    PeContext,
    SmbContext,
    SmtpContext,
    SslContext,
    WeirdContext,
    X509Context,
)
from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey, shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.network import NetworkSensorObservation
from evidenceforge.events.observation import ObservationDecision, ObservationPolicy
from evidenceforge.formats import load_format
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.emitters import zeek as zeek_module
from evidenceforge.generation.emitters import zeek_base as zeek_base_module
from evidenceforge.generation.emitters import zeek_files as zeek_files_module
from evidenceforge.generation.emitters import zeek_http as zeek_http_module
from evidenceforge.generation.emitters import zeek_ocsp as zeek_ocsp_module
from evidenceforge.generation.emitters import zeek_pe as zeek_pe_module
from evidenceforge.generation.emitters import zeek_smb as zeek_smb_module
from evidenceforge.generation.emitters import zeek_ssl as zeek_ssl_module
from evidenceforge.generation.emitters import zeek_weird as zeek_weird_module
from evidenceforge.generation.emitters import zeek_x509 as zeek_x509_module
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ocsp import ZeekOcspEmitter
from evidenceforge.generation.emitters.zeek_pe import ZeekPeEmitter
from evidenceforge.generation.emitters.zeek_smb import (
    ZeekSmbFilesEmitter,
    ZeekSmbMappingEmitter,
)
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_weird import ZeekWeirdEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    compatibility_network_source_duration,
    compatibility_network_source_time,
    network_observation_owns_format_timing,
    network_source_timing_key,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import (
    TemporalConstraintGraph,
    TimingRuntime,
    TimingScope,
)
from evidenceforge.models.exceptions import EventContractError
from tests.network_factories import network_plan

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_MIGRATED_FORMATS = {
    "zeek_conn",
    "zeek_files",
    "zeek_http",
    "zeek_ocsp",
    "zeek_pe",
    "zeek_ssl",
    "zeek_x509",
}


def _simple_event(
    ordinal: int,
    *,
    sensor_names: tuple[str, ...] = ("core-tap",),
) -> OccurrenceBuilder:
    """Return one stable sensor-visible TCP transaction."""

    network = network_plan(
        src_ip="10.0.1.25",
        src_port=40_000 + ordinal,
        dst_ip="198.51.100.40",
        dst_port=443,
        protocol="tcp",
        service="ssl",
        zeek_uid=f"CNetworkTiming{ordinal:05d}",
        conn_id=f"conn-network-timing-{ordinal}",
        duration=3.0,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=3),
        orig_bytes=900,
        resp_bytes=4_800,
        orig_pkts=5,
        resp_pkts=8,
        orig_ip_bytes=1_100,
        resp_ip_bytes=5_120,
        conn_state="SF",
        history="ShADadFf",
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=replace(network, stable_id=f"network:runtime:{ordinal}"),
    )
    event._sensor_hostnames_by_format = {"zeek_conn": list(sensor_names)}
    return event


def _direct_short_http_event(
    duration: float,
    ordinal: int,
    *,
    include_file: bool,
    file_duration: float = 0.0,
) -> OccurrenceBuilder:
    """Return one direct HTTP transaction at a zero/subminimum transport interval."""

    file_id = f"FDirect{ordinal}"
    transfer = (
        FileTransferContext(
            fuid=file_id,
            source="HTTP",
            duration=file_duration,
            seen_bytes=20,
            mime_type="text/plain",
        )
        if include_file
        else None
    )
    return OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.1",
            src_port=50_000 + ordinal,
            dst_ip="198.51.100.1",
            dst_port=80,
            protocol="tcp",
            service="http",
            zeek_uid=f"CDirect{ordinal}",
            conn_id=f"conn-direct-{ordinal}",
            duration=duration,
            source_visible_start_time=T0,
            orig_bytes=100,
            resp_bytes=200,
            conn_state="SF",
            history="ShADadFf",
        ),
        http=HttpContext(
            method="GET",
            host="example.test",
            uri=f"/{ordinal}",
            resp_fuids=(file_id,) if include_file else (),
            resp_mime_types=("text/plain",) if include_file else (),
        ),
        file_transfer=transfer,
    )


def _protocol_event(ordinal: int, *, rich: bool = True) -> OccurrenceBuilder:
    """Return one HTTP/file transaction, optionally with TLS analyzer companions."""

    start = T0 + timedelta(microseconds=ordinal % 17)
    http_fuid = f"FHttpTiming{ordinal:06d}"
    ocsp_fuid = f"FOcspTiming{ordinal:06d}"
    leaf = X509Context(
        fuid=f"FLeafTiming{ordinal:06d}",
        fingerprint="a" * 40,
        certificate_subject="CN=files.example.test",
        certificate_issuer="CN=Example Intermediate",
    )
    intermediate = X509Context(
        fuid=f"FInterTiming{ordinal:05d}",
        fingerprint="b" * 40,
        certificate_subject="CN=Example Intermediate",
        certificate_issuer="CN=Example Root",
        host_cert=False,
    )
    network = network_plan(
        src_ip="10.0.1.25",
        src_port=45_000 + ordinal,
        dst_ip="198.51.100.55",
        dst_port=443 if rich else 80,
        protocol="tcp",
        service="http",
        zeek_uid=f"CProtocolTiming{ordinal:05d}",
        conn_id=f"conn-protocol-timing-{ordinal}",
        duration=3.0,
        source_visible_start_time=start,
        source_visible_close_time=start + timedelta(seconds=3),
        orig_bytes=1_200,
        resp_bytes=100_000,
        orig_pkts=8,
        resp_pkts=80,
        orig_ip_bytes=1_600,
        resp_ip_bytes=104_000,
        conn_state="SF",
        history="ShADadFf",
    )
    event = OccurrenceBuilder(
        timestamp=start,
        event_type="connection",
        network=replace(network, stable_id=f"network:protocol-runtime:{ordinal}"),
        ssl=(
            SslContext(
                version="TLSv13",
                cipher="TLS_AES_128_GCM_SHA256",
                server_name="files.example.test",
                cert_chain_fuids=(leaf.fuid, intermediate.fuid),
            )
            if rich
            else None
        ),
        http=HttpContext(
            method="GET",
            host="files.example.test",
            uri=f"/release/{ordinal}.exe",
            response_body_len=80_000,
            canonical_request_time=start + timedelta(milliseconds=200),
            resp_fuids=(http_fuid, ocsp_fuid) if rich else (http_fuid,),
            resp_mime_types=("application/octet-stream",),
        ),
        file_transfer=FileTransferContext(
            fuid=http_fuid,
            source="HTTP",
            analyzers=("SHA256",),
            mime_type="application/octet-stream",
            duration=0.2,
            seen_bytes=80_000,
            total_bytes=80_000,
        ),
        file_transfers=(
            [
                FileTransferContext(
                    fuid=ocsp_fuid,
                    source="HTTP",
                    duration=0.1,
                    seen_bytes=1_200,
                    total_bytes=1_200,
                )
            ]
            if rich
            else []
        ),
        x509=leaf if rich else None,
        x509_chain=[leaf, intermediate] if rich else [],
        ocsp=OcspContext(id=ocsp_fuid) if rich else None,
        pe_analyses=[PeContext(id=http_fuid)] if rich else [],
    )
    formats = _MIGRATED_FORMATS if rich else {"zeek_conn", "zeek_http", "zeek_files"}
    event._sensor_hostnames_by_format = {format_name: ["core-tap"] for format_name in formats}
    return event


def _seal_test_occurrence(event: OccurrenceBuilder, ordinal: int) -> CanonicalOccurrence:
    """Publish one fixture through the canonical immutable boundary."""

    event.occurrence_key = SemanticOccurrenceKey(
        action_id=f"test-direct-protocol-{ordinal}",
        role=OccurrenceRole.PRIMARY,
        instance_key=f"connection-{ordinal}",
    )
    event.contract_seal = shadow_seal(event)
    assert event.contract_seal.valid
    return event.seal()


_PHASE_TIMING_FORMATS = (
    "zeek_smb_mapping",
    "zeek_smb_files",
    "zeek_files",
    "zeek_weird",
)


def _phase_timing_event(
    format_name: str,
    *,
    storyline_cluster_id: str | None = None,
) -> OccurrenceBuilder:
    """Return one network phase event using the real SMB/weird contract shapes."""

    event_type = {
        "zeek_smb_mapping": "smb_tree_connect",
        "zeek_smb_files": "smb_file_open",
        "zeek_files": "smb_file_read",
        "zeek_weird": "connection",
    }[format_name]
    network = network_plan(
        src_ip="10.0.1.25",
        src_port=44_512,
        dst_ip="10.0.2.40",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"CPhaseTiming{format_name}",
        conn_id=f"conn-phase-timing-{format_name}",
        duration=2.0,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=2),
        orig_bytes=800,
        resp_bytes=2_400,
        orig_pkts=5,
        resp_pkts=7,
        orig_ip_bytes=1_000,
        resp_ip_bytes=2_680,
        conn_state="SF",
        history="ShADadFf",
    )
    smb = SmbContext(
        phase=(
            "tree_connect"
            if format_name == "zeek_smb_mapping"
            else "read"
            if format_name == "zeek_files"
            else "open"
        ),
        operation="copy",
        purpose="collection",
        session_id="session-phase-1",
        tree_id="tree-phase-1",
        share_ref="FILE-01.finance",
        share_name="finance",
        result="success",
        share_path="reports/q3.xlsx",
    )
    transfer = (
        FileTransferContext(
            fuid="FPhaseTiming0001",
            source="SMB",
            filename="q3.xlsx",
            duration=0.4,
            seen_bytes=2_400,
            total_bytes=2_400,
            is_orig=False,
        )
        if format_name == "zeek_files"
        else None
    )
    event = OccurrenceBuilder(
        timestamp=T0 + timedelta(milliseconds=750 if format_name == "zeek_files" else 250),
        event_type=event_type,
        network=replace(network, stable_id=f"network:phase-timing:{format_name}"),
        smb=smb if format_name != "zeek_weird" else None,
        file_transfer=transfer,
        weird=(
            WeirdContext(name="bad_TCP_checksum", source="TCP")
            if format_name == "zeek_weird"
            else None
        ),
        storyline_cluster_id=storyline_cluster_id,
    )
    event._sensor_hostnames_by_format = {format_name: ["core"]}
    return event


def _phase_source_times(
    observation: NetworkSensorObservation,
    format_name: str,
) -> tuple[datetime, ...]:
    """Return every exact frozen timestamp for one format."""

    prefix = f"{format_name}:"
    return tuple(
        timestamp
        for key, timestamp in observation.source_times
        if key == format_name or key.startswith(prefix)
    )


def _phase_source_deployment(
    format_name: str,
    *,
    missingness: float = 0.0,
    windows: tuple[CollectionWindow, ...] = (CollectionWindow(),),
) -> CompiledCollectionDeployment:
    """Return one exact compiled Zeek sensor deployment for a phase format."""

    analyzer_capabilities = {
        "zeek_smb_mapping": CollectionCapability.SMB | CollectionCapability.SMB_ANALYZER,
        "zeek_smb_files": CollectionCapability.SMB
        | CollectionCapability.FILE
        | CollectionCapability.SMB_ANALYZER
        | CollectionCapability.FILE_ANALYZER,
        "zeek_files": CollectionCapability.FILE | CollectionCapability.FILE_ANALYZER,
        "zeek_weird": CollectionCapability.NONE,
    }[format_name]
    return CompiledCollectionDeployment(
        (
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance="zeek:core",
                    hostname="core",
                    family="zeek",
                ),
                formats=(format_name,),
                policy=SourceCollectionPolicy(
                    capabilities=CollectionCapability.NETWORK | analyzer_capabilities,
                    missingness=missingness,
                    windows=windows,
                ),
            ),
        )
    )


def _auxiliary_protocol_event(ordinal: int) -> OccurrenceBuilder:
    """Return one transport carrying the newly runtime-owned protocol analyzers."""

    start = T0 + timedelta(microseconds=ordinal % 23)
    close = start + timedelta(milliseconds=750)
    uid = f"CAuxTiming{ordinal:06d}"
    network = network_plan(
        src_ip="10.0.1.25",
        src_port=53_000 + ordinal,
        dst_ip="10.0.1.53",
        dst_port=53,
        protocol="udp",
        service="smtp",
        zeek_uid=uid,
        conn_id=f"conn-aux-timing-{ordinal}",
        duration=0.75,
        source_visible_start_time=start,
        source_visible_close_time=close,
        orig_bytes=180,
        resp_bytes=420,
        orig_pkts=2,
        resp_pkts=2,
        orig_ip_bytes=260,
        resp_ip_bytes=500,
        conn_state="SF",
        history="DdDd",
    )
    event = OccurrenceBuilder(
        timestamp=start,
        event_type="connection",
        network=replace(network, stable_id=f"network:aux-runtime:{ordinal}"),
        dns=DnsContext(
            query=f"host-{ordinal}.corp.example",
            trans_id=ordinal % 65_535 or 1,
            answers=["10.0.2.40"],
            TTLs=[300.0],
            rtt=0.02,
        ),
        dhcp=DhcpContext(
            client_addr="0.0.0.0",
            server_addr="10.0.1.53",
            mac="00:11:22:33:44:55",
            assigned_addr="10.0.1.25",
            uids=[uid],
            msg_types=["DISCOVER", "OFFER", "REQUEST", "ACK"],
            duration=0.35,
        ),
        smtp=SmtpContext(
            helo="mail.corp.example",
            mailfrom="sender@corp.example",
            rcptto=["recipient@corp.example"],
            date="Sun, 16 Aug 2026 12:00:00 +0000",
            from_header="sender@corp.example",
            to_header=["recipient@corp.example"],
            msg_id=f"<{ordinal}@corp.example>",
            subject="Quarterly report",
            last_reply="250 Message accepted",
        ),
        ntp=NtpContext(
            version=4,
            mode=4,
            stratum=2,
            ref_ts=(start - timedelta(seconds=60)).timestamp(),
            org_ts=start.timestamp(),
            rec_ts=(start + timedelta(milliseconds=8)).timestamp(),
            xmt_ts=(start + timedelta(milliseconds=9)).timestamp(),
        ),
    )
    event._sensor_hostnames_by_format = {
        format_name: ["core-tap"]
        for format_name in ("zeek_conn", "zeek_dhcp", "zeek_dns", "zeek_ntp", "zeek_smtp")
    }
    return event


def _runtime_planner(namespace: str) -> tuple[NetworkTransactionPlanner, TimingRuntime]:
    """Return a planner adapter that exposes only the shared timing runtime."""

    runtime = TimingRuntime(reference_time=T0, namespace=namespace)
    executor = SimpleNamespace(timing_runtime=runtime)
    return NetworkTransactionPlanner(executor), runtime


def _planned_population(
    *,
    cache_size: int,
    workers: int,
    reverse: bool,
) -> dict[int, tuple[tuple[str, datetime], ...]]:
    """Plan a population under one ordering, worker, and clock-cache shape."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="network-runtime-determinism",
        max_clock_cache_entries=cache_size,
    )
    planner = NetworkObservationPlanner(None, timing_runtime=runtime)
    ordinals = list(range(128))
    if reverse:
        ordinals.reverse()

    def plan_one(ordinal: int) -> tuple[int, tuple[tuple[str, datetime], ...]]:
        observation = planner.plan(_simple_event(ordinal), {"zeek_conn"})[0]
        return ordinal, observation.source_times

    if workers == 1:
        values = tuple(plan_one(ordinal) for ordinal in ordinals)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = tuple(executor.map(plan_one, ordinals))
    assert runtime.clocks.cache_size <= cache_size
    return dict(values)


def _planned_auxiliary_population(
    *,
    cache_size: int,
    workers: int,
    reverse: bool,
) -> dict[int, tuple[tuple[str, datetime], ...]]:
    """Plan protocol companions under varied order, worker, and cache shapes."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="aux-network-runtime-determinism",
        max_clock_cache_entries=cache_size,
    )
    planner = NetworkObservationPlanner(None, timing_runtime=runtime)
    ordinals = list(range(96))
    if reverse:
        ordinals.reverse()

    def plan_one(ordinal: int) -> tuple[int, tuple[tuple[str, datetime], ...]]:
        event = _auxiliary_protocol_event(ordinal)
        observation = planner.plan(event, set(event._sensor_hostnames_by_format))[0]
        return ordinal, observation.source_times

    if workers == 1:
        values = tuple(plan_one(ordinal) for ordinal in ordinals)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = tuple(executor.map(plan_one, ordinals))
    assert runtime.clocks.cache_size <= cache_size
    return dict(values)


@pytest.mark.parametrize("cache_size", [0, 1, 7, 128])
@pytest.mark.parametrize("workers", [1, 4])
def test_network_runtime_is_order_worker_and_cache_independent(
    cache_size: int,
    workers: int,
) -> None:
    """Sensor projection must not depend on arrival order, workers, or cache eviction."""

    reference = _planned_population(cache_size=0, workers=1, reverse=False)
    observed = _planned_population(cache_size=cache_size, workers=workers, reverse=True)

    assert observed == reference


@pytest.mark.parametrize("cache_size", [0, 1, 7])
@pytest.mark.parametrize("workers", [1, 4])
def test_auxiliary_protocol_timing_is_order_worker_and_cache_independent(
    cache_size: int,
    workers: int,
) -> None:
    """DNS, DHCP, SMTP, and NTP rows must use stateless semantic draws."""

    reference = _planned_auxiliary_population(cache_size=0, workers=1, reverse=False)
    observed = _planned_auxiliary_population(
        cache_size=cache_size,
        workers=workers,
        reverse=True,
    )

    assert observed == reference


def test_network_runtime_is_hash_seed_independent() -> None:
    """Sensor clocks and route delays must ignore Python hash randomization."""

    script = """
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import DnsContext, NtpContext
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.generation.timing import TimingRuntime
from tests.network_factories import network_plan

t0 = datetime(2026, 8, 16, 12, tzinfo=UTC)
runtime = TimingRuntime(reference_time=t0, namespace='network-hash-seed', max_clock_cache_entries=1)
planner = NetworkObservationPlanner(None, timing_runtime=runtime)
values = {}
for ordinal in reversed(range(64)):
    network = network_plan(
        src_ip='10.0.1.25', src_port=41000 + ordinal,
        dst_ip='198.51.100.40', dst_port=443, protocol='tcp', service='ssl',
        zeek_uid=f'CHashTiming{ordinal:05d}', conn_id=f'conn-hash-{ordinal}', duration=2.0,
        source_visible_start_time=t0, source_visible_close_time=t0 + timedelta(seconds=2),
        conn_state='SF', history='ShADadFf',
    )
    event = OccurrenceBuilder(
        timestamp=t0, event_type='connection',
        network=replace(network, stable_id=f'network:hash:{ordinal}'),
        dns=DnsContext(query=f'host-{ordinal}.example', answers=['198.51.100.40'], rtt=0.02),
        ntp=NtpContext(stratum=2, org_ts=t0.timestamp(), rec_ts=t0.timestamp() + 0.02),
    )
    event._sensor_hostnames_by_format = {
        name: ['hash-tap'] for name in ('zeek_conn', 'zeek_dns', 'zeek_ntp')
    }
    observation = planner.plan(event, {'zeek_conn', 'zeek_dns', 'zeek_ntp'})[0]
    values[str(ordinal)] = [
        [key, timestamp.isoformat()] for key, timestamp in observation.source_times
    ]
print(json.dumps(values, sort_keys=True))
"""
    outputs = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1]


def test_sensor_instances_own_distinct_coherent_clocks() -> None:
    """Repeated observations reuse one sensor clock while peer sensors remain distinct."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="network-source-instances",
        max_clock_cache_entries=2,
    )
    planner = NetworkObservationPlanner(None, timing_runtime=runtime)
    event = _simple_event(11, sensor_names=("core-tap", "dmz-tap"))

    first = planner.plan(event, {"zeek_conn"})
    second = planner.plan(event, {"zeek_conn"})
    first_times = {
        observation.sensor_identity: observation.source_time("zeek_conn") for observation in first
    }
    second_times = {
        observation.sensor_identity: observation.source_time("zeek_conn") for observation in second
    }

    assert first_times == second_times
    assert first_times["core-tap"] != first_times["dmz-tap"]
    assert runtime.clocks.cache_size == 2


def test_explicit_compiled_sensor_targets_do_not_require_legacy_route_metadata() -> None:
    """Compiled source targets should directly drive frozen observation identity."""

    event = _simple_event(12)
    event._sensor_hostnames_by_format = {}
    planner = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace="compiled-sensor-target"),
    )

    observations = planner.plan(
        event,
        {"zeek_conn"},
        sensor_formats={"compiled-tap.example.test": {"zeek_conn"}},
    )

    assert len(observations) == 1
    assert observations[0].sensor_identity == "compiled-tap.example.test"
    assert observations[0].visible_formats == frozenset({"zeek_conn"})
    assert observations[0].connection_uid != event.network.zeek_uid


def test_sensor_route_delays_are_right_skewed_without_grid_or_ceiling_atoms() -> None:
    """Route timing should retain a broad right tail and microsecond texture."""

    timing = NetworkSensorObservationTiming(
        profile_name="shape-probe",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=200,
        route_delay_max_us=3_500,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=0.0,
        capture_loss_min_fraction=0.0,
        capture_loss_max_fraction=0.0,
        capture_loss_max_missed_bytes=0,
    )
    runtime = TimingRuntime(reference_time=T0, namespace="network-route-shape")
    values = []
    for ordinal in range(4_096):
        observed, _close = NetworkObservationPlanner._observed_interval(
            T0,
            None,
            timing,
            "shape-tap",
            "source_side",
            f"network:route-shape:{ordinal}",
            runtime,
        )
        values.append(round((observed - T0).total_seconds() * 1_000_000))

    assert min(values) > 200
    assert max(values) < 3_500
    assert values.count(200) == values.count(3_500) == 0
    assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005
    median = statistics.median(values)
    p90 = sorted(values)[round(0.9 * (len(values) - 1))]
    assert median < 1_050
    assert p90 > median * 1.8
    bins = [0] * 8
    for value in values:
        bins[min(7, int((value - 200) / 412.5))] += 1
    assert bins[0] > bins[-1] * 10
    assert max(bins) - min(bins) > len(values) * 0.25
    summary = runtime.audit.snapshot()
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_file_durations_are_right_skewed_without_ms_or_bound_atoms() -> None:
    """Files analyzer durations should avoid flat bins, clamps, and millisecond grids."""

    runtime = TimingRuntime(reference_time=T0, namespace="network-file-duration-shape")
    planner = NetworkObservationPlanner(None, timing_runtime=runtime)
    values = []
    for ordinal in range(2_048):
        event = _protocol_event(ordinal, rich=False)
        observation = planner.plan(event, {"zeek_conn", "zeek_http", "zeek_files"})[0]
        fuid = event.protocol.primary_file_transfer.fuid
        duration = observation.source_duration(network_source_timing_key("zeek_files", fuid))
        assert duration is not None
        values.append(round(duration * 1_000_000))

    assert min(values) > 110_000
    assert max(values) < 310_000
    assert values.count(110_000) == values.count(310_000) == 0
    assert statistics.mean(values) > statistics.median(values)
    assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005
    bins = [0] * 8
    for value in values:
        bins[min(7, int((value - 110_000) / 25_000))] += 1
    assert max(bins) - min(bins) > len(values) * 0.08
    summary = runtime.audit.snapshot()
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_dns_kerberos_ntp_and_failed_durations_have_right_skew_without_atoms() -> None:
    """Canonical protocol timing should have tails, microseconds, and no clamp ceiling."""

    planner, runtime = _runtime_planner("canonical-protocol-duration-shape")
    dns_values: list[int] = []
    dns_close_slack_values: list[int] = []
    kerberos_values: list[int] = []
    ntp_values: list[int] = []
    failed_values: list[int] = []
    for ordinal in range(2_048):
        request = NetworkConnectionRequest(
            src_ip="10.0.1.25",
            src_port=40_000 + ordinal,
            dst_ip="10.0.1.53",
            dst_port=53,
            proto="udp",
            service="dns",
            time=T0 + timedelta(microseconds=ordinal),
        )
        dns_values.append(round(planner._dns_rtt_seconds(request, is_public_resolver=False) * 1e6))
        dns_close_slack_values.append(
            round(planner._dns_transport_duration_seconds(request, 0.0) * 1e6)
        )
        kerberos_values.append(round(planner._kerberos_udp_duration_seconds(request) * 1e6))
        ntp_values.append(
            round(
                planner._ntp_timing_components(
                    request,
                    median_rtt_ms=10.0,
                    rtt_sigma=0.7,
                )[0]
                * 1e6
            )
        )
        failed_values.append(
            round(
                planner._failed_transport_duration_seconds(
                    request,
                    state="S1",
                    duration=2.0,
                    sample_key="shape",
                )
                * 1e6
            )
        )

    for values, lower, upper in (
        (dns_values, 99, 250_001),
        (dns_close_slack_values, 1_037, 12_001),
        (kerberos_values, 3_000, 160_001),
        (ntp_values, 200, 300_001),
        (failed_values, 37, 500_001),
    ):
        assert min(values) > lower
        assert max(values) < upper
        assert values.count(lower) == values.count(upper) == 0
        assert statistics.mean(values) > statistics.median(values)
        assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005
        bins = [0] * 8
        width = (upper - lower) / len(bins)
        for value in values:
            bins[min(len(bins) - 1, int((value - lower) / width))] += 1
        assert max(bins) - min(bins) > len(values) * 0.10

    summary = runtime.audit.snapshot()
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_ntp_endpoint_clocks_are_instance_scoped_and_cache_independent() -> None:
    """NTP packet fields should reuse stable client/server clocks across cache shapes."""

    request = NetworkConnectionRequest(
        src_ip="10.0.1.25",
        dst_ip="129.6.15.28",
        dst_port=123,
        proto="udp",
        service="ntp",
        time=T0,
    )

    def projected(
        cache_size: int,
    ) -> tuple[tuple[datetime, datetime], tuple[datetime, datetime], tuple[datetime, datetime]]:
        runtime = TimingRuntime(
            reference_time=T0,
            namespace="ntp-instance-clocks",
            max_clock_cache_entries=cache_size,
        )
        planner = NetworkTransactionPlanner(SimpleNamespace(timing_runtime=runtime))

        def trajectory(role: str, identity: str) -> tuple[datetime, datetime]:
            return tuple(
                planner._ntp_clock_time(request, instant, role=role, identity=identity)
                for instant in (T0, T0 + timedelta(minutes=3))
            )

        client = trajectory("client", "10.0.1.25")
        server = trajectory("server", "129.6.15.28")
        peer = trajectory("server", "132.163.96.1")
        assert runtime.clocks.cache_size <= cache_size
        return client, server, peer

    uncached = projected(0)
    cached = projected(1)

    assert cached == uncached
    assert len(set(cached)) == 3


def test_auxiliary_protocol_rows_remain_inside_one_sensor_lifecycle() -> None:
    """DNS, DHCP, SMTP, and NTP observations must stay inside their transport."""

    event = _auxiliary_protocol_event(31)
    canonical_timestamp = event.timestamp
    canonical_start = event.network.started_at
    canonical_close = event.network.closed_at
    runtime = TimingRuntime(reference_time=T0, namespace="aux-protocol-lifecycle")
    formats = set(event._sensor_hostnames_by_format)
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(event, formats)[0]
    source_times = dict(observation.source_times)
    source_durations = dict(observation.source_durations)

    dns_time = source_times[network_source_timing_key("zeek_dns")]
    dns_response = source_times[network_source_timing_key("zeek_dns", "response")]
    assert observation.observed_start_time < dns_time < dns_response
    assert dns_response < observation.observed_close_time
    assert dns_response == dns_time + timedelta(
        seconds=source_durations[network_source_timing_key("zeek_dns")]
    )
    assert source_times[network_source_timing_key("zeek_dhcp")] == observation.observed_start_time
    assert (
        source_times[network_source_timing_key("zeek_dhcp", "close")]
        == observation.observed_close_time
    )
    for format_name in ("zeek_smtp", "zeek_ntp"):
        assert (
            observation.observed_start_time
            < source_times[network_source_timing_key(format_name)]
            < observation.observed_close_time
        )

    assert event.timestamp == canonical_timestamp
    assert event.network.started_at == canonical_start
    assert event.network.closed_at == canonical_close


def test_auxiliary_source_delays_are_right_skewed_without_ms_or_bound_atoms() -> None:
    """DNS, SMTP, and NTP sensor rows should retain microsecond right tails."""

    runtime = TimingRuntime(reference_time=T0, namespace="aux-source-delay-shape")
    planner = NetworkObservationPlanner(None, timing_runtime=runtime)
    values_by_format: dict[str, list[int]] = {
        "zeek_dns": [],
        "zeek_smtp": [],
        "zeek_ntp": [],
    }
    for ordinal in range(1_024):
        event = _auxiliary_protocol_event(ordinal)
        observation = planner.plan(event, set(event._sensor_hostnames_by_format))[0]
        for format_name in values_by_format:
            source_time = observation.source_time(format_name)
            assert source_time is not None
            values_by_format[format_name].append(
                round((source_time - observation.observed_start_time).total_seconds() * 1e6)
            )

    for format_name, lower, upper in (
        ("zeek_dns", 1_000, 95_000),
        ("zeek_smtp", 1_300, 180_000),
        ("zeek_ntp", 100, 120_000),
    ):
        values = values_by_format[format_name]
        assert min(values) > lower
        assert max(values) < upper
        assert values.count(lower) == values.count(upper) == 0
        assert statistics.mean(values) > statistics.median(values)
        assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005

    summary = runtime.audit.snapshot()
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_firewall_teardown_processing_is_right_skewed_without_timeout_atom() -> None:
    """ASA teardown processing should not pile up on the policy timeout boundary."""

    network = network_plan(
        src_ip="10.0.1.25",
        src_port=42_000,
        dst_ip="198.51.100.40",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CFirewallTimingShape",
        conn_id="conn-firewall-timing-shape",
        conn_state="S0",
        history="S",
        orig_bytes=0,
        resp_bytes=0,
        orig_pkts=1,
        resp_pkts=0,
        orig_ip_bytes=40,
        resp_ip_bytes=0,
        source_visible_start_time=T0,
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=replace(network, stable_id="network:firewall-shape"),
    )
    runtime = TimingRuntime(reference_time=T0, namespace="firewall-teardown-shape")
    values = []
    for ordinal in range(2_048):
        _reason, teardown = NetworkObservationPlanner._firewall_teardown_plan(
            event,
            {"cisco_asa"},
            "fw-perimeter",
            T0,
            None,
            scope=TimingScope(
                stable_id=f"network:firewall-shape:{ordinal}",
                source="fw-perimeter",
            ),
            runtime=runtime,
        )
        assert teardown is not None
        values.append(round((teardown - T0 - timedelta(seconds=30)).total_seconds() * 1e6))

    assert min(values) > 137
    assert max(values) < 18_500
    assert values.count(137) == values.count(18_500) == 0
    assert statistics.mean(values) > statistics.median(values)
    assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005
    summary = runtime.audit.snapshot()
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_protocol_rows_remain_inside_one_sensor_lifecycle() -> None:
    """TLS, HTTP, file, OCSP, and PE rows must stay within their owning flow."""

    event = _protocol_event(7)
    canonical_timestamp = event.timestamp
    canonical_start = event.network.started_at
    canonical_close = event.network.closed_at
    runtime = TimingRuntime(reference_time=T0, namespace="network-lifecycle")
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        _MIGRATED_FORMATS,
    )[0]
    source_times = dict(observation.source_times)
    source_durations = dict(observation.source_durations)
    http_fuid = event.protocol.primary_file_transfer.fuid
    ocsp_fuid = event.protocol.ocsp.id
    certificates = event.protocol.x509_chain

    conn_time = source_times["zeek_conn"]
    ssl_time = source_times["zeek_ssl"]
    http_time = source_times["zeek_http"]
    assert conn_time < ssl_time < http_time < observation.observed_close_time
    for fuid in (http_fuid, ocsp_fuid):
        file_key = network_source_timing_key("zeek_files", fuid)
        file_time = source_times[file_key]
        file_duration = source_durations[file_key]
        assert http_time < file_time < file_time + timedelta(seconds=file_duration)
        assert file_time + timedelta(seconds=file_duration) < observation.observed_close_time
    assert (
        source_times[network_source_timing_key("zeek_files", ocsp_fuid)]
        < source_times[network_source_timing_key("zeek_ocsp", ocsp_fuid)]
        < source_times[network_source_timing_key("zeek_files", ocsp_fuid)]
        + timedelta(seconds=source_durations[network_source_timing_key("zeek_files", ocsp_fuid)])
    )
    assert (
        source_times[network_source_timing_key("zeek_files", http_fuid)]
        < source_times[network_source_timing_key("zeek_pe", http_fuid)]
        < source_times[network_source_timing_key("zeek_files", http_fuid)]
        + timedelta(seconds=source_durations[network_source_timing_key("zeek_files", http_fuid)])
    )
    previous_x509 = ssl_time
    for certificate in certificates:
        file_time = source_times[network_source_timing_key("zeek_files", certificate.fuid)]
        x509_time = source_times[network_source_timing_key("zeek_x509", certificate.fuid)]
        assert ssl_time < file_time < x509_time < observation.observed_close_time
        assert previous_x509 < x509_time
        previous_x509 = x509_time

    assert event.timestamp == canonical_timestamp
    assert event.network.started_at == canonical_start
    assert event.network.closed_at == canonical_close


def test_zero_duration_direct_http_and_file_match_c009_bytes(tmp_path: Path) -> None:
    """The no-interval bridge must retain the exact supported parent direct rows."""

    event = _direct_short_http_event(0.0, 0, include_file=True)
    http_output = tmp_path / "http.json"
    files_output = tmp_path / "files.json"
    http_emitter = ZeekHttpEmitter(load_format("zeek_http"), http_output, buffer_size=1)
    files_emitter = ZeekFilesEmitter(load_format("zeek_files"), files_output, buffer_size=1)

    http_emitter.emit(event)
    files_emitter.emit(event)
    http_emitter.close()
    files_emitter.close()

    expected_http = {
        "ts": 1786881600.034384,
        "uid": "CDirect0",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 50000,
        "id.resp_h": "198.51.100.1",
        "id.resp_p": 80,
        "trans_depth": 1,
        "method": "GET",
        "host": "example.test",
        "uri": "/0",
        "version": "1.1",
        "request_body_len": 0,
        "response_body_len": 0,
        "status_code": 200,
        "status_msg": "OK",
        "resp_fuids": ["FDirect0"],
        "resp_mime_types": ["text/plain"],
    }
    expected_file = {
        "ts": 1786881600.150049,
        "fuid": "FDirect0",
        "tx_hosts": ["198.51.100.1"],
        "rx_hosts": ["10.0.0.1"],
        "conn_uids": ["CDirect0"],
        "source": "HTTP",
        "depth": 0,
        "mime_type": "text/plain",
        "duration": 0.0,
        "local_orig": True,
        "is_orig": False,
        "seen_bytes": 20,
        "missing_bytes": 0,
        "overflow_bytes": 0,
        "timedout": False,
    }
    assert http_output.read_text(encoding="utf-8") == (
        json.dumps(expected_http, separators=(",", ":")) + "\n"
    )
    assert files_output.read_text(encoding="utf-8") == (
        json.dumps(expected_file, separators=(",", ":")) + "\n"
    )


@pytest.mark.parametrize(
    ("duration", "ordinal", "expected_timestamp"),
    [
        (0.000001, 1, 1786881600.0),
        (0.000002, 2, 1786881600.000001),
    ],
)
def test_subminimum_direct_http_matches_c009_bytes(
    tmp_path: Path,
    duration: float,
    ordinal: int,
    expected_timestamp: float,
) -> None:
    """One- and two-microsecond direct HTTP rows retain exact parent behavior."""

    event = _direct_short_http_event(duration, ordinal, include_file=False)
    output = tmp_path / f"http-{ordinal}.json"
    emitter = ZeekHttpEmitter(load_format("zeek_http"), output, buffer_size=1)
    emitter.emit(event)
    emitter.close()

    expected = {
        "ts": expected_timestamp,
        "uid": f"CDirect{ordinal}",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 50_000 + ordinal,
        "id.resp_h": "198.51.100.1",
        "id.resp_p": 80,
        "trans_depth": 1,
        "method": "GET",
        "host": "example.test",
        "uri": f"/{ordinal}",
        "version": "1.1",
        "request_body_len": 0,
        "response_body_len": 0,
        "status_code": 200,
        "status_msg": "OK",
    }
    assert output.read_text(encoding="utf-8") == (
        json.dumps(expected, separators=(",", ":")) + "\n"
    )


@pytest.mark.parametrize("duration", [0.000001, 0.000002])
def test_subminimum_direct_file_uses_legal_deterministic_endpoint(
    tmp_path: Path,
    duration: float,
) -> None:
    """Bridge the c009 AttributeError while keeping the new row inside its interval.

    c009 called the removed ``file_transfer_close_margin_seconds`` helper for this
    positive microflow. That failure is the negative control this compatibility
    path intentionally replaces.
    """

    ordinal = round(duration * 1_000_000)
    event = _direct_short_http_event(
        duration,
        ordinal,
        include_file=True,
        file_duration=0.001,
    )
    outputs = (tmp_path / "first.json", tmp_path / "second.json")
    for output in outputs:
        emitter = ZeekFilesEmitter(load_format("zeek_files"), output, buffer_size=1)
        emitter.emit(event)
        emitter.close()

    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    row = json.loads(outputs[0].read_text(encoding="utf-8"))
    parent_start = event.timestamp
    parent_close = parent_start + timedelta(seconds=event.network.duration)
    assert parent_start.timestamp() <= row["ts"] <= parent_close.timestamp()
    assert row["ts"] == parent_close.timestamp()
    assert row["duration"] == 0.0
    assert row["duration"] <= event.network.duration


def test_subminimum_direct_rows_use_event_anchored_parent_interval(tmp_path: Path) -> None:
    """A stale canonical network start cannot pull direct rows outside the event interval."""

    event = _direct_short_http_event(0.000001, 5, include_file=True, file_duration=0.001)
    event.network = network_plan(
        src_ip="10.0.0.1",
        src_port=50_005,
        dst_ip="198.51.100.1",
        dst_port=80,
        protocol="tcp",
        service="http",
        zeek_uid="CDirect5",
        conn_id="conn-direct-5",
        duration=0.000001,
        orig_bytes=100,
        resp_bytes=200,
        conn_state="SF",
        history="ShADadFf",
    )
    assert event.network.started_at.year == 2024
    outputs = {
        "conn": (ZeekEmitter, "zeek_conn"),
        "http": (ZeekHttpEmitter, "zeek_http"),
        "files": (ZeekFilesEmitter, "zeek_files"),
    }
    rows: dict[str, dict[str, object]] = {}
    for name, (emitter_type, format_name) in outputs.items():
        output = tmp_path / f"{name}.json"
        emitter = emitter_type(load_format(format_name), output, buffer_size=1)
        emitter.emit(event)
        emitter.close()
        rows[name] = json.loads(output.read_text(encoding="utf-8"))

    parent_close = event.timestamp + timedelta(microseconds=1)
    assert rows["conn"]["ts"] == event.timestamp.timestamp()
    assert rows["http"]["ts"] == event.timestamp.timestamp()
    assert rows["files"]["ts"] == parent_close.timestamp()
    assert rows["files"]["duration"] == 0.0


def test_zero_duration_canonical_http_request_matches_c009_bytes(tmp_path: Path) -> None:
    """The parent canonical-request branch remains exact at a collapsed direct interval."""

    event = _direct_short_http_event(0.0, 6, include_file=False)
    event.http = replace(event.http, canonical_request_time=T0 + timedelta(microseconds=1))
    output = tmp_path / "canonical-http.json"
    emitter = ZeekHttpEmitter(load_format("zeek_http"), output, buffer_size=1)
    emitter.emit(event)
    emitter.close()

    expected = {
        "ts": 1786881600.000001,
        "uid": "CDirect6",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 50006,
        "id.resp_h": "198.51.100.1",
        "id.resp_p": 80,
        "trans_depth": 1,
        "method": "GET",
        "host": "example.test",
        "uri": "/6",
        "version": "1.1",
        "request_body_len": 0,
        "response_body_len": 0,
        "status_code": 200,
        "status_msg": "OK",
    }
    assert output.read_text(encoding="utf-8") == (
        json.dumps(expected, separators=(",", ":")) + "\n"
    )


def test_zero_duration_direct_certificate_rows_do_not_use_transfer_lookup(tmp_path: Path) -> None:
    """Certificate file IDs remain valid when no FileTransferContext owns the key."""

    certificate = X509Context(
        fuid="FCertDirectZero",
        fingerprint="c" * 40,
        certificate_subject="CN=zero.example.test",
        certificate_issuer="CN=Example Root",
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.1",
            src_port=51_000,
            dst_ip="198.51.100.2",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="CCertDirectZero",
            conn_id="conn-cert-direct-zero",
            duration=0.0,
            source_visible_start_time=T0,
            conn_state="SF",
            history="ShADadFf",
        ),
        ssl=SslContext(cert_chain_fuids=(certificate.fuid,)),
        x509=certificate,
        x509_chain=[certificate],
    )
    files_output = tmp_path / "cert-files.json"
    x509_output = tmp_path / "cert-x509.json"
    files_emitter = ZeekFilesEmitter(load_format("zeek_files"), files_output, buffer_size=1)
    x509_emitter = ZeekX509Emitter(load_format("zeek_x509"), x509_output, buffer_size=1)
    files_emitter.emit(event)
    x509_emitter.emit(event)
    files_emitter.close()
    x509_emitter.close()

    assert json.loads(files_output.read_text(encoding="utf-8"))["fuid"] == certificate.fuid
    assert json.loads(x509_output.read_text(encoding="utf-8"))["id"] == certificate.fuid


def test_zero_duration_direct_protocol_matrix_matches_c009_and_is_call_order_invariant(
    tmp_path: Path,
) -> None:
    """All migrated direct renderers retain the stateless c009 zero-flow contract."""

    emitter_specs = (
        ("conn", ZeekEmitter, "zeek_conn"),
        ("http", ZeekHttpEmitter, "zeek_http"),
        ("files", ZeekFilesEmitter, "zeek_files"),
        ("ssl", ZeekSslEmitter, "zeek_ssl"),
        ("x509", ZeekX509Emitter, "zeek_x509"),
        ("ocsp", ZeekOcspEmitter, "zeek_ocsp"),
        ("pe", ZeekPeEmitter, "zeek_pe"),
    )

    def _render(order, directory: Path) -> dict[str, Path]:
        event = _protocol_event(7)
        event.network = replace(
            event.network,
            duration=0.0,
            closed_at=event.network.started_at,
        )
        event._sensor_hostnames_by_format = {}
        outputs: dict[str, Path] = {}
        for name, emitter_type, format_name in order:
            output = directory / f"{name}.json"
            emitter = emitter_type(load_format(format_name), output, buffer_size=1)
            emitter.emit(event)
            emitter.close()
            outputs[name] = output
        assert event.source_timing is None
        return outputs

    forward = _render(emitter_specs, tmp_path / "forward")
    reverse = _render(tuple(reversed(emitter_specs)), tmp_path / "reverse")
    for name in forward:
        assert forward[name].read_bytes() == reverse[name].read_bytes()

    conn = json.loads(forward["conn"].read_text(encoding="utf-8"))
    http = json.loads(forward["http"].read_text(encoding="utf-8"))
    ssl = json.loads(forward["ssl"].read_text(encoding="utf-8"))
    files = {
        row["fuid"]: row
        for row in map(
            json.loads,
            forward["files"].read_text(encoding="utf-8").splitlines(),
        )
    }
    x509 = {
        row["id"]: row
        for row in map(
            json.loads,
            forward["x509"].read_text(encoding="utf-8").splitlines(),
        )
    }
    ocsp = json.loads(forward["ocsp"].read_text(encoding="utf-8"))
    pe = json.loads(forward["pe"].read_text(encoding="utf-8"))

    assert (conn["ts"], conn["duration"]) == (1786881600.000007, 2.455)
    assert http["ts"] == 1786881600.200007
    assert ssl["ts"] == 1786881600.066718
    assert (files["FHttpTiming000007"]["ts"], files["FHttpTiming000007"]["duration"]) == (
        1786881600.081940,
        0.2,
    )
    assert (files["FOcspTiming000007"]["ts"], files["FOcspTiming000007"]["duration"]) == (
        1786881600.131796,
        0.1,
    )
    assert files["FLeafTiming000007"]["ts"] == 1786881600.094878
    assert files["FInterTiming00007"]["ts"] == 1786881600.105204
    assert x509["FLeafTiming000007"]["ts"] == 1786881600.228614
    assert x509["FInterTiming00007"]["ts"] == 1786881600.233365
    assert ocsp["ts"] == 1786881600.271970
    assert pe["ts"] == 1786881600.249990


@pytest.mark.parametrize("duration_us", [1, 2])
@pytest.mark.parametrize("request_position", ["before", "inside", "after"])
def test_subminimum_rich_direct_protocol_matrix_uses_event_anchored_interval(
    duration_us: int,
    request_position: str,
) -> None:
    """Every rich direct row stays legal despite canonical and transport anchor drift."""

    event = _protocol_event(80 + duration_us)
    request_offsets = {
        "before": timedelta(seconds=-30),
        "inside": timedelta(microseconds=duration_us // 2),
        "after": timedelta(seconds=30),
    }
    event.http = replace(
        event.http,
        canonical_request_time=event.timestamp + request_offsets[request_position],
    )
    stale_start = datetime(2024, 1, 1, tzinfo=UTC)
    stale_close = stale_start + timedelta(microseconds=duration_us)
    event.network = replace(
        event.network,
        duration=duration_us / 1_000_000,
        started_at=stale_start,
        closed_at=stale_close,
        phase_times=(
            ("transport_start", stale_start),
            ("transport_close", stale_close),
        ),
    )
    transfer_keys = [
        network_source_timing_key("zeek_files", transfer.fuid)
        for transfer in event.protocol.file_transfers
    ]
    analyzer_keys = [
        network_source_timing_key("zeek_conn"),
        network_source_timing_key("zeek_http"),
        network_source_timing_key("zeek_ssl"),
        *transfer_keys,
        *(
            network_source_timing_key("zeek_files", certificate.fuid)
            for certificate in event.protocol.x509_chain
        ),
        *(
            network_source_timing_key("zeek_x509", certificate.fuid)
            for certificate in event.protocol.x509_chain
        ),
        network_source_timing_key("zeek_ocsp", event.protocol.ocsp.id),
        network_source_timing_key("zeek_pe", event.protocol.pe_analyses[0].id),
    ]
    parent_start = event.timestamp
    parent_close = parent_start + timedelta(microseconds=duration_us)
    duration_keys = [network_source_timing_key("zeek_conn"), *transfer_keys]

    for key in analyzer_keys:
        timestamp = compatibility_network_source_time(event, key)
        assert parent_start <= timestamp <= parent_close
    for key in duration_keys:
        timestamp = compatibility_network_source_time(event, key)
        duration = compatibility_network_source_duration(event, key)
        remaining = (parent_close - timestamp).total_seconds()
        assert duration is not None
        assert 0.0 <= duration <= remaining <= duration_us / 1_000_000
    assert (
        compatibility_network_source_duration(
            event,
            network_source_timing_key("zeek_conn"),
        )
        == event.network.duration
    )
    for key in transfer_keys:
        assert compatibility_network_source_duration(event, key) == 0.0
    expected_http = {
        "before": parent_start,
        "inside": parent_start + timedelta(microseconds=duration_us // 2),
        "after": parent_close,
    }[request_position]
    assert (
        compatibility_network_source_time(
            event,
            network_source_timing_key("zeek_http"),
        )
        == expected_http
    )
    assert event.network.started_at == stale_start
    assert event.source_timing is None


@pytest.mark.parametrize("duration_us", [0, 1, 2])
def test_short_direct_protocol_matrix_accepts_sealed_occurrences(duration_us: int) -> None:
    """Immutable canonical occurrences receive the same event-local compatibility plan."""

    event = _protocol_event(7)
    if duration_us == 0:
        event.network = replace(
            event.network,
            duration=0.0,
            closed_at=event.network.started_at,
        )
    else:
        stale_start = datetime(2024, 1, 1, tzinfo=UTC)
        stale_close = stale_start + timedelta(microseconds=duration_us)
        event.http = replace(
            event.http,
            canonical_request_time=event.timestamp + timedelta(seconds=30),
        )
        event.network = replace(
            event.network,
            duration=duration_us / 1_000_000,
            started_at=stale_start,
            closed_at=stale_close,
            phase_times=(
                ("transport_start", stale_start),
                ("transport_close", stale_close),
            ),
        )
    sealed = _seal_test_occurrence(event, duration_us)
    transfer_keys = [
        network_source_timing_key("zeek_files", transfer.fuid)
        for transfer in event.protocol.file_transfers
    ]
    time_keys = [
        network_source_timing_key("zeek_conn"),
        network_source_timing_key("zeek_http"),
        network_source_timing_key("zeek_ssl"),
        *transfer_keys,
        *(
            network_source_timing_key("zeek_files", certificate.fuid)
            for certificate in event.protocol.x509_chain
        ),
        *(
            network_source_timing_key("zeek_x509", certificate.fuid)
            for certificate in event.protocol.x509_chain
        ),
        network_source_timing_key("zeek_ocsp", event.protocol.ocsp.id),
        network_source_timing_key("zeek_pe", event.protocol.pe_analyses[0].id),
    ]
    duration_keys = [network_source_timing_key("zeek_conn"), *transfer_keys]

    mutable_times = {key: compatibility_network_source_time(event, key) for key in time_keys}
    sealed_times = {key: compatibility_network_source_time(sealed, key) for key in time_keys}
    mutable_durations = {
        key: compatibility_network_source_duration(event, key) for key in duration_keys
    }
    sealed_durations = {
        key: compatibility_network_source_duration(sealed, key) for key in duration_keys
    }

    assert sealed_times == mutable_times
    assert sealed_durations == mutable_durations
    assert event.source_timing is None
    assert sealed.source_timing is None
    if duration_us > 0:
        parent_start = event.timestamp
        parent_close = parent_start + timedelta(microseconds=duration_us)
        assert all(parent_start <= timestamp <= parent_close for timestamp in sealed_times.values())
        for key, duration in sealed_durations.items():
            assert duration is not None
            remaining = (parent_close - sealed_times[key]).total_seconds()
            assert 0.0 <= duration <= remaining <= duration_us / 1_000_000


def test_zero_duration_direct_files_preserve_c009_multirow_clamp(tmp_path: Path) -> None:
    """The files-only bridge replays sorted rows and the legacy 100us floor exactly."""

    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.1",
            src_port=51_003,
            dst_ip="198.51.100.1",
            dst_port=80,
            protocol="tcp",
            service="http",
            zeek_uid="CM3",
            conn_id="m3",
            duration=0.0,
            source_visible_start_time=T0,
            conn_state="SF",
            history="ShADadFf",
        ),
        http=HttpContext(
            method="GET",
            host="example.test",
            uri="/3",
            orig_fuids=("FA3",),
            resp_fuids=("FB3",),
        ),
        file_transfers=[
            FileTransferContext(
                fuid="FA3",
                source="HTTP",
                duration=0.2,
                seen_bytes=10,
                is_orig=True,
            ),
            FileTransferContext(
                fuid="FB3",
                source="HTTP",
                duration=0.3,
                seen_bytes=20,
                is_orig=False,
            ),
        ],
    )
    output = tmp_path / "files.json"
    emitter = ZeekFilesEmitter(load_format("zeek_files"), output, buffer_size=1)
    emitter.emit(event)
    emitter.close()

    expected = (
        {
            "ts": 1786881600.252701,
            "fuid": "FA3",
            "tx_hosts": ["10.0.0.1"],
            "rx_hosts": ["198.51.100.1"],
            "conn_uids": ["CM3"],
            "source": "HTTP",
            "depth": 0,
            "duration": 0.2,
            "local_orig": True,
            "is_orig": True,
            "seen_bytes": 10,
            "missing_bytes": 0,
            "overflow_bytes": 0,
            "timedout": False,
        },
        {
            "ts": 1786881600.252801,
            "fuid": "FB3",
            "tx_hosts": ["198.51.100.1"],
            "rx_hosts": ["10.0.0.1"],
            "conn_uids": ["CM3"],
            "source": "HTTP",
            "depth": 0,
            "duration": 0.3,
            "local_orig": True,
            "is_orig": False,
            "seen_bytes": 20,
            "missing_bytes": 0,
            "overflow_bytes": 0,
            "timedout": False,
        },
    )
    assert output.read_text(encoding="utf-8") == "".join(
        json.dumps(row, separators=(",", ":")) + "\n" for row in expected
    )


def test_output_window_uses_final_format_row_and_emitters_do_not_fallback(tmp_path: Path) -> None:
    """A format whose last frozen row reaches ``end`` is suppressed as one unit."""

    event = _protocol_event(13)
    namespace = "network-output-window"
    unbounded = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace=namespace),
    ).plan(event, _MIGRATED_FORMATS)[0]
    file_times = [
        timestamp
        for key, timestamp in unbounded.source_times
        if key == "zeek_files" or key.startswith("zeek_files:")
    ]
    output_end = max(file_times)
    bounded = NetworkObservationPlanner(
        None,
        output_end_time=output_end,
        timing_runtime=TimingRuntime(reference_time=T0, namespace=namespace),
    ).plan(event, _MIGRATED_FORMATS)[0]

    assert "zeek_files" not in bounded.visible_formats
    assert (
        max(timestamp for key, timestamp in bounded.source_times if key.startswith("zeek_files:"))
        == output_end
    )

    event.network_observations = (bounded,)
    event.network_observations_planned = True
    emitter = ZeekFilesEmitter(load_format("zeek_files"), tmp_path)
    with (
        patch.object(
            zeek_files_module,
            "direct_zeek_source_time",
            side_effect=AssertionError("frozen emitter replanned time"),
        ),
        patch.object(
            zeek_files_module,
            "direct_zeek_source_duration",
            side_effect=AssertionError("frozen emitter replanned duration"),
        ),
    ):
        emitter.emit(event)
        emitter.close()
    assert not (tmp_path / "core-tap" / "files.json").exists()


@pytest.mark.parametrize(
    ("format_name", "final_key"),
    [
        ("zeek_dns", network_source_timing_key("zeek_dns", "response")),
        ("zeek_dhcp", network_source_timing_key("zeek_dhcp", "close")),
    ],
)
def test_auxiliary_multi_phase_formats_use_final_row_for_output_admission(
    format_name: str,
    final_key: str,
) -> None:
    """Half-open output admission must include DNS responses and DHCP closes."""

    event = _auxiliary_protocol_event(37)
    formats = set(event._sensor_hostnames_by_format)
    namespace = f"aux-output-window:{format_name}"
    unbounded = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace=namespace),
    ).plan(event, formats)[0]
    output_end = unbounded.source_time(final_key)
    assert output_end is not None

    bounded = NetworkObservationPlanner(
        None,
        output_end_time=output_end,
        timing_runtime=TimingRuntime(reference_time=T0, namespace=namespace),
    ).plan(event, formats)[0]

    assert format_name not in bounded.visible_formats
    assert bounded.source_time(final_key) == output_end


def test_auxiliary_admission_uses_dns_response_and_dhcp_close() -> None:
    """Dispatcher admission should use each protocol's frozen terminal row."""

    event = _auxiliary_protocol_event(41)
    runtime = TimingRuntime(reference_time=T0, namespace="aux-admission-final-row")
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        set(event._sensor_hostnames_by_format),
    )[0]
    event.network_observations = (observation,)
    event.network_observations_planned = True
    planner = SourceTimingPlanner(timing_runtime=runtime)

    assert planner.admission_time(event, "zeek_dns") == observation.source_time(
        network_source_timing_key("zeek_dns", "response")
    )
    assert planner.admission_time(event, "zeek_dhcp") == observation.source_time(
        network_source_timing_key("zeek_dhcp", "close")
    )


def test_rendered_zeek_rows_consume_frozen_sensor_times(tmp_path: Path) -> None:
    """Migrated Zeek emitters should format the planner's exact timestamps only."""

    event = _protocol_event(17)
    runtime = TimingRuntime(reference_time=T0, namespace="network-rendered-probe")
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        _MIGRATED_FORMATS,
    )[0]
    event.network_observations = (observation,)
    event.network_observations_planned = True
    event._observed_formats = set(_MIGRATED_FORMATS)
    emitters = (
        ZeekEmitter(load_format("zeek_conn"), tmp_path),
        ZeekSslEmitter(load_format("zeek_ssl"), tmp_path),
        ZeekHttpEmitter(load_format("zeek_http"), tmp_path),
        ZeekFilesEmitter(load_format("zeek_files"), tmp_path),
        ZeekX509Emitter(load_format("zeek_x509"), tmp_path),
        ZeekOcspEmitter(load_format("zeek_ocsp"), tmp_path),
        ZeekPeEmitter(load_format("zeek_pe"), tmp_path),
    )

    with (
        patch.object(
            zeek_module,
            "direct_zeek_source_time",
            side_effect=AssertionError("conn emitter replanned time"),
        ),
        patch.object(
            zeek_module,
            "direct_zeek_source_duration",
            side_effect=AssertionError("conn emitter replanned duration"),
        ),
        patch.object(
            zeek_ssl_module,
            "direct_zeek_source_time",
            side_effect=AssertionError("ssl emitter replanned time"),
        ),
        patch.object(
            zeek_http_module,
            "direct_zeek_source_time",
            side_effect=AssertionError("http emitter replanned time"),
        ),
        patch.object(
            zeek_files_module,
            "direct_zeek_source_time",
            side_effect=AssertionError("files emitter replanned time"),
        ),
        patch.object(
            zeek_files_module,
            "direct_zeek_source_duration",
            side_effect=AssertionError("files emitter replanned duration"),
        ),
    ):
        for emitter in emitters:
            emitter.emit(event)
            emitter.close()

    sensor_dir = tmp_path / "core-tap"
    conn = json.loads((sensor_dir / "conn.json").read_text(encoding="utf-8"))
    ssl = json.loads((sensor_dir / "ssl.json").read_text(encoding="utf-8"))
    http = json.loads((sensor_dir / "http.json").read_text(encoding="utf-8"))
    files = [
        json.loads(line)
        for line in (sensor_dir / "files.json").read_text(encoding="utf-8").splitlines()
    ]
    x509 = [
        json.loads(line)
        for line in (sensor_dir / "x509.json").read_text(encoding="utf-8").splitlines()
    ]
    ocsp = json.loads((sensor_dir / "ocsp.json").read_text(encoding="utf-8"))
    pe = json.loads((sensor_dir / "pe.json").read_text(encoding="utf-8"))
    http_fuid = event.protocol.primary_file_transfer.fuid
    http_file = next(row for row in files if row["fuid"] == observation.file_id(http_fuid))

    assert conn["ts"] == pytest.approx(observation.source_time("zeek_conn").timestamp())
    assert conn["duration"] == pytest.approx(observation.source_duration("zeek_conn"))
    assert ssl["ts"] == pytest.approx(observation.source_time("zeek_ssl").timestamp())
    assert http["ts"] == pytest.approx(observation.source_time("zeek_http").timestamp())
    assert http_file["ts"] == pytest.approx(
        observation.source_time(network_source_timing_key("zeek_files", http_fuid)).timestamp()
    )
    assert http_file["duration"] == pytest.approx(
        observation.source_duration(network_source_timing_key("zeek_files", http_fuid))
    )
    for row, certificate in zip(x509, event.protocol.x509_chain, strict=True):
        assert row["ts"] == pytest.approx(
            observation.source_time(
                network_source_timing_key("zeek_x509", certificate.fuid)
            ).timestamp()
        )
    assert ocsp["ts"] == pytest.approx(
        observation.source_time(
            network_source_timing_key("zeek_ocsp", event.protocol.ocsp.id)
        ).timestamp()
    )
    assert pe["ts"] == pytest.approx(
        observation.source_time(
            network_source_timing_key("zeek_pe", event.protocol.pe_analyses[0].id)
        ).timestamp()
    )


def _planned_conn_event_data(
    event: OccurrenceBuilder,
    observations: tuple[NetworkSensorObservation, ...],
    *,
    timestamp: datetime,
    duration: float,
) -> dict[str, object]:
    """Return one deliberately hostile preprojection row with frozen sensor metadata."""

    network = event.network
    return {
        "ts": timestamp,
        "uid": network.zeek_uid,
        "id.orig_h": network.src_ip,
        "id.orig_p": network.src_port,
        "id.resp_h": network.dst_ip,
        "id.resp_p": network.dst_port,
        "proto": network.protocol,
        "service": network.service,
        "duration": duration,
        "conn_state": network.conn_state,
        "history": network.history,
        "_source_timing_key": network_source_timing_key("zeek_conn"),
        "_source_duration_key": network_source_timing_key("zeek_conn"),
        "_sensor_hostnames": [observation.sensor_identity for observation in observations],
        "_network_sensor_observations": {
            observation.sensor_identity: observation for observation in observations
        },
        "_network_observations_planned": True,
        "_canonical_network_start": network.started_at,
    }


@pytest.mark.parametrize("missing_index", [0, 1, 2])
@pytest.mark.parametrize("missing_kind", ["timestamp", "duration"])
def test_missing_frozen_key_rejects_all_sensor_output_atomically(
    tmp_path: Path,
    missing_index: int,
    missing_kind: str,
) -> None:
    """A bad first, middle, or last target must fail before render or writer creation."""

    sensor_names = ("tap-a", "tap-b", "tap-c")
    event = _simple_event(71, sensor_names=sensor_names)
    observations = list(
        NetworkObservationPlanner(
            None,
            timing_runtime=TimingRuntime(
                reference_time=T0,
                namespace=f"missing-frozen:{missing_kind}:{missing_index}",
            ),
        ).plan(event, {"zeek_conn"})
    )
    key = network_source_timing_key("zeek_conn")
    broken = observations[missing_index]
    if missing_kind == "timestamp":
        broken = replace(
            broken,
            source_times=tuple(
                (candidate, value) for candidate, value in broken.source_times if candidate != key
            ),
        )
        hostile_timestamp = T0 + timedelta(seconds=30)
        hostile_duration = event.network.duration
    else:
        broken = replace(
            broken,
            source_durations=tuple(
                (candidate, value)
                for candidate, value in broken.source_durations
                if candidate != key
            ),
        )
        hostile_timestamp = event.network.started_at
        hostile_duration = 100.0
    observations[missing_index] = broken
    emitter = ZeekEmitter(load_format("zeek_conn"), tmp_path)
    event_data = _planned_conn_event_data(
        event,
        tuple(observations),
        timestamp=hostile_timestamp,
        duration=hostile_duration,
    )

    with (
        patch.object(
            emitter,
            "_render_event",
            side_effect=AssertionError("missing-key row reached per-format rendering"),
        ) as render,
        pytest.raises(EventContractError, match=f"missing frozen source {missing_kind}"),
    ):
        emitter.emit_event(event_data)

    render.assert_not_called()
    assert emitter._writers == {}
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("missing_index", [0, 1, 2])
def test_threaded_missing_frozen_key_surfaces_without_any_sensor_output(
    tmp_path: Path,
    missing_index: int,
) -> None:
    """A threaded first, middle, or last target failure must reach the caller."""

    sensor_names = ("tap-a", "tap-b", "tap-c")
    event = _simple_event(72, sensor_names=sensor_names)
    observations = list(
        NetworkObservationPlanner(
            None,
            timing_runtime=TimingRuntime(
                reference_time=T0,
                namespace=f"threaded-missing-frozen:{missing_index}",
            ),
        ).plan(event, {"zeek_conn"})
    )
    key = network_source_timing_key("zeek_conn")
    broken = observations[missing_index]
    observations[missing_index] = replace(
        broken,
        source_times=tuple(
            (candidate, value) for candidate, value in broken.source_times if candidate != key
        ),
    )
    emitter = ZeekEmitter(load_format("zeek_conn"), tmp_path, threaded=True)
    event_data = _planned_conn_event_data(
        event,
        tuple(observations),
        timestamp=T0 + timedelta(seconds=30),
        duration=event.network.duration,
    )

    with patch.object(
        emitter,
        "_render_event",
        side_effect=AssertionError("missing-key row reached threaded rendering"),
    ) as render:
        emitter.emit_event(event_data)
        with pytest.raises(RuntimeError, match="zeek_conn emitter thread failed") as barrier:
            emitter.barrier_flush()
        assert isinstance(barrier.value.__cause__, EventContractError)
        with pytest.raises(RuntimeError, match="zeek_conn emitter thread failed") as close:
            emitter.close()
        assert isinstance(close.value.__cause__, EventContractError)

    render.assert_not_called()
    assert emitter._writers == {}
    assert list(tmp_path.iterdir()) == []


def test_threaded_failure_closes_existing_sensor_writers_before_reraising(tmp_path: Path) -> None:
    """A worker failure finalizes prior rows and removes every external-sort artifact."""

    sensor_names = ("tap-a", "tap-b", "tap-c")
    event = _simple_event(74, sensor_names=sensor_names)
    observations = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace="threaded-cleanup"),
    ).plan(event, {"zeek_conn"})
    key = network_source_timing_key("zeek_conn")
    broken_first = replace(
        observations[0],
        source_times=tuple(
            (candidate, value)
            for candidate, value in observations[0].source_times
            if candidate != key
        ),
    )
    broken_observations = (broken_first, *observations[1:])
    emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        buffer_size=1,
        threaded=True,
    )
    emitter.emit_event(
        _planned_conn_event_data(
            event,
            observations,
            timestamp=T0 + timedelta(seconds=30),
            duration=100.0,
        )
    )
    emitter.emit_event(
        _planned_conn_event_data(
            event,
            broken_observations,
            timestamp=T0 + timedelta(seconds=30),
            duration=100.0,
        )
    )

    with pytest.raises(RuntimeError, match="zeek_conn emitter thread failed") as barrier:
        emitter.barrier_flush()
    assert isinstance(barrier.value.__cause__, EventContractError)
    with pytest.raises(RuntimeError, match="zeek_conn emitter thread failed") as close:
        emitter.close()
    assert isinstance(close.value.__cause__, EventContractError)

    assert emitter.event_count == len(sensor_names)
    for observation in observations:
        output = tmp_path / observation.sensor_identity / "conn.json"
        rows = output.read_text(encoding="utf-8").splitlines()
        assert len(rows) == 1
        assert json.loads(rows[0])["ts"] == pytest.approx(observation.source_time(key).timestamp())
    assert not list(tmp_path.rglob(".conn.json.sort-*"))
    assert not list(tmp_path.rglob("*.merging"))
    assert not list(tmp_path.rglob("*.preview"))


def test_complete_frozen_keys_replace_hostile_preprojection_values_for_every_sensor(
    tmp_path: Path,
) -> None:
    """Accepted planned rows render each sensor's frozen timestamp and duration exactly."""

    event = _simple_event(73, sensor_names=("tap-a", "tap-b", "tap-c"))
    observations = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace="complete-frozen-parity"),
    ).plan(event, {"zeek_conn"})
    key = network_source_timing_key("zeek_conn")
    observations = tuple(
        replace(
            observation,
            source_durations=tuple(
                (candidate, 0.375 if candidate == key else duration)
                for candidate, duration in observation.source_durations
            ),
        )
        for observation in observations
    )
    emitter = ZeekEmitter(load_format("zeek_conn"), tmp_path)
    emitter.emit_event(
        _planned_conn_event_data(
            event,
            observations,
            timestamp=T0 + timedelta(seconds=30),
            duration=100.0,
        )
    )
    emitter.close()

    for observation in observations:
        row = json.loads(
            (tmp_path / observation.sensor_identity / "conn.json").read_text(encoding="utf-8")
        )
        assert row["ts"] == pytest.approx(observation.source_time("zeek_conn").timestamp())
        assert row["duration"] == pytest.approx(observation.source_duration("zeek_conn"))
        assert row["duration"] != pytest.approx(observation.observed_duration)
        assert row["ts"] != (T0 + timedelta(seconds=30)).timestamp()
        assert row["duration"] != 100.0


@pytest.mark.parametrize("format_name", _PHASE_TIMING_FORMATS)
def test_phase_format_runtime_ownership_requires_exact_frozen_key(format_name: str) -> None:
    """Non-transport events become runtime-owned only with a visible exact key."""

    event = _phase_timing_event(format_name)
    transport_fast_path = event.event_type == "connection"
    assert network_observation_owns_format_timing(event, format_name) is transport_fast_path

    observation = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(reference_time=T0, namespace=f"phase-owner:{format_name}"),
    ).plan(event, {format_name})[0]
    event.network_observations = (observation,)
    event.network_observations_planned = True
    exact_times = _phase_source_times(observation, format_name)
    assert exact_times
    expected_phase = observation.observed_start_time + (event.timestamp - event.network.started_at)
    expected_phase = max(observation.observed_start_time, expected_phase)
    if observation.observed_close_time is not None:
        expected_phase = min(observation.observed_close_time, expected_phase)
    assert min(exact_times) >= expected_phase
    assert network_observation_owns_format_timing(event, format_name)
    assert SourceTimingPlanner().admission_time(event, format_name) == max(exact_times)

    prefix = f"{format_name}:"
    event.network_observations = (
        replace(
            observation,
            source_times=tuple(
                (key, timestamp)
                for key, timestamp in observation.source_times
                if key != format_name and not key.startswith(prefix)
            ),
            source_durations=tuple(
                (key, duration)
                for key, duration in observation.source_durations
                if key != format_name and not key.startswith(prefix)
            ),
        ),
    )
    assert network_observation_owns_format_timing(event, format_name) is transport_fast_path


@pytest.mark.parametrize("format_name", _PHASE_TIMING_FORMATS)
@pytest.mark.parametrize("dropped", [False, True])
def test_legacy_phase_format_policy_preserves_frozen_timing_and_missingness(
    monkeypatch: pytest.MonkeyPatch,
    format_name: str,
    dropped: bool,
) -> None:
    """Legacy projection preserves loss but never reapplies delay to frozen phase rows."""

    event = _phase_timing_event(format_name)
    policy = ObservationPolicy("complete")
    decision = (
        ObservationDecision(status="dropped")
        if dropped
        else ObservationDecision(status="delayed", delay=timedelta(seconds=5))
    )
    monkeypatch.setattr(policy, "decide", lambda *_args, **_kwargs: decision)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={format_name: emitter},
        observation_policy=policy,
        timing_runtime=TimingRuntime(
            reference_time=T0,
            namespace=f"legacy-phase-policy:{format_name}:{dropped}",
        ),
    )

    dispatcher.dispatch_builder(event)

    if dropped:
        emitter.emit.assert_not_called()
        return
    emitter.emit.assert_called_once()
    projected = emitter.emit.call_args.args[0]
    observation = projected.network_observations[0]
    exact_times = _phase_source_times(observation, format_name)
    assert exact_times
    assert projected.timestamp == event.timestamp
    assert projected._source_observation_status == "visible"
    assert dispatcher.source_timing_planner.admission_time(projected, format_name) == max(
        exact_times
    )
    assert max(exact_times) <= observation.observed_close_time


@pytest.mark.parametrize("format_name", _PHASE_TIMING_FORMATS)
@pytest.mark.parametrize("dropped", [False, True])
def test_compiled_phase_format_policy_preserves_frozen_timing_and_missingness(
    monkeypatch: pytest.MonkeyPatch,
    format_name: str,
    dropped: bool,
) -> None:
    """Compiled projection keeps exact loss while suppressing duplicate collection delay."""

    event = _phase_timing_event(format_name)
    policy = ObservationPolicy("complete")
    if not dropped:
        monkeypatch.setattr(
            policy,
            "decide_projection",
            lambda *_args, **_kwargs: ObservationDecision(
                status="delayed",
                delay=timedelta(seconds=5),
            ),
        )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={format_name: emitter},
        observation_policy=policy,
        collection_deployment=_phase_source_deployment(
            format_name,
            missingness=1.0 if dropped else 0.0,
        ),
        timing_runtime=TimingRuntime(
            reference_time=T0,
            namespace=f"compiled-phase-policy:{format_name}:{dropped}",
        ),
    )
    applied_delays: list[timedelta] = []
    original_delay = dispatcher._delay_sensor_observation

    def _record_delay(
        observation: NetworkSensorObservation,
        delay: timedelta,
    ) -> NetworkSensorObservation:
        applied_delays.append(delay)
        return original_delay(observation, delay)

    monkeypatch.setattr(dispatcher, "_delay_sensor_observation", _record_delay)

    dispatcher.dispatch_builder(event)

    if dropped:
        emitter.emit.assert_not_called()
        assert applied_delays == []
        return
    emitter.emit.assert_called_once()
    assert applied_delays == [timedelta(0)]
    projected = emitter.emit.call_args.args[0]
    observation = projected.network_observations[0]
    exact_times = _phase_source_times(observation, format_name)
    assert exact_times
    assert projected.timestamp == event.timestamp
    assert projected._source_observation_status == "visible"
    assert projected._projection_envelope.observed_time == max(exact_times)
    assert max(exact_times) <= observation.observed_close_time


def test_compiled_phase_key_controls_exact_collection_window_admission() -> None:
    """A per-source half-open end rejects a phase row at its frozen timestamp."""

    format_name = "zeek_smb_mapping"
    event = _phase_timing_event(format_name, storyline_cluster_id="phase-window")
    runtime = TimingRuntime(reference_time=T0, namespace="compiled-phase-window")
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        {format_name},
    )[0]
    exact_time = max(_phase_source_times(observation, format_name))
    assert event.timestamp < exact_time
    event.network_observations = (observation,)
    event.network_observations_planned = True
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={format_name: emitter},
        collection_deployment=_phase_source_deployment(
            format_name,
            windows=(
                CollectionWindow(
                    start=event.timestamp - timedelta(seconds=1),
                    end=exact_time,
                ),
            ),
        ),
        timing_runtime=runtime,
    )

    dispatcher.dispatch_builder(event)

    emitter.emit.assert_not_called()
    assert dispatcher.source_evidence_status["phase-window"]["zeek"] == {"out_of_window": 1}


@pytest.mark.parametrize(
    (
        "format_name",
        "emitter_type",
        "filename",
        "event_type",
        "context_field",
        "phase_offset",
    ),
    [
        (
            "zeek_smb_mapping",
            ZeekSmbMappingEmitter,
            "smb_mapping.json",
            "smb_tree_connect",
            "smb_mapping",
            timedelta(milliseconds=250),
        ),
        (
            "zeek_smb_files",
            ZeekSmbFilesEmitter,
            "smb_files.json",
            "smb_file_open",
            "smb_files",
            timedelta(milliseconds=750),
        ),
        (
            "zeek_files",
            ZeekFilesEmitter,
            "files.json",
            "smb_file_read",
            "smb_file_transfer",
            timedelta(milliseconds=750),
        ),
        (
            "zeek_weird",
            ZeekWeirdEmitter,
            "weird.json",
            "connection",
            "weird",
            timedelta(milliseconds=1250),
        ),
        (
            "zeek_smb_mapping",
            ZeekSmbMappingEmitter,
            "smb_mapping.json",
            "smb_tree_connect",
            "smb_mapping",
            timedelta(milliseconds=-250),
        ),
        (
            "zeek_weird",
            ZeekWeirdEmitter,
            "weird.json",
            "connection",
            "weird",
            timedelta(milliseconds=2500),
        ),
    ],
)
def test_smb_and_weird_rows_require_frozen_source_keys_before_rendering(
    tmp_path: Path,
    format_name: str,
    emitter_type: type[SensorMultiplexEmitter],
    filename: str,
    event_type: str,
    context_field: str,
    phase_offset: timedelta,
) -> None:
    """SMB/weird production routing must never enter keyless Zeek repair."""

    network = network_plan(
        src_ip="10.0.1.25",
        src_port=44_512,
        dst_ip="10.0.2.40",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"C{format_name}",
        conn_id=f"conn-{format_name}",
        duration=2.0,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=2),
        orig_bytes=800,
        resp_bytes=2_400,
        orig_pkts=5,
        resp_pkts=7,
        orig_ip_bytes=1_000,
        resp_ip_bytes=2_680,
        conn_state="SF",
        history="ShADadFf",
    )
    smb = SmbContext(
        phase=(
            "tree_connect"
            if context_field == "smb_mapping"
            else "read"
            if context_field == "smb_file_transfer"
            else "open"
        ),
        operation="copy",
        purpose="collection",
        session_id="session-1",
        tree_id="tree-1",
        share_ref="FILE-01.finance",
        share_name="finance",
        result="success",
        share_path="reports/q3.xlsx",
    )
    transfer = (
        FileTransferContext(
            fuid="FPhaseSmbFiles0001",
            source="SMB",
            filename="q3.xlsx",
            duration=0.4,
            seen_bytes=2_400,
            total_bytes=2_400,
            is_orig=False,
        )
        if context_field == "smb_file_transfer"
        else None
    )
    event = OccurrenceBuilder(
        timestamp=T0 + phase_offset,
        event_type=event_type,
        network=replace(network, stable_id=f"network:{format_name}"),
        smb=smb if context_field.startswith("smb") else None,
        file_transfer=transfer,
        weird=(
            WeirdContext(name="bad_TCP_checksum", source="TCP")
            if context_field == "weird"
            else None
        ),
    )
    event._sensor_hostnames_by_format = {format_name: ["core-tap", "dmz-tap"]}
    canonical_timestamp = event.timestamp
    canonical_start = event.network.started_at
    runtime = TimingRuntime(reference_time=T0, namespace=f"frozen-{format_name}")
    timing_key = network_source_timing_key(
        format_name,
        transfer.fuid if transfer is not None else None,
    )
    observations = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        {format_name},
    )
    for observation in observations:
        expected_time = observation.observed_start_time + phase_offset
        expected_time = max(observation.observed_start_time, expected_time)
        if observation.observed_close_time is not None:
            expected_time = min(observation.observed_close_time, expected_time)
        source_time = observation.source_time(timing_key)
        if transfer is None:
            assert source_time == expected_time
        else:
            assert source_time is not None
            assert expected_time <= source_time <= observation.observed_close_time
            source_duration = observation.source_duration(timing_key)
            assert source_duration is not None
            assert (
                0.0
                <= source_duration
                <= (observation.observed_close_time - source_time).total_seconds()
            )
    event.network_observations = observations
    event.network_observations_planned = True
    event._observed_formats = {format_name}

    original_apply = SensorMultiplexEmitter._apply_sensor_observation

    def _reject_keyless_repair(
        self,
        render_data,
        planned_observation,
        planned_canonical_start,
        source_timing_key=None,
        source_duration_key=None,
        source_duration_field="duration",
    ):
        assert source_timing_key == timing_key
        assert planned_observation.source_time(source_timing_key) is not None
        return original_apply(
            self,
            render_data,
            planned_observation,
            planned_canonical_start,
            source_timing_key,
            source_duration_key,
            source_duration_field,
        )

    emitter = emitter_type(load_format(format_name), tmp_path)
    with patch.object(
        SensorMultiplexEmitter,
        "_apply_sensor_observation",
        _reject_keyless_repair,
    ):
        emitter.emit(event)
        emitter.close()

    for observation in observations:
        row = json.loads(
            (tmp_path / observation.sensor_identity / filename).read_text(encoding="utf-8")
        )
        assert row["ts"] == pytest.approx(observation.source_time(timing_key).timestamp())
        if transfer is not None:
            assert row["duration"] == pytest.approx(observation.source_duration(timing_key))
    assert event.timestamp == canonical_timestamp
    assert event.network.started_at == canonical_start


def test_constraint_repairs_have_interior_microsecond_slack_without_saturation() -> None:
    """Constraint repair cohorts should not pile up on hard bounds or ms residues."""

    runtime = TimingRuntime(reference_time=T0, namespace="constraint-repair-shape")
    lower = T0 + timedelta(milliseconds=10)
    upper = T0 + timedelta(milliseconds=35)
    values = []
    for ordinal in range(2_048):
        graph = TemporalConstraintGraph(
            timing_runtime=runtime,
            scope=TimingScope(stable_id=f"constraint-repair:{ordinal}"),
        )
        graph.add_node("row", T0, not_before=lower, not_after=upper)
        values.append(round((graph.resolved_time("row") - lower).total_seconds() * 1_000_000))

    assert min(values) > 0
    assert max(values) < 25_000
    assert values.count(0) == values.count(25_000) == 0
    assert sum(value % 1_000 == 0 for value in values) / len(values) < 0.005
    summary = runtime.audit.snapshot()
    assert summary.total_repairs == len(values)
    assert summary.total_saturations / max(1, summary.total_samples) < 0.005


def test_migrated_network_timing_has_no_module_planners_or_direct_duration_rng() -> None:
    """Policy guard migrated emitters and duration helpers against ownership regressions."""

    emitter_modules = (
        zeek_base_module,
        zeek_module,
        zeek_http_module,
        zeek_ssl_module,
        zeek_files_module,
        zeek_x509_module,
        zeek_ocsp_module,
        zeek_pe_module,
        zeek_smb_module,
        zeek_weird_module,
    )
    for module in emitter_modules:
        source = inspect.getsource(module)
        assert "SourceTimingPlanner" not in source
        assert "_SOURCE_TIMING =" not in source
        assert ".record_source_time(" not in source

    for helper in (
        NetworkTransactionPlanner._tls_floor_slack_seconds,
        NetworkTransactionPlanner._tls_completed_extension_seconds,
        NetworkTransactionPlanner._http_floor_slack_seconds,
        NetworkTransactionPlanner._http_default_duration_seconds,
    ):
        assert "rng." not in inspect.getsource(helper)
    planner_source = inspect.getsource(NetworkTransactionPlanner.execute)
    for forbidden in (
        "duration = rng.uniform",
        "duration * rng.uniform",
        "_jitter_default_connection_duration",
    ):
        assert forbidden not in planner_source
    assert "uniform(0.0, 0.5)" not in inspect.getsource(
        generator_module.ActivityGenerator._attach_ssl_context
    )
    observation_source = inspect.getsource(NetworkObservationPlanner._observed_traffic)
    assert "rng.random()" in observation_source
    attach_source = inspect.getsource(generator_module._attach_http_file_transfers)
    assert "http_request_file_transfer_parent_duration" not in attach_source
    assert "http_response_file_transfer_parent_duration" not in attach_source
    assert ".uniform(0.05, 0.55)" not in attach_source


def test_admission_time_uses_last_frozen_row_for_multirow_formats() -> None:
    """Format admission should account for every row a multiplex emitter will render."""

    event = _protocol_event(23)
    runtime = TimingRuntime(reference_time=T0, namespace="network-admission-final-row")
    observation = NetworkObservationPlanner(None, timing_runtime=runtime).plan(
        event,
        _MIGRATED_FORMATS,
    )[0]
    event.network_observations = (observation,)
    event.network_observations_planned = True
    expected = max(
        timestamp for key, timestamp in observation.source_times if key.startswith("zeek_files:")
    )

    assert (
        SourceTimingPlanner(timing_runtime=runtime).admission_time(event, "zeek_files") == expected
    )
