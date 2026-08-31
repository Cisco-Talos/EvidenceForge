# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production dispatch tests for exact compiled collection projections."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.collection_policy import (
    CollectionCapability,
    ProjectionRole,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.contexts import HostContext, ProcessContext, SyslogContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, ThreadIdentity
from evidenceforge.events.observation import ObservationDecision, ObservationPolicy
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.source_timing import SourceTimingPlan, ecar_flow_render_key
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import NetworkConfig, NetworkSegment, NetworkSensor, System
from tests.network_factories import network_plan

_TIME = datetime(2026, 8, 16, 12, tzinfo=UTC)


def _host(hostname: str, ip: str, *, os_category: str = "windows") -> HostContext:
    return HostContext(
        hostname=hostname,
        fqdn=f"{hostname.casefold()}.example.test",
        ip=ip,
        os="Windows 11" if os_category == "windows" else "Ubuntu 24.04",
        os_category=os_category,
        system_type="workstation" if os_category == "windows" else "server",
    )


def _source(
    source_instance: str,
    hostname: str,
    family: str,
    source_format: str,
    capabilities: CollectionCapability,
    *,
    missingness: float = 0.0,
    enabled: bool = True,
) -> SourceInstanceDeployment:
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=source_instance,
            hostname=hostname,
            family=family,
        ),
        formats=(source_format,),
        policy=SourceCollectionPolicy(
            enabled=enabled,
            capabilities=capabilities,
            missingness=missingness,
        ),
    )


def _connection(src: HostContext, dst: HostContext | None = None) -> OccurrenceBuilder:
    return OccurrenceBuilder(
        timestamp=_TIME,
        event_type="connection",
        src_host=src,
        dst_host=dst,
        network=network_plan(
            src_ip=src.ip,
            src_port=51000,
            dst_ip=dst.ip if dst is not None else "198.51.100.20",
            dst_port=443,
            protocol="tcp",
            zeek_uid="CcollectionProjection",
            source_visible_start_time=_TIME,
            duration=1.0,
        ),
    )


def _process_identity(host: HostContext, pid: int) -> ProcessIdentity:
    """Return explicit process identity for dispatcher-boundary tests."""

    object_id = f"process-{host.hostname}-{pid}-{_TIME.isoformat()}"
    return ProcessIdentity(
        hostname=host.hostname,
        object_id=object_id,
        pid=pid,
        parent_pid=4,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        principal="EXAMPLE\\analyst",
        logon_id="0x1234",
        started_at=_TIME,
        lifecycle_group_id=f"lifecycle-{object_id}",
        primary_thread=ThreadIdentity(
            hostname=host.hostname,
            process_object_id=object_id,
            pid=pid,
            tid=((pid + 3) // 4) * 4,
            object_id=f"thread-{object_id}-{((pid + 3) // 4) * 4}",
            started_at=_TIME,
            kind="primary",
        ),
    )


def test_compiled_dispatch_executes_projection_stages_in_contract_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "syslog:linux-01",
                "linux-01",
                "syslog",
                "syslog",
                CollectionCapability.PROCESS
                | CollectionCapability.AUTHENTICATION
                | CollectionCapability.SESSION
                | CollectionCapability.FILE
                | CollectionCapability.SERVICE
                | CollectionCapability.TASK
                | CollectionCapability.SSH,
            ),
        )
    )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"syslog": emitter},
        collection_deployment=deployment,
    )
    stage_names = (
        "_build_projection_targets",
        "_apply_deployment_admission",
        "_apply_projection_topology",
        "_apply_projection_missingness",
        "_finalize_projection_timing",
        "_render_projection_targets",
    )
    calls: list[str] = []
    for stage_name in stage_names:
        original = getattr(dispatcher, stage_name)

        def spy(*args: object, _name: str = stage_name, _original=original, **kwargs: object):
            calls.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(dispatcher, stage_name, spy)

    event = OccurrenceBuilder(
        timestamp=_TIME,
        event_type="syslog",
        src_host=_host("LINUX-01", "10.0.0.10", os_category="linux"),
        syslog=SyslogContext(
            app_name="systemd",
            pid=1,
            facility=3,
            severity=6,
            message="collection stage order",
        ),
    )
    dispatcher.dispatch_builder(event)

    assert calls == list(stage_names)
    projected = emitter.emit.call_args.args[0]
    assert projected._projection_envelope.source.source_instance == "syslog:linux-01"
    assert projected._projection_envelope.observed_time is not None


def test_ecar_endpoint_flow_roles_admit_only_the_deployed_side() -> None:
    src = _host("SRC-01", "10.0.0.10")
    dst = _host("DST-01", "10.0.0.20")
    capabilities = CollectionCapability.NETWORK | CollectionCapability.SOURCE_ENDPOINT
    deployment = CompiledCollectionDeployment(
        (
            _source("ecar:src-01", "src-01", "ecar", "ecar", capabilities),
            _source(
                "ecar:dst-01",
                "dst-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.DESTINATION_ENDPOINT,
                enabled=False,
            ),
        )
    )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": emitter},
        collection_deployment=deployment,
    )

    dispatcher.dispatch_builder(_connection(src, dst))

    emitter.emit.assert_called_once()
    envelope = emitter.emit.call_args.args[0]._projection_envelope
    assert envelope.role is ProjectionRole.SOURCE_ENDPOINT
    assert envelope.source.source_instance == "ecar:src-01"


def test_ecar_endpoint_targets_receive_isolated_finalized_plans() -> None:
    src = _host("SRC-01", "10.0.0.10")
    dst = _host("DST-01", "10.0.0.20")
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.SOURCE_ENDPOINT,
            ),
            _source(
                "ecar:dst-01",
                "dst-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.DESTINATION_ENDPOINT,
            ),
        )
    )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": emitter},
        collection_deployment=deployment,
    )

    canonical_plan = SourceTimingPlan(
        canonical_timestamp=_TIME,
        observation_delays={"canonical.delay": timedelta(milliseconds=3)},
        source_times={"canonical.source": _TIME + timedelta(milliseconds=4)},
        finalized_times={"canonical.finalized": _TIME + timedelta(milliseconds=5)},
        finalized_flags={"canonical.flag": True},
    )
    builder = _connection(src, dst)
    builder.source_timing = canonical_plan
    canonical_dicts = {
        field_name: dict(getattr(canonical_plan, field_name))
        for field_name in (
            "observation_delays",
            "source_times",
            "finalized_times",
            "finalized_flags",
        )
    }

    dispatcher.dispatch_builder(builder)

    projected = [call.args[0] for call in emitter.emit.call_args_list]
    assert len(projected) == 2
    assert projected[0].source_timing is not projected[1].source_timing
    for event in projected:
        envelope = event._projection_envelope
        assert envelope is not None
        if envelope.role is ProjectionRole.SOURCE_ENDPOINT:
            key = ecar_flow_render_key("outbound", src.hostname)
        else:
            key = ecar_flow_render_key("inbound", dst.hostname)
        assert envelope.observed_time == event.source_timing.finalized_times[key]
        assert {
            candidate
            for candidate in event.source_timing.finalized_times
            if candidate.startswith("ecar.flow.")
        } == {key}
    mutations = {
        "observation_delays": timedelta(seconds=1),
        "source_times": _TIME + timedelta(seconds=1),
        "finalized_times": _TIME + timedelta(seconds=2),
        "finalized_flags": False,
    }
    for field_name, mutation in mutations.items():
        first = getattr(projected[0].source_timing, field_name)
        second = getattr(projected[1].source_timing, field_name)
        assert first is not second
        first["projection.mutation"] = mutation
        assert "projection.mutation" not in second
        assert getattr(canonical_plan, field_name) == canonical_dicts[field_name]


def test_migrated_process_observation_delay_changes_visibility_not_canonical_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collection delay cannot mutate a runtime-owned PROCESS occurrence."""

    host = _host("SRC-01", "10.0.0.10")
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.PROCESS,
            ),
        )
    )
    policy = ObservationPolicy("complete")
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
        state_manager=StateManager(),
        emitters={"ecar": emitter},
        observation_policy=policy,
        collection_deployment=deployment,
    )
    event = OccurrenceBuilder(
        timestamp=_TIME,
        event_type="process_create",
        src_host=host,
        process=ProcessContext(
            pid=4_242,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            username="EXAMPLE\\analyst",
            start_time=_TIME,
        ),
        identity_plan=EventIdentityPlan(subject=_process_identity(host, 4_242)),
    )

    dispatcher.dispatch_builder(event)

    projected = emitter.emit.call_args.args[0]
    assert projected.timestamp == _TIME
    assert projected.source_timing.canonical_timestamp == _TIME
    assert projected._source_observation_status == "visible"
    assert _TIME < projected._projection_envelope.observed_time < _TIME + timedelta(seconds=1)


def test_runtime_final_process_time_controls_output_window_admission() -> None:
    """A canonical in-window PROCESS row is omitted when its finalized row is outside."""

    host = _host("SRC-01", "10.0.0.10")
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.PROCESS,
            ),
        )
    )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=StateManager(),
        emitters={"ecar": emitter},
        collection_deployment=deployment,
        output_start_time=_TIME - timedelta(seconds=1),
        output_end_time=_TIME + timedelta(milliseconds=1),
    )

    event = OccurrenceBuilder(
        timestamp=_TIME,
        event_type="process_create",
        src_host=host,
        process=ProcessContext(
            pid=4_242,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            username="EXAMPLE\\analyst",
            start_time=_TIME,
        ),
        identity_plan=EventIdentityPlan(subject=_process_identity(host, 4_242)),
        storyline_cluster_id="timing-window",
    )
    dispatcher.dispatch_builder(event)

    emitter.emit.assert_not_called()
    assert dispatcher.source_evidence_status["timing-window"]["ecar"] == {"out_of_window": 1}


def test_real_ecar_emitter_renders_only_the_admitted_endpoint(tmp_path) -> None:
    """A frozen endpoint role prevents one emitter call from leaking its peer row."""

    src = _host("SRC-01", "10.0.0.10")
    dst = _host("DST-01", "10.0.0.20")
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.SOURCE_ENDPOINT,
            ),
            _source(
                "ecar:dst-01",
                "dst-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.DESTINATION_ENDPOINT,
                enabled=False,
            ),
        )
    )
    format_def = MagicMock()
    format_def.name = "ecar"
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"
    emitter = EcarEmitter(format_def, tmp_path / "ecar", threaded=False)
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": emitter},
        collection_deployment=deployment,
    )

    dispatcher.dispatch_builder(_connection(src, dst))
    emitter.close()

    source_path = tmp_path / "ecar" / "src-01.example.test" / "ecar.json"
    destination_path = tmp_path / "ecar" / "dst-01.example.test" / "ecar.json"
    rows = [json.loads(line) for line in source_path.read_text(encoding="utf-8").splitlines()]
    assert [row["properties"]["direction"] for row in rows] == ["OUTBOUND"]
    assert not destination_path.exists()


def test_complete_profile_ecar_split_preserves_legacy_bytes(tmp_path) -> None:
    """Exact endpoint fan-out keeps the complete-profile renderer byte-identical."""

    src = _host("SRC-01", "10.0.0.10")
    dst = _host("DST-01", "10.0.0.20")
    format_def = MagicMock()
    format_def.name = "ecar"
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"

    legacy_emitter = EcarEmitter(format_def, tmp_path / "legacy", threaded=False)
    legacy = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": legacy_emitter},
    )
    legacy.dispatch_builder(_connection(src, dst))
    legacy_emitter.close()

    compiled_emitter = EcarEmitter(format_def, tmp_path / "compiled", threaded=False)
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK
                | CollectionCapability.SOURCE_ENDPOINT
                | CollectionCapability.DESTINATION_ENDPOINT
                | CollectionCapability.COHERENT_ACTOR,
            ),
            _source(
                "ecar:dst-01",
                "dst-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK
                | CollectionCapability.SOURCE_ENDPOINT
                | CollectionCapability.DESTINATION_ENDPOINT
                | CollectionCapability.COHERENT_ACTOR,
            ),
        )
    )
    compiled = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": compiled_emitter},
        collection_deployment=deployment,
    )
    compiled.dispatch_builder(_connection(src, dst))
    compiled_emitter.close()

    legacy_rows = {
        path.relative_to(tmp_path / "legacy"): path.read_bytes()
        for path in (tmp_path / "legacy").rglob("*.json")
    }
    compiled_rows = {
        path.relative_to(tmp_path / "compiled"): path.read_bytes()
        for path in (tmp_path / "compiled").rglob("*.json")
    }
    assert compiled_rows == legacy_rows


def test_optional_actor_capability_does_not_block_required_projection() -> None:
    src = _host("SRC-01", "10.0.0.10")
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "ecar:src-01",
                "src-01",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK
                | CollectionCapability.PROCESS
                | CollectionCapability.SOURCE_ENDPOINT,
            ),
        )
    )
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"ecar": emitter},
        collection_deployment=deployment,
    )
    event = _connection(src)
    event.process = ProcessContext(
        pid=456,
        parent_pid=123,
        image=r"C:\Program Files\Browser\browser.exe",
        command_line="browser.exe",
        username="analyst",
        start_time=_TIME,
    )

    dispatcher.dispatch_builder(event)

    emitter.emit.assert_called_once()
    envelope = emitter.emit.call_args.args[0]._projection_envelope
    assert envelope.admitted
    assert envelope.requested_capabilities.covers(
        CollectionCapability.NETWORK | CollectionCapability.SOURCE_ENDPOINT
    )
    assert not envelope.effective_capabilities.covers(CollectionCapability.COHERENT_ACTOR)


def test_two_exact_sensors_apply_divergent_policy_without_host_family_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = System(
        hostname="SRC-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    sensors = [
        NetworkSensor(
            type="network",
            name="TAP-A",
            hostname="sensor-a.example.test",
            monitoring_segments=["lan"],
            log_formats=["zeek_conn"],
        ),
        NetworkSensor(
            type="network",
            name="TAP-B",
            hostname="sensor-b.example.test",
            monitoring_segments=["lan"],
            log_formats=["zeek_conn"],
        ),
    ]
    visibility = NetworkVisibilityEngine(
        NetworkConfig(
            segments=[
                NetworkSegment(
                    name="lan",
                    cidr="10.0.0.0/24",
                    exposure="internal",
                )
            ],
            sensors=sensors,
        ),
        [system],
    )
    deployment = CompiledCollectionDeployment(
        (
            _source(
                "zeek:tap-a",
                "sensor-a.example.test",
                "zeek",
                "zeek_conn",
                CollectionCapability.NETWORK,
            ),
            _source(
                "zeek:tap-b",
                "sensor-b.example.test",
                "zeek",
                "zeek_conn",
                CollectionCapability.NETWORK,
                missingness=1.0,
            ),
        )
    )

    def reject_scan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("hot projection admission scanned a broad deployment bucket")

    monkeypatch.setattr(CompiledCollectionDeployment, "iter_host_family", reject_scan)
    monkeypatch.setattr(CompiledCollectionDeployment, "iter_format", reject_scan)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"zeek_conn": emitter},
        visibility_engine=visibility,
        collection_deployment=deployment,
    )

    dispatcher.dispatch_builder(_connection(_host("SRC-01", "10.0.0.10")))

    emitter.emit.assert_called_once()
    projected = emitter.emit.call_args.args[0]
    assert projected._projection_envelope.source.source_instance == "zeek:tap-a"
    assert [item.sensor_identity for item in projected.network_observations] == [
        "sensor-a.example.test"
    ]
    assert deployment.exact_lookup_candidates("zeek:tap-a") == 1
    assert deployment.exact_lookup_candidates("zeek:tap-b") == 1


def test_exact_sensor_delays_preserve_canonical_time_and_sensor_envelopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = System(
        hostname="SRC-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    sensors = [
        NetworkSensor(
            type="network",
            name=name,
            hostname=hostname,
            monitoring_segments=["lan"],
            log_formats=["zeek_conn"],
        )
        for name, hostname in (
            ("TAP-A", "sensor-a.example.test"),
            ("TAP-B", "sensor-b.example.test"),
        )
    ]
    visibility = NetworkVisibilityEngine(
        NetworkConfig(
            segments=[NetworkSegment(name="lan", cidr="10.0.0.0/24", exposure="internal")],
            sensors=sensors,
        ),
        [system],
    )
    deployment = CompiledCollectionDeployment(
        tuple(
            _source(
                f"zeek:tap-{suffix}",
                f"sensor-{suffix}.example.test",
                "zeek",
                "zeek_conn",
                CollectionCapability.NETWORK,
            )
            for suffix in ("a", "b")
        )
    )
    policy = ObservationPolicy("complete")

    def decide_projection(
        _format_name: str,
        _event: object,
        *,
        source_instance: str,
        **_kwargs: object,
    ) -> ObservationDecision:
        seconds = 1 if source_instance == "zeek:tap-a" else 2
        return ObservationDecision(status="delayed", delay=timedelta(seconds=seconds))

    monkeypatch.setattr(policy, "decide_projection", decide_projection)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"zeek_conn": emitter},
        visibility_engine=visibility,
        observation_policy=policy,
        collection_deployment=deployment,
    )

    canonical_event = _connection(_host("SRC-01", "10.0.0.10"))
    identifiers = dispatcher.dispatch_builder(canonical_event)

    projected = {
        call.args[0]._projection_envelope.source.source_instance: call.args[0]
        for call in emitter.emit.call_args_list
    }
    assert set(projected) == {"zeek:tap-a", "zeek:tap-b"}
    # Migrated network observations retain canonical occurrence time. Collection
    # policy controls visibility only; the final per-sensor source time is frozen
    # in the projection envelope and NetworkSensorObservation below.
    assert projected["zeek:tap-a"].timestamp == _TIME
    assert projected["zeek:tap-b"].timestamp == _TIME
    assert projected["zeek:tap-a"].source_timing is not projected["zeek:tap-b"].source_timing
    assert (
        identifiers["zeek_conn"] == projected["zeek:tap-a"].network_observations[0].connection_uid
    )
    cached = dispatcher.network_observations_for("CcollectionProjection")
    assert {observation.sensor_identity: observation.connection_uid for observation in cached} == {
        event.network_observations[0].sensor_identity: event.network_observations[0].connection_uid
        for event in projected.values()
    }
    for event in projected.values():
        assert len(event.network_observations) == 1
        assert (
            event._projection_envelope.observed_time
            == event.network_observations[0].observed_start_time
        )

    # WFP is an endpoint companion over the same canonical plan. Its dispatch has
    # no sensor target and must not erase the transport observation before an
    # application-layer child (SMB/HTTP/etc.) consumes that exact sensor identity.
    emitter.can_handle.side_effect = lambda event: event.event_type == "connection"
    dispatcher.dispatch_builder(
        OccurrenceBuilder(
            timestamp=_TIME,
            event_type="wfp_connection",
            src_host=_host("SRC-01", "10.0.0.10"),
            network=canonical_event.network,
        )
    )
    assert dispatcher.network_observations_for("CcollectionProjection") == cached


def test_exact_source_reads_are_identical_across_worker_counts() -> None:
    """Immutable exact lookups do not depend on concurrent reader scheduling."""

    deployment = CompiledCollectionDeployment(
        tuple(
            _source(
                f"ecar:host-{index:04d}",
                f"host-{index:04d}",
                "ecar",
                "ecar",
                CollectionCapability.NETWORK | CollectionCapability.SOURCE_ENDPOINT,
            )
            for index in range(1_000)
        )
    )
    source_ids = tuple(f"ecar:host-{index:04d}" for index in range(1_000))

    def lookup(source_id: str) -> tuple[str, str]:
        source = deployment.source_by_instance(source_id)
        assert source is not None
        return source.identity.source_instance, source.identity.hostname

    with ThreadPoolExecutor(max_workers=1) as single:
        one_worker = tuple(single.map(lookup, source_ids))
    with ThreadPoolExecutor(max_workers=4) as four:
        four_workers = tuple(four.map(lookup, source_ids))

    assert one_worker == four_workers


def test_source_compilation_digest_is_hash_seed_independent() -> None:
    """Catalog/source ordering and digest do not depend on interpreter hash tables."""

    script = """
import json
from pathlib import Path
import yaml
from evidenceforge.generation.source_deployment_compiler import compile_scenario_source_deployment
from evidenceforge.models.scenario import Scenario

payload = yaml.safe_load(Path('tests/fixtures/scenarios/minimal.yaml').read_text())
scenario = Scenario.model_validate(payload)
result = compile_scenario_source_deployment(scenario)
print(json.dumps({'digest': result.digest, 'sources': result.source_instances}, sort_keys=True))
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
