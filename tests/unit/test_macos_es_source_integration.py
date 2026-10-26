# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented complete facts exercise activation and normal native source routing."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.collection_policy import (
    CollectionCapability,
    CollectionWindow,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.actions.posix_process import process_fork_occurrence
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.emitters.macos_endpoint_security import MacosEndpointSecurityEmitter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.macos_es_source import (
    macos_es_source_instance,
    prepared_macos_es_fork_publication,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_source_profile import _setup
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_native_sink_publication import _prepare


@pytest.mark.parametrize("native", [False, True])
def test_engine_activates_same_canonical_collector_independent_of_output(
    tmp_path: Path, native: bool
) -> None:
    scenario = _scenario()
    scenario.output.logs = [{"format": "macos_endpoint_security" if native else "ecar"}]
    engine = GenerationEngine(scenario, tmp_path)
    try:
        engine._initialize()
        pid = engine._system_pids["MAC-01"]["eslogger"]
        collector = engine.state_manager.get_process_identity("MAC-01", pid)
        assert collector.image == "/usr/bin/eslogger"
        assert collector.arguments == ("/usr/bin/eslogger", "fork", "exec", "exit")
        assert collector.credentials.effective_uid == 0
        assert collector.parent_pid == 1
        assert collector.executable_version is not None
        source = engine.initialize_macos_es_source(collector)
        assert source.connection().next_delivery == 0
        assert source.coverage.known_from == engine.warmup_start_time
        assert source.coverage.known_until == engine.end_time
        assert source.connection().process.pid == pid
        # Rebinding is idempotent and allocates no process, counter or lifecycle.
        before = engine.state_manager.materialization_digest()
        assert engine.initialize_macos_es_source(collector).connection() == source.connection()
        assert engine.state_manager.materialization_digest() == before
        if native:
            assert isinstance(
                engine.emitters["macos_endpoint_security"], MacosEndpointSecurityEmitter
            )
            assert (
                engine.source_deployment_compilation.deployment.ordinal_for_instance(
                    "macos_endpoint_security:mac-01"
                )
                is not None
            )
    finally:
        for emitter in engine.emitters.values():
            emitter.close()


def _routed(
    tmp_path: Path, *, exported: bool = True, complete: bool = True, known_stdio: bool = False
) -> tuple:
    source, system, collector, prior, _, _, artifacts = _setup()
    state = source.owner.state
    start = source.coverage.known_from + timedelta(seconds=1)
    birth = state.plan_process_materialization(
        system=prior.hostname,
        parent_pid=prior.pid,
        image=prior.image,
        command_line=prior.command_line,
        username=prior.principal,
        integrity_level="Medium",
        os_category="macos",
        start_time=start,
        credentials=prior.credentials,
        new_posix_session=True,
        executable_version=prior.executable_version,
        image_security=prior.image_security if complete else None,
        responsibility=ProcessResponsibility(None),
        macos_terminal="absent",
        macos_standard_io="null" if known_stdio else None,
    )
    state.materialize_process(birth)
    parent = birth.identity
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=start + timedelta(seconds=1)).identity
    cohort = builder.seal()
    output = MacosEndpointSecurityEmitter(load_format("macos_endpoint_security"), tmp_path)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    dispatcher = EventDispatcher(
        state,
        {"macos_endpoint_security": output} if exported else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.local_artifact_registry = artifacts
    dispatcher.es_collectors = source.owner.collectors
    host = HostContext(
        hostname=system.hostname,
        ip=system.ip,
        os=system.os,
        os_category="macos",
        system_type=system.type,
    )
    event = process_fork_occurrence(host=host, parent=parent, child=child, integrity_level="Medium")
    return source, dispatcher, output, cohort, event, collector, parent, child


@pytest.mark.parametrize("exported", [False, True])
def test_router_publishes_selected_fork_and_filtered_counters_once(
    tmp_path: Path, exported: bool
) -> None:
    source, dispatcher, output, cohort, event, collector, parent, child = _routed(
        tmp_path, exported=exported
    )
    dispatcher.storyline_cluster_id = "invented-native-fork"
    # Exercise the production caller rather than binding a test-native sink.
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert source.connection().next_delivery == 1
    assert dispatcher.source_evidence_status["invented-native-fork"]["macos_endpoint_security"] == {
        "visible" if exported else "filtered": 1
    }
    assert dispatcher.state_manager.get_process_identity(child.hostname, child.pid) == child
    dispatcher.assert_exact_projection_recoveries_drained()
    output.close()
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(exported)
    if exported:
        records = [
            decode_endpoint_security_record(line) for line in paths[0].read_text().splitlines()
        ]
        assert len(records) == 1 and records[0].version == 11 and records[0].event_type == 11
        assert records[0].process.audit_token.pid == parent.pid
        assert records[0].event.fork.child.audit_token.pid == child.pid


def test_native_preparation_failure_releases_delivery_and_preserves_state(tmp_path: Path) -> None:
    source, dispatcher, output, cohort, event, _, _, child = _routed(tmp_path)
    before = dispatcher.state_manager.materialization_digest()
    with pytest.raises(RuntimeError, match="injected"):
        with prepared_macos_es_fork_publication(dispatcher, cohort, event) as native:
            assert native is not None
            raise RuntimeError("injected caller failure before exact preparation")
    assert source.connection().next_delivery == 0
    assert dispatcher.state_manager.materialization_digest() == before
    assert dispatcher.state_manager.get_process(child.hostname, child.pid) is None
    assert source.owner.collectors.snapshot_with_membership()
    output.close()


@pytest.mark.parametrize("exported", [False, True])
def test_incomplete_fork_never_publishes_padded_native_records(
    tmp_path: Path, exported: bool
) -> None:
    source, dispatcher, output, cohort, event, _, _, _ = _routed(
        tmp_path, exported=exported, complete=False
    )
    before = dispatcher.state_manager.materialization_digest()
    if exported:
        with pytest.raises(StateError, match="complete static signing"):
            with prepared_macos_es_fork_publication(dispatcher, cohort, event):
                pytest.fail("incomplete fork was admitted")
    else:
        with prepared_macos_es_fork_publication(dispatcher, cohort, event) as native:
            assert native is None
    assert source.connection().next_delivery == 0
    assert dispatcher.state_manager.materialization_digest() == before
    output.close()


def test_router_rebuilds_binding_from_restored_state_and_counter_owners(tmp_path: Path) -> None:
    source, dispatcher, output, cohort, event, _, _, _ = _routed(tmp_path)
    with prepared_macos_es_fork_publication(dispatcher, cohort, event) as native:
        batch = _prepare(
            dispatcher,
            cohort,
            (event,),
            root=native.delivery.observation.occurrence_id,
            es_delivery=native.delivery,
            es_collector_process=native.collector,
            es_native_sink=native.sink,
        )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    head = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    _restore_head(dispatcher.state_manager, _capture_head(dispatcher.state_manager))
    DispatcherObservationParticipant(dispatcher).restore_checkpoint(head.head.payload, ())
    parent = event.identity_plan.actor
    builder = dispatcher.state_manager.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=event.timestamp + timedelta(seconds=1)).identity
    next_event = process_fork_occurrence(
        host=event.src_host, parent=parent, child=child, integrity_level="Medium"
    )
    with prepared_macos_es_fork_publication(dispatcher, builder.seal(), next_event) as native:
        assert native.delivery.observation.seq_num == 1
        assert native.delivery.observation.global_seq_num == 1
        dispatcher.es_collectors.cancel(native.delivery)
    assert (
        dispatcher.es_collectors.connection(macos_es_source_instance(parent.hostname)).next_delivery
        == 1
    )
    output.close()


@pytest.mark.parametrize("policy_kind", ["disabled", "outside", "drop", "visible"])
def test_router_obeys_compiled_source_admission_and_missingness(
    tmp_path: Path, policy_kind: str
) -> None:
    source, dispatcher, output, cohort, event, _, _, child = _routed(tmp_path)
    dispatcher.collection_deployment = CompiledCollectionDeployment(
        (
            SourceInstanceDeployment(
                SourceInstanceIdentity(
                    f"macos_endpoint_security:{child.hostname}",
                    child.hostname,
                    "macos_endpoint_security",
                ),
                ("macos_endpoint_security",),
                SourceCollectionPolicy(
                    enabled=policy_kind != "disabled",
                    capabilities=CollectionCapability.PROCESS,
                    windows=(
                        CollectionWindow(
                            start=event.timestamp + timedelta(seconds=1)
                            if policy_kind == "outside"
                            else None
                        ),
                    ),
                    missingness=1.0 if policy_kind == "drop" else 0.0,
                ),
            ),
        )
    )
    with prepared_macos_es_fork_publication(dispatcher, cohort, event) as native:
        assert (
            native.delivery.observation.status
            == {
                "disabled": "filtered",
                "outside": "out_of_window",
                "drop": "dropped",
                "visible": "visible",
            }[policy_kind]
        )
        batch = _prepare(
            dispatcher,
            cohort,
            (event,),
            root=native.delivery.observation.occurrence_id,
            es_delivery=native.delivery,
            es_collector_process=native.collector,
            es_native_sink=native.sink,
        )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert source.connection().next_delivery == 1
    output.close()
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(policy_kind == "visible")


@pytest.mark.parametrize(
    "changes", [{"architecture": "x64"}, {"os": "macOS 26"}, {"type": "server"}]
)
def test_requested_native_source_rejects_an_unsupported_host_before_activation(
    tmp_path: Path, changes: dict
) -> None:
    scenario = _scenario()
    scenario.output.logs = [{"format": "macos_endpoint_security"}]
    for key, value in changes.items():
        setattr(scenario.environment.systems[0], key, value)
    engine = GenerationEngine(scenario, tmp_path)
    with pytest.raises(StateError, match="macOS 27 arm64"):
        engine._initialize()
    assert not engine.state_manager._running_processes


def test_selected_native_source_has_same_canonical_collector_as_filtered_run(
    tmp_path: Path,
) -> None:
    identities = []
    for name in ("ecar", "macos_endpoint_security"):
        scenario = _scenario()
        scenario.output.logs = [{"format": name}]
        engine = GenerationEngine(scenario, tmp_path / name)
        try:
            engine._initialize()
            identities.append(
                engine.state_manager.get_process_identity(
                    "MAC-01", engine._system_pids["MAC-01"]["eslogger"]
                )
            )
        finally:
            for emitter in engine.emitters.values():
                emitter.close()
    assert identities[0] == identities[1]


def test_production_fork_route_recovers_native_sink_without_repeating_state_or_reporting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    source, dispatcher, output, cohort, event, _, _, child = _routed(tmp_path)
    dispatcher.storyline_cluster_id = "invented-native-recovery"
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    original = ExternalSortedLineWriter._commit_exact_row
    failed = False

    def lost_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal failed
        original(writer, *args)
        if not failed:
            failed = True
            raise RuntimeError("injected native row acknowledgement loss")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lost_return)
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    with pytest.raises(RuntimeError, match="acknowledgement loss") as error:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    before = dispatcher.state_manager.materialization_digest()
    assert source.connection().next_delivery == 1
    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", original)
    dispatcher.resume_action_cohort_projection(error.value.action_cohort_receipt)
    assert dispatcher.state_manager.materialization_digest() == before
    assert source.connection().next_delivery == 1
    assert dispatcher.source_evidence_status["invented-native-recovery"][
        "macos_endpoint_security"
    ] == {"visible": 1}
    dispatcher.assert_exact_projection_recoveries_drained()
    output.close()
    assert (
        sum(
            len(p.read_text().splitlines())
            for p in tmp_path.rglob("macos_endpoint_security.ndjson")
        )
        == 1
    )


@pytest.mark.slow
def test_production_fork_route_is_deterministic_across_fresh_processes(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    script = """
import sys
from pathlib import Path
from tests.unit.test_macos_es_source_integration import _routed
from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
source, dispatcher, output, plan, event, collector, parent, child = _routed(Path(sys.argv[1]))
startup = object.__new__(MacosSshReceiverStartup)
startup._dispatcher = dispatcher
batch = startup._prepare_retained_publication(plan, event, f"process-fork:{child.object_id}", ())
dispatcher.publish_prepared_action_cohort_batch(batch)
assert source.connection().next_delivery == 1
dispatcher.assert_exact_projection_recoveries_drained()
output.close()
"""
    results = []
    for seed in ("13", "97"):
        output = tmp_path / seed
        result = subprocess.run(
            [sys.executable, "-c", script, str(output)],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        results.append(
            [path.read_bytes() for path in sorted(output.rglob("macos_endpoint_security.ndjson"))]
        )
    assert results[0] == results[1] and len(results[0]) == 1


@pytest.mark.slow
def test_cli_selects_native_source_and_records_manifest_without_inventing_forks(
    tmp_path: Path,
) -> None:
    import json

    import yaml
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    data = _scenario().model_dump(mode="json", exclude_none=True)
    data["time_window"]["duration"] = "1h"
    data["time_window"]["warmup"] = "1h"
    data["storyline"] = []
    data["output"]["logs"] = [{"format": "macos_endpoint_security"}]
    path = tmp_path / "invented-source.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    destination = tmp_path / "output"
    result = CliRunner().invoke(
        app,
        [
            "generate",
            str(path),
            "--output",
            str(destination),
            "--seed",
            "326",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    manifest = json.loads((destination / "GENERATION_MANIFEST.json").read_text())
    assert manifest["formats"] == ["macos_endpoint_security"]
    assert not list(destination.rglob("macos_endpoint_security.ndjson"))
