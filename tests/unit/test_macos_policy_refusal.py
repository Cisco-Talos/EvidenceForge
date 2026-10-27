# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented refusal attempts; never execute a native app or inspect captured records."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.storyline import ResolvedEvent
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.macos_unified_log import (
    decode_unified_log_record,
    project_kernel_log_observation,
)
from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.macos_unified_log import MacosUnifiedLogEmitter
from evidenceforge.generation.indexes import ExpiringIndex
from evidenceforge.generation.macos_logging import prepare_policy_refusal
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import ProcessEventSpec, Scenario
from evidenceforge.validation.evidence_reachability import analyze_evidence_reachability
from tests.unit.test_macos_unified_projection import _owned_writer
from tests.unit.test_process_execution_state import _START, _process

_IMAGE = "/Applications/ExampleRefused.app/Contents/MacOS/ExampleRefused"


def _state() -> tuple[StateManager, ProcessIdentity]:
    state, initiator = _process()
    state.register_boot_time(initiator.hostname, _START - timedelta(hours=1))
    return state, initiator


def test_refusal_plan_is_pure_and_commit_reserves_only_observation_identities() -> None:
    state, initiator = _state()
    before = state.materialization_digest()
    threads = len(state.state.running_threads)
    builder = state.begin_action_cohort_materialization()
    allocation = builder.plan_macos_policy_refusal(
        initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    assert state.materialization_digest() == before
    assert allocation.target.pid != initiator.pid
    assert not state.validates_macos_policy_refusal(allocation.target)
    result = state.materialize_action_cohort(plan)
    assert (
        result.started_processes == result.executed_processes == result.terminated_processes == ()
    )
    assert state.validates_macos_policy_refusal(allocation.target)
    assert state.get_process(initiator.hostname, allocation.target.pid) is None
    assert len(state.list_running_processes()) == 1
    assert len(state.state.running_threads) == threads
    assert state.get_process_identity(initiator.hostname, initiator.pid) == initiator
    assert allocation.kernel_thread_id != initiator.primary_thread.tid


def test_refusal_allocators_and_reservations_survive_exact_state_restore() -> None:
    state, initiator = _state()
    builder = state.begin_action_cohort_materialization()
    first = builder.plan_macos_policy_refusal(
        initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=1)
    )
    state.materialize_action_cohort(builder.seal())
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.validates_macos_policy_refusal(first.target)
    targets = []
    for owner in (state, restored):
        next_builder = owner.begin_action_cohort_materialization()
        targets.append(
            next_builder.plan_macos_policy_refusal(
                initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=2)
            )
        )
        owner.materialize_action_cohort(next_builder.seal())
    assert targets[0] == targets[1]
    assert targets[0].target.pid != first.target.pid
    assert targets[0].kernel_thread_id > first.kernel_thread_id


@pytest.mark.parametrize("fault", ["path", "time", "stale", "namespace"])
def test_refusal_invalid_inputs_consume_no_allocator_state(fault: str) -> None:
    state, initiator = _state()
    if fault == "namespace":
        state._pid_os[initiator.hostname] = "linux"
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    with pytest.raises((StateError, ValueError)):
        builder.plan_macos_policy_refusal(
            replace(initiator, image="/different") if fault == "stale" else initiator,
            image="/usr/bin/id" if fault == "path" else _IMAGE,
            refused_at=_START - timedelta(seconds=1)
            if fault == "time"
            else _START + timedelta(seconds=1),
        )
    assert state.materialization_digest() == before


def test_refusal_failure_rolls_back_allocation_and_caller_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, initiator = _state()
    builder = state.begin_action_cohort_materialization()
    target = builder.plan_macos_policy_refusal(
        initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    before = state.materialization_digest()
    commit = state._commit_pid_allocator_patch

    def fail(*args: object, **kwargs: object) -> None:
        commit(*args, **kwargs)
        raise RuntimeError("invented allocation commit failure")

    monkeypatch.setattr(state, "_commit_pid_allocator_patch", fail)
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="invented"):
        state.materialize_action_cohort(plan)
    assert state.materialization_digest() == before
    assert not state.validates_macos_policy_refusal(target.target)


def _event(
    scenarios_dir: Path, *, commit: bool = True, missing: bool = False
) -> tuple[StateManager, OccurrenceBuilder]:
    state, registry, writer = _owned_writer(scenarios_dir)
    at = writer.execution_started_at + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    allocation = builder.plan_macos_policy_refusal(writer, image=_IMAGE, refused_at=at)
    before = state.materialization_digest()
    refusal = prepare_policy_refusal(
        state,
        None if missing else registry,
        initiator=writer,
        allocation=allocation,
        os_name="macOS 27",
    )
    assert state.materialization_digest() == before
    event = OccurrenceBuilder(
        timestamp=at,
        event_type="macos_policy_refusal",
        macos_policy_refusal=refusal,
        src_host=HostContext(
            hostname=writer.hostname,
            fqdn="refusal-fixture.example.test",
            ip="192.0.2.41",
            os="macOS 27",
            os_category="macos",
            system_type="workstation",
        ),
        identity_plan=EventIdentityPlan(
            subject=refusal.target.entity, actor=refusal.native.writer if refusal.native else None
        ),
        lifecycle=ActionLifecycleContext(
            group_id=refusal.target.object_id, canonical_start=at, phase="dependent"
        ),
    )
    if commit:
        state.materialize_action_cohort(builder.seal())
    return state, event


@pytest.mark.parametrize("threaded", [False, True])
def test_kernel_policy_projection_uses_distinct_writer_and_sender_and_shared_host_output(
    scenarios_dir: Path, tmp_path: Path, threaded: bool
) -> None:
    state, event = _event(scenarios_dir)
    native = event.macos_policy_refusal.native
    assert native is not None
    assert not shadow_seal(event).violations
    emitter = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path, threaded=threaded)
    EventDispatcher(state, {"macos_unified_log": emitter}).dispatch_builder(event)
    emitter.close()
    lines = (
        (tmp_path / "refusal-fixture.example.test" / "macos_unified_log.ndjson")
        .read_text()
        .splitlines()
    )
    assert len(lines) == 1
    record = decode_unified_log_record(lines[0])
    assert record.process_id == record.user_id == 0
    assert record.process_image_uuid != record.sender_image_uuid
    assert record.process_image_path == native.kernel_path
    assert record.process_image_path == "/kernel"
    assert record.sender_image_path == native.sender_path
    assert record.thread_id == native.thread_id
    assert record.trace_id & 0xFFFFFFFF == 0x00080004
    assert record.message_type == "Default" and record.subsystem == record.category == ""
    assert record.activity_identifier == record.parent_activity_identifier == 0
    assert (
        record.event_message
        == f"ASP: Security policy would not allow process: {event.macos_policy_refusal.target.pid}, {_IMAGE}\n"
    )
    assert record.mach_timestamp == native.mach_timestamp
    assert state.get_process(native.writer.hostname, event.macos_policy_refusal.target.pid) is None


@pytest.mark.parametrize("damage", ["target", "thread", "initiator", "boot"])
def test_state_refuses_forged_observation_receipts(scenarios_dir: Path, damage: str) -> None:
    state, event = _event(scenarios_dir, missing=damage == "target")
    refusal = event.macos_policy_refusal
    if damage == "target":
        refusal = replace(refusal, target=replace(refusal.target, pid=refusal.target.pid + 1))
    elif damage == "thread":
        refusal = replace(
            refusal, native=replace(refusal.native, thread_id=refusal.native.thread_id + 1)
        )
    elif damage == "initiator":
        refusal = replace(
            refusal,
            initiator=replace(
                refusal.initiator, object_id="unowned-initiator", primary_thread=None
            ),
        )
    else:
        state.register_boot_time(
            refusal.target.hostname, refusal.native.boot_time - timedelta(seconds=1)
        )
    event.macos_policy_refusal = refusal
    before = state.materialization_digest()
    with pytest.raises(StateError, match="receipt|State boot"):
        state.apply(event)
    assert state.materialization_digest() == before


def test_uncommitted_refusal_is_not_publishable_and_missing_native_facts_never_fabricate(
    scenarios_dir: Path, tmp_path: Path
) -> None:
    state, event = _event(scenarios_dir, commit=False)
    with pytest.raises(StateError, match="receipt"):
        state.apply(event)
    state, event = _event(scenarios_dir, missing=True)
    emitter = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path)
    EventDispatcher(state, {"macos_unified_log": emitter}).dispatch_builder(event)
    emitter.close()
    assert event.macos_policy_refusal.unavailable_reason == "native_image_unavailable"
    assert not list(tmp_path.rglob("*.ndjson"))


@pytest.mark.parametrize("damage", ["host", "time", "actor", "subject", "lifecycle"])
def test_policy_contract_rejects_wrong_canonical_roles(scenarios_dir: Path, damage: str) -> None:
    _, event = _event(scenarios_dir)
    if damage == "host":
        event.src_host = replace(event.src_host, hostname="other-mac")
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    elif damage == "actor":
        event.identity_plan = replace(
            event.identity_plan, actor=event.macos_policy_refusal.initiator
        )
    elif damage == "subject":
        event.identity_plan = replace(
            event.identity_plan, subject=event.macos_policy_refusal.initiator
        )
    else:
        event.lifecycle = replace(event.lifecycle, group_id="wrong-attempt")
    assert shadow_seal(event).violations


def test_kernel_spool_checkpoint_retains_sorted_bytes_and_exact_state_receipt(
    scenarios_dir: Path, tmp_path: Path
) -> None:
    state, event = _event(scenarios_dir)
    output = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path / "first")
    output.enable_incremental_checkpointing()
    EventDispatcher(state, {"macos_unified_log": output}).dispatch_builder(event)
    output.barrier_flush()
    participant = EmitterSpoolParticipant(
        emitters={"macos_unified_log": output}, output_root=tmp_path / "first"
    )
    seal = participant.prepare_checkpoint(1)
    participant.checkpoint_committed(1)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.validates_macos_policy_refusal(
        event.macos_policy_refusal.target,
        kernel_thread_id=event.macos_policy_refusal.native.thread_id,
    )
    other = MacosUnifiedLogEmitter(load_format("macos_unified_log"), tmp_path / "restored")
    other.enable_incremental_checkpointing()
    EmitterSpoolParticipant(
        emitters={"macos_unified_log": other}, output_root=tmp_path / "restored"
    ).restore_checkpoint(seal.head.payload, tuple(segment.payload for segment in seal.segments))
    output.close()
    other.close()
    assert (
        tmp_path / "first/refusal-fixture.example.test/macos_unified_log.ndjson"
    ).read_bytes() == (
        tmp_path / "restored/refusal-fixture.example.test/macos_unified_log.ndjson"
    ).read_bytes()


def test_legacy_state_head_migrates_with_no_refusal_receipts() -> None:
    state, _ = _state()
    old = loads(_capture_head(state))
    old["schema_version"] = "9"
    del old["expiring"]["_macos_policy_refusals"]
    restored = StateManager()
    _restore_head(restored, dumps(old))
    assert not restored._macos_policy_refusals


def test_kernel_projection_uses_planned_wall_time_without_recomputing_native_facts(
    scenarios_dir: Path,
) -> None:
    _, event = _event(scenarios_dir)
    native = event.macos_policy_refusal.native
    later = event.timestamp + timedelta(minutes=1)
    record = project_kernel_log_observation(native, wall_time=later, timezone_name="UTC")
    assert record.event_time == later and record.mach_timestamp == native.mach_timestamp


def test_failure_after_receipt_publication_rolls_back_receipt_namespaces_and_initiator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, initiator = _state()
    builder = state.begin_action_cohort_materialization()
    allocation = builder.plan_macos_policy_refusal(
        initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    original = ExpiringIndex.set

    def fail(index: ExpiringIndex, *args: object, **kwargs: object) -> None:
        original(index, *args, **kwargs)
        if index is state._macos_policy_refusals:
            raise RuntimeError("invented receipt failure")

    monkeypatch.setattr(ExpiringIndex, "set", fail)
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="receipt failure"):
        state.materialize_action_cohort(plan)
    assert state.materialization_digest() == before
    assert not state.validates_macos_policy_refusal(allocation.target)


def test_refusal_receipts_expire_without_inventing_process_termination() -> None:
    state, initiator = _state()
    builder = state.begin_action_cohort_materialization()
    allocation = builder.plan_macos_policy_refusal(
        initiator, image=_IMAGE, refused_at=_START + timedelta(seconds=1)
    )
    state.materialize_action_cohort(builder.seal())
    state._expire_retained_identities(_START + timedelta(days=10))
    assert not state.validates_macos_policy_refusal(allocation.target)
    assert state.get_process_identity(initiator.hostname, initiator.pid) == initiator


@pytest.mark.parametrize(
    "changes",
    [
        {"parent_ref": None},
        {"process_ref": "unborn"},
        {"process_name": "/usr/bin/false"},
        {"process_name": _IMAGE + "\n"},
        {"process_name": "/Applications/../Example.app/Contents/MacOS/Example"},
    ],
)
def test_authored_policy_refusal_rejects_unbounded_target_or_reference(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ProcessEventSpec.model_validate(
            dict(process_name=_IMAGE, parent_ref="caller", outcome="policy_refused") | changes
        )


def _scenario(*, native: bool = True) -> Scenario:
    data = yaml.safe_load(Path("scenarios/macos-denied-launch-example/scenario.yaml").read_text())
    target = data["storyline"][1]["events"][0]
    target.update(outcome="policy_refused", process_name=_IMAGE)
    data["output"]["logs"] = [{"format": "ecar"}] + (
        [{"format": "macos_unified_log"}] if native else []
    )
    return Scenario.model_validate(data)


@pytest.mark.parametrize("native", [False, True])
def test_policy_refusal_has_its_own_reachability_and_evaluation_source_group(native: bool) -> None:
    scenario = _scenario(native=native)
    findings = [
        finding
        for finding in analyze_evidence_reachability(scenario)
        if finding.behavior_id == "macos_authored_policy_refusal"
    ]
    assert bool(findings) is not native
    if findings:
        assert findings[0].severity == "warning"
    groups = VisibilityModel(
        scenario, {"ecar", "macos_unified_log"} if native else {"ecar"}
    ).get_expected_format_groups(
        scenario.environment.systems[0].hostname, ["process"], [{"outcome": "policy_refused"}]
    )
    assert groups == ([("app_policy_refusal", {"macos_unified_log"})] if native else [])


@pytest.mark.parametrize("damage", [None, "host", "target", "writer", "format", "parse"])
def test_evaluation_requires_bounded_refusal_without_claiming_process_success(
    scenarios_dir: Path, damage: str | None
) -> None:
    _, event = _event(scenarios_dir)
    native = event.macos_policy_refusal.native
    fields = project_kernel_log_observation(
        native, wall_time=event.timestamp, timezone_name="UTC"
    ).model_dump(by_alias=True)
    resolved = ResolvedEvent(
        index=0,
        time=event.timestamp,
        actor="casey",
        system=event.src_host.hostname,
        system_ip=event.src_host.ip,
        activity="Invented refusal",
        details={"process_name": _IMAGE, "outcome": "policy_refused"},
        event_types=["process"],
    )
    if damage == "target":
        fields["eventMessage"] = fields["eventMessage"].replace(_IMAGE, "/other/Example")
    if damage == "writer":
        fields["processID"] = 1234
    if damage == "format":
        fields["formatString"] = "%s"
    record = ParsedRecord(
        source_format="macos_unified_log",
        raw="",
        fields=fields,
        timestamp=event.timestamp,
        source_host="other-mac" if damage == "host" else event.src_host.hostname,
        parse_errors=["invented"] if damage == "parse" else [],
    )
    assert CausalityScorer()._record_matches(record, "macos_unified_log", resolved, "process") is (
        damage is None
    )
    assert not CausalityScorer()._record_matches(record, "ecar", resolved, "process")


def test_schema9_ssh_command_streams_survive_new_state_head() -> None:
    from tests.unit.test_macos_ssh_command_descriptors import _ready

    state, shell = _ready()
    legacy = loads(_capture_head(state))
    legacy["schema_version"] = "9"
    del legacy["expiring"]["_macos_policy_refusals"]
    restored = StateManager()
    _restore_head(restored, dumps(legacy))
    assert (
        restored.get_session(shell.logon_id).ssh_command_streams
        == state.get_session(shell.logon_id).ssh_command_streams
    )
