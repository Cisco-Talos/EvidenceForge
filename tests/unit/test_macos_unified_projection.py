# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored native writer contracts; no captured records."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    MachOImageIdentity,
)
from evidenceforge.events.identity import (
    PosixProcessCredentials,
    ProcessIdentity,
    ThreadIdentity,
)
from evidenceforge.events.macos_logging import MacosUnifiedLogObservation, UnifiedLogCallsite
from evidenceforge.formats.macos_unified_log import (
    decode_unified_log_record,
    project_unified_log_observation,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.macos_logging import prepare_unified_log_observation
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing.macos import MachTimebase
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.exceptions import StateError
from tests.support.macos_ssh import macos_ssh_scenario

_START = datetime(2026, 8, 4, 12, tzinfo=UTC)


def _observation() -> MacosUnifiedLogObservation:
    key = BinaryReleaseKey("example-writer", "1", "test", "arm64", "macos", "Writer")
    binary = BinaryReleaseIdentity(key, mach_o_image=MachOImageIdentity.derive(key))
    thread = ThreadIdentity("mac-fixture", "process-a", 200, 400, "thread-a", _START)
    writer = ProcessIdentity(
        "mac-fixture",
        "process-a",
        200,
        1,
        "/Applications/Writer",
        "Writer",
        "root",
        "",
        _START,
        "process-life-a",
        primary_thread=thread,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    return MacosUnifiedLogObservation(
        canonical_time=_START + timedelta(seconds=30),
        writer=writer,
        thread=thread,
        binary=binary,
        boot_uuid="12345678-1234-4234-8234-123456789abc",
        mach_timestamp=720_000_000,
        callsite=UnifiedLogCallsite(
            "Default", "org.example.writer", "Requests", "%s", 0x20000, 0x10000
        ),
        message="Invented request",
    )


def test_projection_uses_writer_identity_and_keeps_uptime_when_export_clock_changes() -> None:
    observation = _observation()
    later = (observation.canonical_time + timedelta(seconds=90)).astimezone(
        timezone(timedelta(hours=-4))
    )
    record = project_unified_log_observation(observation, wall_time=later, timezone_name="EDT")
    assert record.user_id == observation.writer.credentials.effective_uid == 0
    assert record.process_id == observation.thread.pid == 200
    assert record.thread_id == observation.thread.tid == 400
    assert (
        record.process_image_uuid
        == record.sender_image_uuid
        == observation.binary.mach_o_image.build_uuid
    )
    assert record.process_image_path == record.sender_image_path == observation.writer.image
    assert record.mach_timestamp == observation.mach_timestamp
    assert record.boot_uuid == observation.boot_uuid
    assert record.event_time == later
    assert record.timestamp.endswith("-0400")
    raw = record.to_ndjson()
    assert "backtrace" not in json.loads(raw) and "source" not in json.loads(raw)
    assert not {
        "personaID",
        "personaName",
        "personaType",
        "launchPersonaID",
        "launchPersonaName",
        "launchPersonaType",
    }.intersection(json.loads(raw))
    assert decode_unified_log_record(raw) == record


def test_tracepoint_represents_static_callsite_not_pid_user_thread_or_occurrence() -> None:
    first = _observation()
    second = replace(
        first,
        canonical_time=first.canonical_time + timedelta(seconds=3),
        mach_timestamp=792_000_000,
    )
    assert first.callsite.trace_id == second.callsite.trace_id
    raw = first.callsite.trace_id.to_bytes(8, "little")
    assert raw[:4] == bytes([4, 0, 2, 2])
    assert int.from_bytes(raw[4:], "little") == first.callsite.format_string_offset
    assert first.callsite.program_counter != first.callsite.format_string_offset
    assert replace(first.callsite, has_rules=True).trace_id.to_bytes(8, "little")[:4] == bytes(
        [4, 0, 2, 6]
    )
    assert replace(first.callsite, subsystem="", category="").trace_id.to_bytes(8, "little")[
        :4
    ] == bytes([4, 0, 2, 0])


@pytest.mark.parametrize(
    "level,wire", [("Default", 0), ("Info", 1), ("Debug", 2), ("Error", 16), ("Fault", 17)]
)
def test_tracepoint_log_level_uses_native_discriminant(level: str, wire: int) -> None:
    assert replace(_observation().callsite, message_type=level).trace_id >> 8 & 255 == wire


@pytest.mark.parametrize(
    "field,value",
    [
        ("message_type", "Notice"),
        ("message_type", None),
        ("format_string", ""),
        ("format_string", "bad\x00"),
        ("subsystem", ""),
        ("has_rules", 1),
        ("format_string_offset", True),
        ("format_string_offset", 0),
        ("format_string_offset", 2**31),
        ("program_counter", 3),
        ("program_counter", -4),
        ("program_counter", 2**32),
    ],
)
def test_callsite_rejects_unknown_or_unsupported_wire_shapes(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        replace(_observation().callsite, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostname", "other-mac"),
        ("pid", 201),
        ("process_object_id", "reused-pid-lifetime"),
        ("started_at", _START - timedelta(seconds=1)),
        ("started_at", _START + timedelta(seconds=31)),
        ("tid", True),
        ("tid", 2**64),
    ],
)
def test_writer_rejects_foreign_retired_or_invalid_threads(field: str, value: object) -> None:
    observation = _observation()
    with pytest.raises(ValueError):
        replace(observation, thread=replace(observation.thread, **{field: value}))


def test_exec_rejects_prior_image_thread_and_accepts_owned_replacement() -> None:
    observation = _observation()
    executed = _START + timedelta(seconds=5)
    writer = replace(
        observation.writer, execution_ordinal=1, executed_at=executed, lifetime_image="/bin/old"
    )
    with pytest.raises(ValueError, match="current writer execution"):
        replace(observation, writer=writer)
    new_thread = replace(observation.thread, started_at=executed, tid=401, object_id="thread-b")
    projected = replace(
        observation, writer=replace(writer, primary_thread=new_thread), thread=new_thread
    )
    assert projected.writer.object_id == observation.writer.object_id
    assert projected.writer.execution_id != observation.writer.execution_id


@pytest.mark.parametrize(
    "field,value",
    [
        ("canonical_time", _START.replace(tzinfo=None)),
        ("mach_timestamp", -1),
        ("mach_timestamp", True),
        ("mach_timestamp", 2**64),
        ("boot_uuid", ""),
        ("boot_uuid", "00000000-0000-0000-0000-000000000000"),
        ("boot_uuid", "12345678123442348234123456789abc"),
        ("message", "bad\x00"),
    ],
)
def test_observation_rejects_unknown_or_invalid_clock_and_message_facts(
    field: str, value: object
) -> None:
    with pytest.raises(ValueError):
        replace(_observation(), **{field: value})


def test_writer_requires_explicit_image_and_credentials_without_path_inference() -> None:
    observation = _observation()
    with pytest.raises(ValueError, match="explicit native"):
        replace(observation, binary=replace(observation.binary, mach_o_image=None))
    with pytest.raises(ValueError, match="effective credentials"):
        replace(observation, writer=replace(observation.writer, credentials=None))
    with pytest.raises(ValueError, match="exact native artifact"):
        replace(observation, writer=replace(observation.writer, image="/usr/bin/other"))
    with pytest.raises(ValueError, match="aware source"):
        project_unified_log_observation(
            observation, wall_time=_START.replace(tzinfo=None), timezone_name=""
        )


def test_projection_preserves_redaction_and_json_escapes_without_filling_private_values() -> None:
    observation = replace(_observation(), message='value: <private>\n"quoted"\\path')
    record = project_unified_log_observation(observation, wall_time=_START, timezone_name="UTC")
    assert len(record.to_ndjson().splitlines()) == 1
    assert json.loads(record.to_ndjson())["eventMessage"] == observation.message


def _owned_writer(
    scenarios_dir: Path,
) -> tuple[StateManager, DeploymentContentRegistry, ProcessIdentity]:
    scenario = macos_ssh_scenario(scenarios_dir)
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))
    manager = StateManager()
    manager.register_boot_time("TEST-01", _START - timedelta(hours=2))
    writer = _materialize_writer(manager)
    return manager, registry, writer


def _materialize_writer(
    manager: StateManager, *, at: datetime = _START, pid: int | None = None
) -> ProcessIdentity:
    image = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
    plan = manager.plan_process_materialization(
        system="TEST-01",
        parent_pid=0,
        image=image,
        command_line=image,
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=at,
        fixed_pid=pid,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    manager.materialize_process(plan)
    return plan.identity


def _prepare(
    manager: StateManager,
    registry: DeploymentContentRegistry,
    writer: ProcessIdentity,
    *,
    at: datetime = _START + timedelta(seconds=30),
) -> MacosUnifiedLogObservation:
    return prepare_unified_log_observation(
        manager,
        registry,
        writer=writer,
        canonical_time=at,
        timebase=MachTimebase(125, 3),
        callsite=_observation().callsite,
        message="Invented request",
    )


def test_preparation_uses_real_state_deployment_and_boot_without_allocating(
    scenarios_dir: Path,
) -> None:
    manager, registry, writer = _owned_writer(scenarios_dir)
    digest = manager.materialization_digest()
    observation = _prepare(manager, registry, writer)
    assert manager.materialization_digest() == digest
    assert observation.writer == writer
    assert observation.thread == manager.get_primary_thread(writer.hostname, writer.pid)
    assert observation.binary == registry.resolve_binary(writer.hostname, writer.image, "macos")
    assert observation.mach_timestamp == (7200 + 30) * 24_000_000
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert _prepare(restored, registry, writer) == observation


def test_prepared_observation_survives_exit_and_pid_reuse_without_new_lookup(
    scenarios_dir: Path,
) -> None:
    manager, registry, writer = _owned_writer(scenarios_dir)
    observation = _prepare(manager, registry, writer)
    manager.end_process(writer.hostname, writer.pid, end_time=_START + timedelta(seconds=31))
    new_writer = _materialize_writer(manager, at=_START + timedelta(seconds=32), pid=writer.pid)
    assert new_writer.pid == writer.pid and new_writer.object_id != writer.object_id
    with pytest.raises(StateError, match="exact active execution"):
        _prepare(manager, registry, writer, at=_START + timedelta(seconds=35))
    with pytest.raises(StateError, match="exact active execution"):
        _prepare(manager, registry, writer)
    later = _START + timedelta(minutes=2)
    record = project_unified_log_observation(observation, wall_time=later, timezone_name="UTC")
    assert record.thread_id == writer.primary_thread.tid
    assert record.thread_id != new_writer.primary_thread.tid
    assert record.mach_timestamp == observation.mach_timestamp


@pytest.mark.parametrize(
    "damage",
    [
        "missing_thread",
        "changed_writer",
        "unknown_image",
        "no_boot",
        "before_start",
        "after_exit",
        "later_boot",
    ],
)
def test_preparation_fails_closed_without_mutating_action_state(
    scenarios_dir: Path, damage: str
) -> None:
    manager, registry, writer = _owned_writer(scenarios_dir)
    at = _START + timedelta(seconds=30)
    if damage == "missing_thread":
        manager.end_thread(
            writer.hostname, writer.object_id, writer.primary_thread.tid, end_time=at
        )
    elif damage == "changed_writer":
        writer = replace(writer, principal="another-user")
    elif damage == "unknown_image":
        registry = DeploymentContentRegistry()
    elif damage == "no_boot":
        manager._system_boot_times.clear()
    elif damage == "later_boot":
        manager.register_boot_time(writer.hostname, _START + timedelta(seconds=1))
    elif damage == "before_start":
        at = _START - timedelta(seconds=1)
    elif damage == "after_exit":
        manager.end_process(writer.hostname, writer.pid, end_time=at)
    digest = manager.materialization_digest()
    with pytest.raises(StateError):
        _prepare(manager, registry, writer, at=at)
    assert manager.materialization_digest() == digest
