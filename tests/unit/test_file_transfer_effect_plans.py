# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact preflight and reconciliation tests for endpoint transfer actions."""

from __future__ import annotations

import json
import os
import random
import runpy
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import OccurrenceRole
from evidenceforge.generation.actions.command_effects import (
    EffectKind,
    EffectOutcomeStatus,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlanError,
)
from evidenceforge.generation.actions.file_transfer import (
    ScpReceiverFileActionBundle,
    ScpReceiverFileRequest,
    StagedArchiveSmbReadActionBundle,
    StagedArchiveSmbReadRequest,
)
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import stable_uuid


class _Dispatcher:
    """Capture canonical builders without source projection side effects."""

    def __init__(self, output_end_time: datetime) -> None:
        self.output_end_time = output_end_time
        self.builders: list[Any] = []

    def dispatch_builder(self, builder: Any) -> None:
        self.builders.append(builder)

    def prepare_builder(self, builder: Any) -> Any:
        """Return one allocation-free compatibility prepared projection."""

        return builder

    def publish_prepared(self, builder: Any) -> None:
        """Publish one previously prepared compatibility projection."""

        self.builders.append(builder)


class _Activity:
    """Read-only planning surface plus explicit effect commit captures."""

    def __init__(
        self,
        state_manager: StateManager,
        *,
        scenario_end: datetime,
        source: System,
        target: System,
        responder_pid: int,
        ready_time: datetime,
    ) -> None:
        self.state_manager = state_manager
        self._scenario_end_time = scenario_end
        self._execution_effect_audit = ExecutionEffectAuditCounter()
        self._storage_world = SimpleNamespace(
            shares=(
                SimpleNamespace(
                    system=target.hostname,
                    name="C$",
                    ref=f"{target.hostname}.c_admin",
                ),
            )
        )
        self._responder_pids = {(source.ip, 49152, target.ip): responder_pid}
        self._ready_times = {(source.ip, 49152, target.ip): ready_time}
        self.process_source_times: dict[tuple[str, int], datetime] = {}
        self.smb_calls: list[dict[str, Any]] = []
        self.terminations: list[dict[str, Any]] = []
        self.smb_admitted = True

    def _build_host_context(self, system: System) -> HostContext:
        os_category = "linux" if "ubuntu" in system.os.casefold() else "windows"
        return HostContext(
            hostname=system.hostname,
            ip=system.ip,
            os=system.os,
            os_category=os_category,
            system_type=system.type,
        )

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        return self.process_source_times.get((hostname, pid))

    def ssh_responder_pid_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> int | None:
        return self._responder_pids.get((source_ip, source_port, target_ip))

    def ssh_session_ready_time_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> datetime | None:
        return self._ready_times.get((source_ip, source_port, target_ip))

    def _get_system_pid(self, hostname: str, process_name: str, fallback: int) -> int:
        _ = (hostname, process_name)
        return fallback

    def generate_smb_activity(self, **kwargs: Any) -> SimpleNamespace:
        self.smb_calls.append(kwargs)
        if not self.smb_admitted:
            return SimpleNamespace(
                session_id="",
                transport_uids=(),
                operations=(),
                completed_at=kwargs["time"],
            )
        return SimpleNamespace(
            session_id="smb-session-1",
            transport_uids=("Csmbtransfer0001",),
            operations=({"operation": "read"},),
            completed_at=kwargs["time"] + timedelta(seconds=4),
        )

    def generate_process_termination(self, **kwargs: Any) -> None:
        self.terminations.append(kwargs)
        system = kwargs["system"]
        assert system is not None
        self.state_manager.end_process(system.hostname, kwargs["pid"], kwargs["time"])


def _create_process(
    state_manager: StateManager,
    *,
    system: System,
    at_time: datetime,
    image: str,
    command_line: str,
    username: str,
) -> int:
    state_manager.set_current_time(at_time)
    return state_manager.create_process(
        system=system.hostname,
        parent_pid=0,
        image=image,
        command_line=command_line,
        username=username,
        integrity_level="High" if username == "root" else "Medium",
    )


def _fixture(seed: int = 17) -> SimpleNamespace:
    base = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    source_windows = System(
        hostname="SRC-WIN",
        ip="10.10.1.20",
        os="Windows 11 Enterprise",
        type="workstation",
    )
    source_linux = System(
        hostname="SRC-LNX",
        ip="10.10.1.30",
        os="Ubuntu 24.04",
        type="workstation",
    )
    target = System(
        hostname="FILE-LNX",
        ip="10.10.2.20",
        os="Ubuntu 24.04",
        type="server",
    )
    actor = User(username="alice", full_name="Alice Example", email="alice@example.test")
    state = StateManager()
    staging_pid = _create_process(
        state,
        system=source_windows,
        at_time=base,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe Copy-Item archive.zip",
        username=actor.username,
    )
    reader_pid = _create_process(
        state,
        system=source_windows,
        at_time=base + timedelta(milliseconds=10),
        image=r"C:\Program Files\Mozilla Firefox\firefox.exe",
        command_line="firefox.exe -contentproc",
        username=actor.username,
    )
    scp_pid = _create_process(
        state,
        system=source_linux,
        at_time=base + timedelta(milliseconds=20),
        image="/usr/bin/scp",
        command_line="scp /tmp/archive.tgz root@FILE-LNX:/var/tmp/archive.tgz",
        username=actor.username,
    )
    responder_pid = _create_process(
        state,
        system=target,
        at_time=base + timedelta(milliseconds=30),
        image="/usr/sbin/sshd",
        command_line="sshd: root [priv]",
        username="root",
    )
    scenario_end = base + timedelta(hours=2)
    ready_time = base + timedelta(minutes=15, milliseconds=100)
    activity = _Activity(
        state,
        scenario_end=scenario_end,
        source=source_linux,
        target=target,
        responder_pid=responder_pid,
        ready_time=ready_time,
    )
    dispatcher = _Dispatcher(scenario_end)
    executor = SimpleNamespace(
        activity_generator=activity,
        dispatcher=dispatcher,
        state_manager=state,
    )
    staged_request = StagedArchiveSmbReadRequest(
        actor=actor,
        source_ip=source_windows.ip,
        staging_ip=target.ip,
        archive_path=r"C:\ProgramData\archive.zip",
        smb_filename=r"\\FILE-LNX\C$\ProgramData\archive.zip",
        staged_at=base + timedelta(minutes=1),
        exfil_time=base + timedelta(minutes=30),
        upload_bytes=80_000_000,
        source_system=source_windows,
        target_system=target,
        source_pid=staging_pid,
        source_process=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        source_command="powershell.exe Copy-Item archive.zip",
        source_logon_id="0xabc",
        terminate_source_process=True,
        reader_pid=reader_pid,
        reader_process=r"C:\Program Files\Mozilla Firefox\firefox.exe",
        reader_command="firefox.exe -contentproc",
        source_file_read_path=r"C:\Users\alice\AppData\Local\Temp\archive.zip",
    )
    scp_request = ScpReceiverFileRequest(
        source_system=source_linux,
        target_system=target,
        actor=actor,
        source_pid=scp_pid,
        source_process="/usr/bin/scp",
        source_command="scp /tmp/archive.tgz root@FILE-LNX:/var/tmp/archive.tgz",
        source_path="/tmp/archive.tgz",
        target_user="root",
        target_path="/var/tmp/archive.tgz",
        transfer_time=base + timedelta(minutes=15),
        source_port=49152,
    )
    return SimpleNamespace(
        base=base,
        source_windows=source_windows,
        source_linux=source_linux,
        target=target,
        actor=actor,
        state=state,
        activity=activity,
        dispatcher=dispatcher,
        executor=executor,
        staging_pid=staging_pid,
        reader_pid=reader_pid,
        scp_pid=scp_pid,
        responder_pid=responder_pid,
        staged=StagedArchiveSmbReadActionBundle(
            executor,
            staged_request,
            random.Random(seed),
        ),
        scp=ScpReceiverFileActionBundle(
            executor,
            scp_request,
            random.Random(seed),
        ),
        staged_request=staged_request,
        scp_request=scp_request,
    )


def _effect_signature(plan: Any) -> tuple[Any, ...]:
    return (
        plan.effects.action_id,
        tuple(
            (
                node.node_id,
                node.intent.kind.value,
                node.role.value,
                node.requirement.value,
                node.actor.kind.value,
                node.actor.node_id,
                node.depends_on,
            )
            for node in plan.effects.ordered_nodes
        ),
        tuple(
            (
                outcome.node_id,
                outcome.status.value,
                outcome.child_action_id,
                outcome.canonical_occurrence_count,
            )
            for outcome in plan.reconciliation.outcomes
        ),
    )


def _scp_plan_signature(seed: int = 17) -> tuple[Any, ...]:
    plan = _fixture(seed).scp.plan_execution()
    assert plan is not None
    return (
        _effect_signature(plan),
        plan.source_read.timestamp.isoformat(),
        plan.receiver_create.timestamp.isoformat(),
        plan.source_process.object_id,
        plan.receiver_process.object_id,
    )


def test_staged_smb_plan_is_allocation_free_frozen_and_exact() -> None:
    fixture = _fixture()
    process_count = len(fixture.state.state.running_processes)
    current_time = fixture.state.state.current_time

    plan = fixture.staged.plan_execution()

    assert plan is not None
    assert len(fixture.state.state.running_processes) == process_count
    assert fixture.state.state.current_time == current_time
    assert fixture.activity.smb_calls == []
    assert fixture.dispatcher.builders == []
    assert fixture.activity.terminations == []
    assert plan.reconciliation.complete
    assert all(outcome.canonical_occurrence_count == 1 for outcome in plan.reconciliation.outcomes)
    assert plan.local_create_retention_deadline == plan.window_end
    assert plan.local_create is not None
    assert plan.source_read is not None
    assert plan.local_create.timestamp < plan.source_read.timestamp < plan.termination_time
    assert any(node.role == OccurrenceRole.CLOSURE for node in plan.effects.nodes)
    with pytest.raises(FrozenInstanceError):
        plan.transfer_bytes = 1  # type: ignore[misc]


def test_staged_smb_execute_preserves_exact_content_and_closes_created_process() -> None:
    fixture = _fixture()
    plan = fixture.staged.plan_execution()
    assert plan is not None

    assert fixture.staged.execute()

    assert len(fixture.activity.smb_calls) == 1
    (content,) = fixture.activity.smb_calls[0]["files_override"]
    assert content is plan.exact_file
    assert content.file_id == stable_uuid(
        "staged-archive-file",
        plan.share_ref,
        plan.relative_path,
        fixture.staged_request.archive_path,
    )
    assert content.size_bytes == plan.transfer_bytes
    assert content.mime_type == "application/zip"
    assert [builder.event_type for builder in fixture.dispatcher.builders] == [
        "file_create",
        "file_read",
    ]
    assert fixture.activity.terminations[0]["time"] == plan.termination_time
    assert fixture.state.get_process(fixture.source_windows.hostname, fixture.staging_pid) is None
    audit = fixture.activity._execution_effect_audit.snapshot()
    assert audit.plan_count == 1
    assert audit.planned_node_count == len(plan.effects.nodes)
    assert audit.realized_effect_occurrence_count == 4


def test_scp_reuses_source_content_identity_and_publishes_exact_receiver_artifact() -> None:
    """SCP read/create evidence shares content while retaining distinct local objects."""

    fixture = _fixture()
    registry = LocalArtifactVersionRegistry(capacity=16, shard_count=2)
    manager = RuntimeContentIdentityManager(registry)
    fixture.activity._runtime_content_manager = manager
    source_token = manager.prepare_effect_publication(
        root_action_id="source-archive-create",
        stable_source_id="canonical-archive-content",
        hostname=fixture.source_linux.hostname,
        principal=fixture.actor.username,
        platform="linux",
        architecture=None,
        native_path=fixture.scp_request.source_path,
        action="create",
        observed_at=fixture.base + timedelta(minutes=1),
        owner_kind="user",
        actor_image=fixture.scp_request.source_process,
        authored_size_bytes=42_000,
        authored_mime_type="application/gzip",
    )
    assert source_token is not None
    with registry.prepared_publication(source_token) as commit:
        commit.commit()

    assert fixture.scp.execute()

    source_record = manager.resolve_record(
        fixture.source_linux.hostname,
        fixture.actor.username,
        fixture.scp_request.source_path,
        "linux",
    )
    receiver_record = manager.resolve_record(
        fixture.target.hostname,
        fixture.scp_request.target_user,
        fixture.scp_request.target_path,
        "linux",
    )
    assert source_record is not None
    assert receiver_record is not None
    assert receiver_record.content == source_record.content
    assert receiver_record.artifact.artifact_id != source_record.artifact.artifact_id
    source_read, receiver_create = fixture.dispatcher.builders
    assert source_read.file is not None
    assert receiver_create.file is not None
    assert source_read.file.artifact_identity == source_record.artifact
    assert receiver_create.file.artifact_identity == receiver_record.artifact
    assert source_read.file.content_identity == receiver_create.file.content_identity


def test_staged_smb_channel_omission_leaves_endpoint_and_audit_state_untouched() -> None:
    fixture = _fixture()
    fixture.activity.smb_admitted = False
    process_count = len(fixture.state.state.running_processes)

    assert not fixture.staged.execute()

    assert len(fixture.activity.smb_calls) == 1
    assert fixture.dispatcher.builders == []
    assert fixture.activity.terminations == []
    assert len(fixture.state.state.running_processes) == process_count
    assert fixture.activity._execution_effect_audit.snapshot().plan_count == 0


def test_scp_plan_links_only_exact_existing_process_objects() -> None:
    fixture = _fixture()
    process_count = len(fixture.state.state.running_processes)
    current_time = fixture.state.state.current_time

    plan = fixture.scp.plan_execution()

    assert plan is not None
    assert len(fixture.state.state.running_processes) == process_count
    assert fixture.state.state.current_time == current_time
    assert plan.reconciliation.complete
    linked = {
        outcome.child_action_id
        for outcome in plan.reconciliation.outcomes
        if outcome.status == EffectOutcomeStatus.LINKED
    }
    assert linked == {plan.source_process.object_id, plan.receiver_process.object_id}
    transfer_outcome = next(
        outcome
        for outcome in plan.reconciliation.outcomes
        if next(node for node in plan.effects.nodes if node.node_id == outcome.node_id).intent.kind
        == EffectKind.TRANSFER
    )
    assert transfer_outcome.status == EffectOutcomeStatus.REALIZED
    assert plan.ssh_ready_time < plan.source_read.timestamp < plan.receiver_create.timestamp
    assert plan.retention_deadline == plan.window_end


def test_scp_execute_emits_exact_cardinality_without_allocating_responder() -> None:
    fixture = _fixture()
    plan = fixture.scp.plan_execution()
    assert plan is not None
    process_count = len(fixture.state.state.running_processes)

    assert fixture.scp.execute()

    assert len(fixture.state.state.running_processes) == process_count
    assert [builder.event_type for builder in fixture.dispatcher.builders] == [
        "file_read",
        "file_create",
    ]
    source_read, receiver_create = fixture.dispatcher.builders
    assert source_read.identity_plan.actor_id == plan.source_process.object_id
    assert receiver_create.identity_plan.actor_id == plan.receiver_process.object_id
    assert source_read.timestamp == plan.source_read.timestamp
    assert receiver_create.timestamp == plan.receiver_create.timestamp
    audit = fixture.activity._execution_effect_audit.snapshot()
    assert audit.plan_count == 1
    assert audit.planned_node_count == 5
    assert audit.realized_effect_occurrence_count == 3


@pytest.mark.parametrize("family", ["staged", "scp"])
def test_near_window_suppression_has_no_partial_state(family: str) -> None:
    fixture = _fixture()
    if family == "staged":
        fixture.activity._scenario_end_time = fixture.staged_request.staged_at + timedelta(
            seconds=1
        )
        bundle = fixture.staged
    else:
        fixture.activity._scenario_end_time = fixture.scp_request.transfer_time + timedelta(
            milliseconds=1
        )
        bundle = fixture.scp
    fixture.dispatcher.output_end_time = fixture.activity._scenario_end_time
    process_count = len(fixture.state.state.running_processes)
    current_time = fixture.state.state.current_time

    assert not bundle.execute()

    assert fixture.dispatcher.builders == []
    assert fixture.activity.smb_calls == []
    assert fixture.activity.terminations == []
    assert len(fixture.state.state.running_processes) == process_count
    assert fixture.state.state.current_time == current_time
    assert fixture.activity._execution_effect_audit.snapshot().plan_count == 0


def test_scp_tuple_drift_fails_before_any_mutation() -> None:
    fixture = _fixture()
    fixture.activity._responder_pids.clear()
    process_count = len(fixture.state.state.running_processes)
    current_time = fixture.state.state.current_time

    with pytest.raises(ExecutionEffectPlanError, match="tuple-bound SSH responder"):
        fixture.scp.execute()

    assert fixture.dispatcher.builders == []
    assert len(fixture.state.state.running_processes) == process_count
    assert fixture.state.state.current_time == current_time
    assert fixture.activity._execution_effect_audit.snapshot().plan_count == 0


@pytest.mark.parametrize("workers", [1, 4, 8])
def test_scp_plan_is_worker_count_deterministic(workers: int) -> None:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        signatures = list(pool.map(_scp_plan_signature, [23] * 16))

    assert len(set(signatures)) == 1


def test_scp_plan_is_pythonhashseed_independent() -> None:
    test_path = Path(__file__).resolve()
    code = (
        "import json, runpy; "
        f"ns = runpy.run_path({str(test_path)!r}); "
        "print(json.dumps(ns['_scp_plan_signature'](29), sort_keys=True))"
    )
    outputs: list[str] = []
    for hash_seed in ("1", "94731"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = hash_seed
        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        outputs.append(result.stdout.strip())

    assert outputs[0] == outputs[1]


if __name__ == "__main__":
    namespace = runpy.run_path(Path(__file__).resolve())
    print(json.dumps(namespace["_scp_plan_signature"](), sort_keys=True))
