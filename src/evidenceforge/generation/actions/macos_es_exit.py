# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Historical ES exit preparation from exact canonical terminal facts.

This boundary admits only the existing v9 wire contract. It does not enable a
source, claim macOS 26 exit fidelity, or commit lifecycle/native sink state.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace

from evidenceforge.events.es_collector import (
    ESCollectorObservation,
    ESDeliveryBatchPreparation,
    ESDeliveryPreparation,
    PreparedESDeliveryBatchCommit,
    PreparedESDeliveryCommit,
)
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_file import MacosFileMetadata, detach_file_metadata
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    ESAction,
    ESExit,
    ESExitEvent,
    ESThread,
)
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_installed_es_process_snapshot,
    prepare_planned_runtime_es_terminal_process,
)
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MacosBootClock
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc


@dataclass(frozen=True, slots=True)
class PreparedMacosExitRecord:
    """Frozen historical native bytes and a claim, not canonical commit authority."""

    ndjson: str
    collector: PreparedESDeliveryCommit


@contextmanager
def prepared_es_exit_record(
    owner: ESCollectionActionOwner,
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    delivery: ESDeliveryPreparation,
    collector_process: ProcessIdentity,
    process: MacosProcessCollectionObservation,
    thread: ThreadIdentity,
    clock: MacosBootClock,
    action: ESAction,
    version: int,
    installed_file: MacosFileMetadata | None = None,
    installed_filesystem: MacosInstalledFilesystem | None = None,
) -> Iterator[PreparedMacosExitRecord]:
    """Freeze a selected explicit termination before its process/thread closes.

    State authenticates the terminal identity, instant and raw-status input.
    File and collector facts must be complete, and the initiating thread must
    still belong to that exact execution. The observing collector must be a
    distinct live process; self-exit delivery is outside this profile. The caller
    must separately compose lifecycle, artifact retention, counters and native
    sink publication. A completed retry uses its already frozen bytes, never a
    new observation.
    """
    if (
        type(owner) is not ESCollectionActionOwner
        or type(executables) not in {LocalArtifactVersionRegistry, DeploymentContentRegistry}
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(delivery) is not ESDeliveryPreparation
        or type(process) is not MacosProcessCollectionObservation
        or type(thread) is not ThreadIdentity
        or type(clock) is not MacosBootClock
        or type(action) is not ESAction
        or type(version) is not int
        or version != 9
    ):
        raise StateError(
            "Native exit preparation requires exact owners and the historical v9 profile"
        )
    if owner.collectors.completed_observation(delivery) is not None:
        raise StateError("Completed exit delivery must reuse its retained native bytes")
    with owner.prepared_commit(delivery, collector_process) as claimed:
        record = _exit_record(
            owner,
            executables,
            cohort=cohort,
            observation=claimed.observation,
            collector_process=collector_process,
            process=process,
            thread=thread,
            clock=clock,
            action=action,
            version=version,
            installed_file=installed_file,
            installed_filesystem=installed_filesystem,
        )
        yield PreparedMacosExitRecord(
            claimed.freeze_native_projection(
                record.to_ndjson(), canonical_token=cohort.publication_token
            ),
            claimed,
        )


def _exit_record(
    owner: ESCollectionActionOwner,
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    observation: ESCollectorObservation,
    collector_process: ProcessIdentity,
    process: MacosProcessCollectionObservation,
    thread: ThreadIdentity,
    clock: MacosBootClock,
    action: ESAction,
    version: int,
    installed_file: MacosFileMetadata | None,
    installed_filesystem: MacosInstalledFilesystem | None = None,
) -> EndpointSecurityRecord:
    """Project one fully supplied terminal record under retained owner claims."""
    if installed_filesystem is not None:
        if (
            type(installed_filesystem) is not MacosInstalledFilesystem
            or type(executables) is not DeploymentContentRegistry
            or installed_file is not None
        ):
            raise StateError("Installed exit requires one exact filesystem fact owner")
        installed_file = installed_filesystem.observe(
            executables, process.process, observed_at=process.observed_at
        ).metadata
    if type(executables) is DeploymentContentRegistry:
        if type(installed_file) is not MacosFileMetadata:
            raise StateError("Installed exit preparation requires explicit executable stat")
        installed_file = detach_file_metadata(installed_file)
    elif installed_file is not None:
        raise StateError("Runtime exit stat must come from its exact retained artifact")
    process.__post_init__()
    action = ESAction.model_validate_json(action.model_dump_json())
    state = owner.state
    state.validate_action_cohort_materialization(cohort)
    owner.validate_observing_cohort(cohort, collector_process, observed_at=observation.observed_at)
    owner.validate_client_observation(process)
    terminal = next(
        (item for item in cohort.process_terminations if item.identity == process.process), None
    )
    if terminal is None:
        raise StateError("Native exit preparation requires one exact selected termination")
    at = terminal.end_time
    identity = terminal.identity
    planned_execution = next(
        (item for item in cohort.process_executions if item.after == identity), None
    )
    thread_owned = (
        thread == planned_execution.after.primary_thread
        if planned_execution is not None
        else state.get_thread(*thread.canonical_key) == thread
        or any(
            item.identity == identity and item.identity.primary_thread == thread
            for item in cohort.processes
        )
    )
    if (
        terminal.exit_outcome is None
        or process.process != identity
        or process.observed_at != at
        or observation.observed_at != at
        or observation.event_type != 15
        or observation.occurrence_id != f"process-exit:{identity.object_id}"
        or observation.hostname != identity.hostname
        or identity.object_id == collector_process.object_id
        or clock.hostname.casefold() != identity.hostname.casefold()
        or thread.hostname != identity.hostname
        or thread.process_object_id != identity.object_id
        or thread.pid != identity.pid
        or thread.started_at > at
        or not thread_owned
    ):
        raise StateError("Native exit preparation requires one explicit owned terminal outcome")
    if type(executables) is DeploymentContentRegistry:
        assert installed_file is not None
        snapshot = prepare_planned_installed_es_process_snapshot(
            state,
            executables,
            cohort=cohort,
            collection=process,
            metadata=installed_file,
            phase="terminal",
            version=version,
        )
    else:
        snapshot = prepare_planned_runtime_es_terminal_process(
            state,
            executables,
            cohort=cohort,
            collection=process,
            version=version,
        )
    record = EndpointSecurityRecord(
        schema_version=1,
        version=version,
        event_type=15,
        action_type=1,
        action=action,
        time=ensure_utc(at).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
        mach_time=clock.ticks_at(at),
        seq_num=observation.seq_num,
        global_seq_num=observation.global_seq_num,
        thread=ESThread(thread_id=thread.tid),
        process=snapshot,
        event=ESExitEvent(exit=ESExit.from_process_exit(terminal.exit_outcome)),
    )
    return record


@dataclass(frozen=True, slots=True)
class MacosExitRecordInput:
    """Complete source-local input for one selected canonical terminal occurrence."""

    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry
    process: MacosProcessCollectionObservation
    thread: ThreadIdentity
    action: ESAction
    installed_file: MacosFileMetadata | None = None
    installed_filesystem: MacosInstalledFilesystem | None = None

    def __post_init__(self) -> None:
        if (
            type(self.executables) not in {LocalArtifactVersionRegistry, DeploymentContentRegistry}
            or type(self.process) is not MacosProcessCollectionObservation
            or type(self.thread) is not ThreadIdentity
            or type(self.action) is not ESAction
        ):
            raise StateError("Native exit batch requires exact per-record owners and observations")
        self.process.__post_init__()
        if self.installed_filesystem is not None:
            if (
                type(self.installed_filesystem) is not MacosInstalledFilesystem
                or type(self.executables) is not DeploymentContentRegistry
                or self.installed_file is not None
            ):
                raise StateError("Installed exit requires one exact filesystem fact owner")
            metadata = self.installed_filesystem.observe(
                self.executables, self.process.process, observed_at=self.process.observed_at
            ).metadata
            object.__setattr__(self, "installed_file", metadata)
            object.__setattr__(self, "installed_filesystem", None)
        object.__setattr__(
            self, "action", ESAction.model_validate_json(self.action.model_dump_json())
        )
        if type(self.executables) is DeploymentContentRegistry:
            if type(self.installed_file) is not MacosFileMetadata:
                raise StateError("Installed exit preparation requires explicit executable stat")
            object.__setattr__(self, "installed_file", detach_file_metadata(self.installed_file))
        elif self.installed_file is not None:
            raise StateError("Runtime exit stat must come from its exact retained artifact")


@dataclass(frozen=True, slots=True)
class PreparedMacosExitRecords:
    """Ordered frozen historical rows with a single all-member counter claim."""

    ndjson: tuple[str, ...]
    collector: PreparedESDeliveryBatchCommit


@contextmanager
def prepared_es_exit_records(
    owner: ESCollectionActionOwner,
    *,
    cohort: ActionCohortMaterializationPlan,
    delivery: ESDeliveryBatchPreparation,
    collector_process: ProcessIdentity,
    records: tuple[MacosExitRecordInput, ...],
    clock: MacosBootClock,
    version: int,
) -> Iterator[PreparedMacosExitRecords]:
    """Freeze every exit in one same-host terminal/adoption cohort before mutation.

    The ordered collection batch supplies exact counters and visibility decisions.
    Every canonical termination occurs once, including filtered deliveries. A
    failed later record binds no native prefix and advances no counters. An outer
    owner must still compose lifecycle/artifacts, counter commit and the durable
    source sink; this helper admits neither an emitter nor a current-build profile.
    """
    if (
        type(owner) is not ESCollectionActionOwner
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(delivery) is not ESDeliveryBatchPreparation
        or type(collector_process) is not ProcessIdentity
        or type(records) is not tuple
        or not 1 <= len(records) <= 256
        or any(type(item) is not MacosExitRecordInput for item in records)
        or type(clock) is not MacosBootClock
        or type(version) is not int
        or version != 9
    ):
        raise StateError("Native exit batch requires exact bounded owners and historical v9")
    if owner.collectors.completed_batch(delivery) is not None:
        raise StateError("Completed exit batch must reuse its retained native bytes")
    with owner.prepared_batch_commit(delivery, collector_process) as claimed:
        owner.state.validate_action_cohort_materialization(cohort)
        records = tuple(replace(item) for item in records)
        selected = tuple(item.process.process for item in records)
        terminals = {item.identity.object_id: item.identity for item in cohort.process_terminations}
        if (
            len(selected) != len(cohort.process_terminations)
            or len(selected) != len(claimed.observations)
            or len({item.object_id for item in selected}) != len(selected)
            or any(item.hostname != collector_process.hostname for item in selected)
            or any(terminals.get(item.object_id) != item for item in selected)
        ):
            raise StateError("Native exit batch must cover each exact same-host termination once")
        rendered = tuple(
            _exit_record(
                owner,
                item.executables,
                cohort=cohort,
                observation=observation,
                collector_process=collector_process,
                process=item.process,
                thread=item.thread,
                clock=clock,
                action=item.action,
                version=version,
                installed_file=item.installed_file,
            ).to_ndjson()
            for item, observation in zip(records, claimed.observations, strict=True)
        )
        yield PreparedMacosExitRecords(
            claimed.freeze_native_projections(rendered, canonical_token=cohort.publication_token),
            claimed,
        )
