# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Historical ES exit preparation from exact canonical terminal facts.

This boundary admits only the existing v9 wire contract. It does not enable a
source, claim macOS 26 exit fidelity, or commit lifecycle/native sink state.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from evidenceforge.events.es_collector import ESDeliveryPreparation, PreparedESDeliveryCommit
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
) -> Iterator[PreparedMacosExitRecord]:
    """Freeze an explicit standalone termination before its process/thread closes.

    State authenticates the terminal identity, instant and raw-status input.
    File and collector facts must be complete, and the initiating thread must
    still belong to that exact execution. The observing collector must be a
    distinct live process; self-exit delivery is outside this profile. The caller
    must separately compose lifecycle, artifact retention, counters and native
    sink publication. A
    completed retry uses its already frozen bytes, never a new observation.
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
    if type(executables) is DeploymentContentRegistry:
        if type(installed_file) is not MacosFileMetadata:
            raise StateError("Installed exit preparation requires explicit executable stat")
        installed_file = detach_file_metadata(installed_file)
    elif installed_file is not None:
        raise StateError("Runtime exit stat must come from its exact retained artifact")
    process.__post_init__()
    action = ESAction.model_validate_json(action.model_dump_json())
    state = owner.state
    if owner.collectors.completed_observation(delivery) is not None:
        raise StateError("Completed exit delivery must reuse its retained native bytes")
    with owner.prepared_commit(delivery, collector_process) as claimed:
        state.validate_action_cohort_materialization(cohort)
        owner.validate_client_observation(process)
        if len(cohort.process_terminations) != 1:
            raise StateError("Native exit preparation requires one exact termination")
        terminal = cohort.process_terminations[0]
        observation = claimed.observation
        at = terminal.end_time
        identity = terminal.identity
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
            or state.get_thread(*thread.canonical_key) != thread
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
        yield PreparedMacosExitRecord(
            claimed.freeze_native_projection(
                record.to_ndjson(), canonical_token=cohort.publication_token
            ),
            claimed,
        )
