# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare native fork bytes under exact canonical and collector ownership.

This boundary writes no sink and grants no source admission. An outer publisher
must still retain artifacts and atomically commit State, lifecycle and source
owners. All native metadata comes from explicit modeled observations.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from evidenceforge.events.es_collector import (
    ESCollectorObservation,
    ESDeliveryPreparation,
    PreparedESDeliveryCommit,
)
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_file import MacosFileMetadata, detach_file_metadata
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    ESAction,
    ESFork,
    ESForkEvent,
    ESThread,
)
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_installed_es_process_snapshot,
    prepare_planned_runtime_es_process_snapshot,
    prepare_planned_runtime_es_source,
)
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MacosBootClock
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc


@dataclass(frozen=True, slots=True)
class PreparedMacosForkRecord:
    """Frozen native bytes and an active collector claim, not State commit authority."""

    ndjson: str
    collector: PreparedESDeliveryCommit


@contextmanager
def prepared_es_fork_record(
    owner: ESCollectionActionOwner,
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    delivery: ESDeliveryPreparation,
    collector_process: ProcessIdentity,
    parent: MacosProcessCollectionObservation,
    child: MacosProcessCollectionObservation,
    thread: ThreadIdentity,
    clock: MacosBootClock,
    action: ESAction,
    version: int,
    installed_file: MacosFileMetadata | None = None,
    installed_filesystem: MacosInstalledFilesystem | None = None,
) -> Iterator[PreparedMacosForkRecord]:
    """Freeze one exact historical fork row under canonical and collector ownership."""
    if type(owner) is not ESCollectionActionOwner or type(delivery) is not ESDeliveryPreparation:
        raise StateError("Native fork requires its exact collection owner and delivery")
    if owner.collectors.completed_observation(delivery) is not None:
        raise StateError("Completed fork delivery must reuse its retained native bytes")
    with owner.prepared_commit(delivery, collector_process) as claimed:
        record = _fork_record(
            owner,
            executables,
            observation=claimed.observation,
            cohort=cohort,
            collector_process=collector_process,
            parent=parent,
            child=child,
            thread=thread,
            clock=clock,
            action=action,
            version=version,
            installed_file=installed_file,
            installed_filesystem=installed_filesystem,
        )
        yield PreparedMacosForkRecord(
            claimed.freeze_native_projection(
                record.to_ndjson(), canonical_token=cohort.publication_token
            ),
            claimed,
        )


def _fork_record(
    owner: ESCollectionActionOwner,
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    observation: ESCollectorObservation,
    collector_process: ProcessIdentity,
    parent: MacosProcessCollectionObservation,
    child: MacosProcessCollectionObservation,
    thread: ThreadIdentity,
    clock: MacosBootClock,
    action: ESAction,
    version: int,
    installed_file: MacosFileMetadata | None = None,
    installed_filesystem: MacosInstalledFilesystem | None = None,
) -> EndpointSecurityRecord:
    """Build one fork row from explicit facts under an outer collector claim."""
    if (
        type(owner) is not ESCollectionActionOwner
        or type(executables) not in {LocalArtifactVersionRegistry, DeploymentContentRegistry}
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(observation) is not ESCollectorObservation
        or type(parent) is not MacosProcessCollectionObservation
        or type(child) is not MacosProcessCollectionObservation
        or type(thread) is not ThreadIdentity
        or type(clock) is not MacosBootClock
        or type(action) is not ESAction
        or type(version) is not int
        or version not in {6, 10, 11}
    ):
        raise StateError("Native fork preparation requires exact supported owners and profile")
    if installed_filesystem is not None:
        if (
            type(installed_filesystem) is not MacosInstalledFilesystem
            or type(executables) is not DeploymentContentRegistry
            or installed_file is not None
        ):
            raise StateError("Installed fork requires one exact filesystem fact owner")
        installed_file = installed_filesystem.observe(
            executables, parent.process, observed_at=parent.observed_at
        ).metadata
    if type(executables) is DeploymentContentRegistry:
        if type(installed_file) is not MacosFileMetadata:
            raise StateError("Installed fork preparation requires explicit executable stat")
        installed_file = detach_file_metadata(installed_file)
    elif installed_file is not None:
        raise StateError("Runtime fork stat must come from its exact retained artifact")
    parent.__post_init__()
    child.__post_init__()
    action = ESAction.model_validate_json(action.model_dump_json())
    state = owner.state
    state.validate_action_cohort_materialization(cohort)
    owner.validate_observing_cohort(cohort, collector_process, observed_at=observation.observed_at)
    owner.validate_client_observation(parent)
    owner.validate_client_observation(child)
    birth = next((item for item in cohort.processes if item.identity == child.process), None)
    if birth is None:
        raise StateError("Native fork preparation requires its exact selected fork")
    at = child.process.started_at
    if (
        not birth.forked
        or birth.identity != child.process
        or birth._payload.parent_identity != parent.process
        or parent.observed_at != at
        or child.observed_at != at
        or observation.observed_at != at
        or observation.event_type != 11
        or observation.occurrence_id != f"process-fork:{child.process.object_id}"
        or observation.hostname != parent.process.hostname
        or (parent.process == collector_process and not parent.is_es_client)
        or clock.hostname.casefold() != parent.process.hostname.casefold()
        or thread.hostname != parent.process.hostname
        or thread.process_object_id != parent.process.object_id
        or thread.pid != parent.process.pid
        or thread.started_at > at
        or state.get_thread(*thread.canonical_key) != thread
    ):
        raise StateError("Native fork preparation requires one exact fork occurrence")
    if type(executables) is DeploymentContentRegistry:
        assert installed_file is not None
        actor = prepare_planned_installed_es_process_snapshot(
            state,
            executables,
            cohort=cohort,
            phase="fork_source",
            fork_child=child.process,
            collection=parent,
            metadata=installed_file,
            version=version,
        )
        target = prepare_planned_installed_es_process_snapshot(
            state,
            executables,
            cohort=cohort,
            collection=child,
            metadata=installed_file,
            phase="birth",
            version=version,
        )
    else:
        actor = prepare_planned_runtime_es_source(
            state,
            executables,
            cohort=cohort,
            collection=parent,
            source="fork",
            fork_child=child.process,
            version=version,
        )
        target = prepare_planned_runtime_es_process_snapshot(
            state, executables, cohort=cohort, collection=child, version=version
        )
    record = EndpointSecurityRecord(
        schema_version=1,
        version=version,
        event_type=11,
        action_type=1,
        action=action,
        time=ensure_utc(at).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
        mach_time=clock.ticks_at(at),
        seq_num=observation.seq_num,
        global_seq_num=observation.global_seq_num,
        thread=ESThread(thread_id=thread.tid),
        process=actor,
        event=ESForkEvent(fork=ESFork(child=target)),
    )
    return record
