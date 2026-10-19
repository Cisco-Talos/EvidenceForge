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

from evidenceforge.events.es_collector import ESDeliveryPreparation, PreparedESDeliveryCommit
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    ESAction,
    ESFork,
    ESForkEvent,
    ESThread,
)
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_process_snapshot,
    prepare_runtime_es_process_snapshot,
)
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
def prepared_runtime_es_fork_record(
    owner: ESCollectionActionOwner,
    artifacts: LocalArtifactVersionRegistry,
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
) -> Iterator[PreparedMacosForkRecord]:
    """Freeze one actual fork and its counter observation before any canonical commit.

    Only a standalone State-authenticated fork with a retained runtime image is
    supported. Parent/child collection facts describe its canonical instant;
    export delay does not move that instant or uptime. The initiating thread is
    supplied explicitly and must be active in the exact parent execution.

    The caller may compose the yielded collector claim with an already prepared
    State/lifecycle transaction. Exiting without commit releases the claim but
    preserves the delivery reservation for explicit cancellation/retry. Completed
    delivery retries must use previously retained bytes, not re-observe State.
    """
    if (
        type(owner) is not ESCollectionActionOwner
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(delivery) is not ESDeliveryPreparation
        or type(parent) is not MacosProcessCollectionObservation
        or type(child) is not MacosProcessCollectionObservation
        or type(thread) is not ThreadIdentity
        or type(clock) is not MacosBootClock
        or type(action) is not ESAction
        or type(version) is not int
        or version not in {6, 10}
    ):
        raise StateError("Native fork preparation requires exact supported owners and profile")
    parent.__post_init__()
    child.__post_init__()
    action = ESAction.model_validate_json(action.model_dump_json())
    state = owner.state
    if owner.collectors.completed_observation(delivery) is not None:
        raise StateError("Completed fork delivery must reuse its retained native bytes")
    with owner.prepared_commit(delivery, collector_process) as claimed:
        state.validate_action_cohort_materialization(cohort)
        if len(cohort.processes) != 1 or cohort.sessions or cohort.session_activity_patches:
            raise StateError("Native fork preparation requires a standalone fork")
        birth = cohort.processes[0]
        observation = claimed.observation
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
        actor = prepare_runtime_es_process_snapshot(
            state, artifacts, process=parent.process, collection=parent, version=version
        )
        target = prepare_planned_runtime_es_process_snapshot(
            state, artifacts, cohort=cohort, collection=child, version=version
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
        yield PreparedMacosForkRecord(record.to_ndjson(), claimed)
