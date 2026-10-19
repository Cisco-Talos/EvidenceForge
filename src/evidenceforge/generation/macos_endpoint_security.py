# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only native process preparation for complete explicit runtime-file facts.

This is not an ES event emitter or a sink transaction. Installed executable stat,
cohort-staged owners and terminal devices require their own supported providers.
"""

from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import ESProcess
from evidenceforge.formats.macos_process_snapshot import es_process_from_observations
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError


def prepare_runtime_es_process_snapshot(
    state: StateManager,
    artifacts: LocalArtifactVersionRegistry,
    *,
    process: ProcessIdentity,
    collection: MacosProcessCollectionObservation,
    version: int,
) -> ESProcess:
    """Join an exact live execution to its retained file and immutable relationships.

    The caller supplies explicit event-time client and terminal knowledge. State
    owns the execution; the artifact registry owns its already-resolved version.
    An overwritten path cannot supply replacement content. Prepare while the
    execution is live, then retain the result for delayed rendering; this helper
    cannot reacquire an exited process or a reused PID as the original subject.
    """
    if (
        type(state) is not StateManager
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(process) is not ProcessIdentity
        or type(collection) is not MacosProcessCollectionObservation
    ):
        raise StateError("ES process preparation requires exact canonical owners and observations")
    collection.__post_init__()
    at = collection.observed_at
    with state._lock:
        if (
            collection.process != process
            or state._pid_os.get(process.hostname) != "macos"
            or state.get_process(process.hostname, process.pid) is None
            or not state.is_process_active_at(process.hostname, process.pid, at)
            or state.get_process_identity(process.hostname, process.pid) != process
        ):
            raise StateError("ES process preparation requires its exact live Mac execution")
        relationships = state.observe_process_relationships(process, observed_at=at)
        return _project_runtime_process(artifacts, relationships, collection, version=version)


def prepare_planned_runtime_es_process_snapshot(
    state: StateManager,
    artifacts: LocalArtifactVersionRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    collection: MacosProcessCollectionObservation,
    version: int,
) -> ESProcess:
    """Prepare a new Mac process before commit using authenticated State birth facts.

    The executable must already be retained. Parent/session/responsible owners
    must already be published; this is not a multi-start cohort overlay. The
    caller must still revalidate and atomically publish the process and source
    transaction. A successful projection is not a commit authorization.
    """
    if (
        type(state) is not StateManager
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(collection) is not MacosProcessCollectionObservation
    ):
        raise StateError("Planned ES preparation requires exact canonical owners and observations")
    collection.__post_init__()
    with state._lock:
        relationships = state.observe_planned_process_relationships(cohort)
        process = relationships.parent.process
        if collection.process != process or collection.observed_at != process.started_at:
            raise StateError("Planned ES preparation requires the exact process birth observation")
        return _project_runtime_process(artifacts, relationships, collection, version=version)


def _project_runtime_process(
    artifacts: LocalArtifactVersionRegistry,
    relationships: ProcessRelationshipObservation,
    collection: MacosProcessCollectionObservation,
    *,
    version: int,
) -> ESProcess:
    process = collection.process
    image = process.executable_version
    if image is None or image.identity_kind != "local_artifact":
        raise StateError("ES process preparation requires a known runtime executable version")
    assert image.artifact_version_id is not None
    record = artifacts.resolve_version(image.artifact_version_id)
    if record is None:
        raise StateError("ES process preparation requires its exact retained executable version")
    context = ProcessContext(
        pid=process.pid,
        parent_pid=process.parent_pid,
        image=process.image,
        command_line=process.command_line,
        username=process.principal,
        logon_id=process.logon_id,
        start_time=process.started_at,
        binary_identity=record.binary,
    )
    try:
        return es_process_from_observations(
            relationships, collection, context, record, version=version
        )
    except ValueError as error:
        raise StateError(f"Incomplete ES runtime process facts: {error}") from error
