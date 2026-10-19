# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only native process preparation for complete explicit runtime-file facts.

This is not an ES event emitter or a sink transaction. Filesystem facts must be
supplied explicitly; terminal devices require their own supported provider.
"""

from typing import Literal

from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_file import MacosFileMetadata
from evidenceforge.events.macos_installed_file import MacosInstalledFileObservation
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import ESFile, ESProcess
from evidenceforge.formats.macos_file_metadata import es_script_at_execution
from evidenceforge.formats.macos_process_snapshot import es_process_from_observations
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError


def prepare_installed_es_process_snapshot(
    state: StateManager,
    deployments: DeploymentContentRegistry,
    *,
    process: ProcessIdentity,
    collection: MacosProcessCollectionObservation,
    metadata: MacosFileMetadata,
    version: int,
) -> ESProcess:
    """Join a live installed execution to explicit occurrence-time filesystem stat.

    The immutable deployment owner validates the installation and release; it
    does not invent inode, allocation or times. A modeled filesystem caller must
    provide those facts. No generator-host filesystem is consulted.
    """
    if (
        type(state) is not StateManager
        or type(deployments) is not DeploymentContentRegistry
        or type(process) is not ProcessIdentity
        or type(collection) is not MacosProcessCollectionObservation
    ):
        raise StateError("Installed ES preparation requires exact canonical owners")
    collection.__post_init__()
    at = collection.observed_at
    with state._lock:
        image = process.executable_version
        if (
            collection.process != process
            or state._pid_os.get(process.hostname) != "macos"
            or state.get_process(process.hostname, process.pid) is None
            or not state.is_process_active_at(process.hostname, process.pid, at)
            or state.get_process_identity(process.hostname, process.pid) != process
            or image is None
            or image.identity_kind != "installed_release"
        ):
            raise StateError("Installed ES preparation requires its exact live loaded execution")
        relationships = state.observe_process_relationships(process, observed_at=at)
        return _project_installed_process(
            deployments, relationships, collection, metadata=metadata, version=version
        )


def _project_installed_process(
    deployments: DeploymentContentRegistry,
    relationships: ProcessRelationshipObservation,
    collection: MacosProcessCollectionObservation,
    *,
    metadata: MacosFileMetadata,
    version: int,
) -> ESProcess:
    process = collection.process
    image = process.executable_version
    if image is None or image.identity_kind != "installed_release":
        raise StateError("Installed ES preparation requires its exact loaded release")
    installation = deployments.installation_for_image(
        process.hostname, process.image, "macos", principal=process.principal
    )
    binary = deployments.resolve_binary(
        process.hostname, process.image, "macos", principal=process.principal
    )
    if installation is None or binary is None or binary.content_id != image.content_id:
        raise StateError("Installed ES preparation lost its exact deployed release")
    try:
        executable = MacosInstalledFileObservation(
            installation, binary, process.image, collection.observed_at, metadata
        )
        context = ProcessContext(
            process.pid,
            process.parent_pid,
            process.image,
            process.command_line,
            process.principal,
            logon_id=process.logon_id,
            start_time=process.started_at,
            binary_identity=binary,
        )
        return es_process_from_observations(
            relationships, collection, context, executable, version=version
        )
    except ValueError as error:
        raise StateError(f"Incomplete installed ES process facts: {error}") from error


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
    may be already published or explicit births in the same sealed cohort. The
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
        relationships = state.observe_planned_process_relationships(
            cohort, process=collection.process
        )
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


def prepare_runtime_es_exec_script(
    state: StateManager,
    artifacts: LocalArtifactVersionRegistry,
    *,
    process: ProcessIdentity,
) -> ESFile | None:
    """Prepare known script facts for the exact live execution before delayed rendering.

    A reference must already be retained by its artifact owner. This helper neither
    interprets commands nor extends retention nor admits a native event family.
    """
    if (
        type(state) is not StateManager
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(process) is not ProcessIdentity
    ):
        raise StateError("ES script preparation requires exact canonical owners")
    with state._lock:
        if (
            state._pid_os.get(process.hostname) != "macos"
            or state.get_process_identity(process.hostname, process.pid) != process
            or not state.is_process_active_at(
                process.hostname, process.pid, process.execution_started_at
            )
        ):
            raise StateError("ES script preparation requires its exact live Mac execution")
        script = process.exec_script
        if script is None:
            raise StateError("ES script preparation requires explicitly known script facts")
        record = (
            None
            if script.artifact_version_id is None
            else artifacts.resolve_version(script.artifact_version_id)
        )
        try:
            return es_script_at_execution(process, record)
        except ValueError as error:
            raise StateError(f"Incomplete ES script facts: {error}") from error


def prepare_planned_runtime_es_exec_target(
    state: StateManager,
    artifacts: LocalArtifactVersionRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    collection: MacosProcessCollectionObservation,
    version: int,
) -> ESProcess:
    """Prepare a complete process target for one sealed exec without replacing live State.

    This is a process snapshot, not an ES exec event or event-family admission.
    Full exec fields, collector sequencing and atomic native publication remain
    separate owners. A prepared result supplies no authority to commit the cohort.
    """
    if (
        type(state) is not StateManager
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(collection) is not MacosProcessCollectionObservation
    ):
        raise StateError("Planned ES exec target requires exact canonical owners")
    collection.__post_init__()
    with state._lock:
        relationships = state.observe_planned_execution_relationships(cohort)
        target = relationships.parent.process
        if collection.process != target or collection.observed_at != target.execution_started_at:
            raise StateError("Planned ES exec target requires its exact execution observation")
        return _project_runtime_process(artifacts, relationships, collection, version=version)


def prepare_planned_runtime_es_terminal_process(
    state: StateManager,
    artifacts: LocalArtifactVersionRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    collection: MacosProcessCollectionObservation,
    version: int,
) -> ESProcess:
    """Freeze one terminal process snapshot before the canonical lifetime closes.

    A process snapshot is distinct from an exit event. Explicit outcome facts,
    target-version wire admission and atomic sink publication remain required.
    No unknown exit status, collector membership or file fact is synthesized.
    """
    if (
        type(state) is not StateManager
        or type(artifacts) is not LocalArtifactVersionRegistry
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(collection) is not MacosProcessCollectionObservation
    ):
        raise StateError("Planned ES terminal process requires exact canonical owners")
    collection.__post_init__()
    with state._lock:
        relationships = state.observe_planned_termination_relationships(
            cohort, process=collection.process
        )
        if (
            collection.process != relationships.parent.process
            or collection.observed_at != relationships.parent.observed_at
        ):
            raise StateError("Planned ES terminal process requires its exact terminal observation")
        return _project_runtime_process(artifacts, relationships, collection, version=version)


def prepare_planned_installed_es_process_snapshot(
    state: StateManager,
    deployments: DeploymentContentRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    collection: MacosProcessCollectionObservation,
    metadata: MacosFileMetadata,
    phase: Literal["birth", "exec", "terminal"],
    version: int,
) -> ESProcess:
    """Prepare an installed process at an explicitly selected canonical transition.

    Deployment resolves the retained release/placement; a modeled filesystem
    owner must still supply exact stat. The selected sealed State boundary owns
    birth/exec/terminal time and relationships, with its existing composition
    limits. This helper grants no native event admission or commit authority.
    """
    if (
        type(state) is not StateManager
        or type(deployments) is not DeploymentContentRegistry
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(collection) is not MacosProcessCollectionObservation
        or type(phase) is not str
        or phase not in {"birth", "exec", "terminal"}
    ):
        raise StateError("Planned installed ES process requires exact canonical owners and phase")
    collection.__post_init__()
    with state._lock:
        if phase == "birth":
            relationships = state.observe_planned_process_relationships(
                cohort, process=collection.process
            )
        elif phase == "exec":
            relationships = state.observe_planned_execution_relationships(cohort)
        else:
            relationships = state.observe_planned_termination_relationships(
                cohort, process=collection.process
            )
        if (
            collection.process != relationships.parent.process
            or collection.observed_at != relationships.parent.observed_at
        ):
            raise StateError("Planned installed ES process requires its exact phase observation")
        return _project_installed_process(
            deployments, relationships, collection, metadata=metadata, version=version
        )
