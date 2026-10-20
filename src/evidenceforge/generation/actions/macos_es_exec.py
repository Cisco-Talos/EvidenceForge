# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare historical exec bytes from one authenticated transition and explicit facts.

This does not enable a source or commit State, artifacts, counters or a native
sink. Target macOS 26 exec evidence and native source admission stay gated.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.es_collector import ESDeliveryPreparation, PreparedESDeliveryCommit
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_file import MacosFileMetadata, detach_file_metadata
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    ESAction,
    ESExec,
    ESExecEvent,
    ESFileDescriptor,
    ESPipe,
    ESThread,
)
from evidenceforge.formats.macos_exec_image import es_exec_image_fields
from evidenceforge.formats.macos_file_metadata import (
    es_directory_at_execution,
)
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_installed_es_process_snapshot,
    prepare_planned_runtime_es_exec_target,
    prepare_planned_runtime_es_source,
    project_runtime_es_exec_script,
)
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MacosBootClock
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc


@dataclass(frozen=True, slots=True)
class PreparedMacosExecRecord:
    """Frozen native bytes and collector claim, without canonical commit authority."""

    ndjson: str
    collector: PreparedESDeliveryCommit


@contextmanager
def prepared_es_exec_record(
    owner: ESCollectionActionOwner,
    executables: LocalArtifactVersionRegistry,
    *,
    cohort: ActionCohortMaterializationPlan,
    delivery: ESDeliveryPreparation,
    collector_process: ProcessIdentity,
    before: MacosProcessCollectionObservation,
    after: MacosProcessCollectionObservation,
    descriptors: MacosExecDescriptorObservation,
    thread: ThreadIdentity,
    clock: MacosBootClock,
    action: ESAction,
    version: int,
    deployments: DeploymentContentRegistry | None = None,
    before_installed_file: MacosFileMetadata | None = None,
    after_installed_file: MacosFileMetadata | None = None,
    installed_filesystem: MacosInstalledFilesystem | None = None,
) -> Iterator[PreparedMacosExecRecord]:
    """Freeze historical v6/v9 runtime exec before replacing the live execution.

    The old initiating thread and before/after image identities remain distinct.
    Both executable versions and any script must already exist. Installed
    images require explicit exact stat and their immutable deployment owner.
    A distinct live collector observes the event; self-exec remains outside
    this profile. All arguments, environment,
    cwd, script presence, image slice and native FD fields must be explicit.
    Completed retries reuse retained bytes instead of observing a later State.
    """
    if (
        type(owner) is not ESCollectionActionOwner
        or type(executables) is not LocalArtifactVersionRegistry
        or (deployments is not None and type(deployments) is not DeploymentContentRegistry)
        or (
            installed_filesystem is not None
            and type(installed_filesystem) is not MacosInstalledFilesystem
        )
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(delivery) is not ESDeliveryPreparation
        or type(before) is not MacosProcessCollectionObservation
        or type(after) is not MacosProcessCollectionObservation
        or type(descriptors) is not MacosExecDescriptorObservation
        or type(thread) is not ThreadIdentity
        or type(clock) is not MacosBootClock
        or type(action) is not ESAction
        or type(version) is not int
        or version not in {6, 9}
    ):
        raise StateError("Native exec preparation requires exact owners and a historical profile")
    if installed_filesystem is not None:
        if (
            deployments is None
            or before_installed_file is not None
            or after_installed_file is not None
        ):
            raise StateError("Installed exec requires one exact filesystem fact owner")
        has_installed = False
        if (
            before.process.executable_version is not None
            and before.process.executable_version.identity_kind == "installed_release"
        ):
            before_installed_file = installed_filesystem.observe(
                deployments, before.process, observed_at=before.observed_at
            ).metadata
            has_installed = True
        if (
            after.process.executable_version is not None
            and after.process.executable_version.identity_kind == "installed_release"
        ):
            after_installed_file = installed_filesystem.observe(
                deployments, after.process, observed_at=after.observed_at
            ).metadata
            has_installed = True
        if not has_installed:
            raise StateError("Runtime exec stat must come from its retained artifact")
    for identity, metadata in (
        (before.process, before_installed_file),
        (after.process, after_installed_file),
    ):
        reference = identity.executable_version
        if reference is None:
            raise StateError("Native exec requires both exact loaded versions")
        if reference.identity_kind == "installed_release":
            if deployments is None or type(metadata) is not MacosFileMetadata:
                raise StateError("Installed exec requires its deployment owner and explicit stat")
        elif metadata is not None:
            raise StateError("Runtime exec stat must come from its retained artifact")
    if before_installed_file is not None:
        before_installed_file = detach_file_metadata(before_installed_file)
    if after_installed_file is not None:
        after_installed_file = detach_file_metadata(after_installed_file)
    before.__post_init__()
    after.__post_init__()
    descriptors.__post_init__()
    action = ESAction.model_validate_json(action.model_dump_json())
    if action.result.result.auth != 0:
        raise StateError("Successful native exec cannot carry a denied authorization result")
    state = owner.state
    if owner.collectors.completed_observation(delivery) is not None:
        raise StateError("Completed exec delivery must reuse its retained native bytes")
    with owner.prepared_commit(delivery, collector_process) as claimed:
        state.validate_action_cohort_materialization(cohort)
        owner.validate_observing_cohort(
            cohort, collector_process, observed_at=claimed.observation.observed_at
        )
        owner.validate_client_observation(before)
        owner.validate_client_observation(after)
        execution = next(
            (item for item in cohort.process_executions if item.after == after.process), None
        )
        if execution is None:
            raise StateError("Native exec preparation requires one exact execution transition")
        at = after.process.execution_started_at
        observation = claimed.observation
        if (
            execution.target != before.process
            or execution.after != after.process
            or before.observed_at != at
            or after.observed_at != at
            or observation.observed_at != at
            or observation.event_type != 9
            or observation.occurrence_id != f"process-exec:{after.process.execution_id}"
            or observation.hostname != before.process.hostname
            or before.process.object_id == collector_process.object_id
            or clock.hostname.casefold() != before.process.hostname.casefold()
            or thread.hostname != before.process.hostname
            or thread.process_object_id != before.process.object_id
            or thread.pid != before.process.pid
            or thread.started_at > at
            or state.get_thread(*thread.canonical_key) != thread
            or execution.descriptors_after is None
            or descriptors.table != execution.descriptors_after
        ):
            raise StateError(
                "Native exec preparation requires exact execution, FD and thread facts"
            )
        if before_installed_file is not None:
            assert deployments is not None
            actor = prepare_planned_installed_es_process_snapshot(
                state,
                deployments,
                cohort=cohort,
                phase="exec_source",
                collection=before,
                metadata=before_installed_file,
                version=version,
            )
        else:
            actor = prepare_planned_runtime_es_source(
                state, executables, cohort=cohort, collection=before, source="exec", version=version
            )
        if after_installed_file is not None:
            assert deployments is not None
            target = prepare_planned_installed_es_process_snapshot(
                state,
                deployments,
                cohort=cohort,
                collection=after,
                metadata=after_installed_file,
                phase="exec",
                version=version,
            )
        else:
            target = prepare_planned_runtime_es_exec_target(
                state, executables, cohort=cohort, collection=after, version=version
            )
        identity = after.process
        if (
            identity.arguments is None
            or identity.environment is None
            or identity.exec_script is None
        ):
            raise StateError(
                "Native exec requires known arguments, environment and script presence"
            )
        reference = identity.executable_version
        assert reference is not None
        if reference.identity_kind == "installed_release":
            assert deployments is not None
            binary = deployments.resolve_binary(
                identity.hostname, identity.image, "macos", principal=identity.principal
            )
        else:
            assert reference.artifact_version_id is not None
            image = executables.resolve_version(reference.artifact_version_id)
            binary = None if image is None else image.binary
        if binary is None:
            raise StateError("Native exec lost its exact executable")
        context = ProcessContext(
            identity.pid,
            identity.parent_pid,
            identity.image,
            identity.command_line,
            identity.principal,
            logon_id=identity.logon_id,
            start_time=identity.started_at,
            binary_identity=binary,
        )
        try:
            image_fields = es_exec_image_fields(identity, context, version=version)
            cwd = es_directory_at_execution(identity)
            script_file = project_runtime_es_exec_script(executables, identity)
        except ValueError as error:
            raise StateError(f"Incomplete historical exec metadata: {error}") from error
        fds = tuple(
            ESFileDescriptor(fd=item.fd, fdtype=item.fdtype, pipe=ESPipe(pipe_id=item.pipe_id))
            if item.pipe_id is not None
            else ESFileDescriptor(fd=item.fd, fdtype=item.fdtype)
            for item in descriptors.descriptors
        )
        record = EndpointSecurityRecord(
            schema_version=1,
            version=version,
            event_type=9,
            action_type=1,
            action=action,
            time=ensure_utc(at).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
            mach_time=clock.ticks_at(at),
            seq_num=observation.seq_num,
            global_seq_num=observation.global_seq_num,
            thread=ESThread(thread_id=thread.tid),
            process=actor,
            event=ESExecEvent(
                exec=ESExec(
                    target=target,
                    script=script_file,
                    cwd=cwd,
                    args=identity.arguments,
                    env=identity.environment,
                    fds=fds,
                    last_fd=descriptors.last_fd,
                    **image_fields,
                )
            ),
        )
        yield PreparedMacosExecRecord(
            claimed.freeze_native_projection(
                record.to_ndjson(), canonical_token=cohort.publication_token
            ),
            claimed,
        )
