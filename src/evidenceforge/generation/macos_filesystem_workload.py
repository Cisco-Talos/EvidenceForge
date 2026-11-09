# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded application-owned document activity through canonical filesystem actions."""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from evidenceforge.events.content_identity import (
    FileContentIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
)
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_file import MacosFileMetadata, MacosFileTime
from evidenceforge.events.macos_file_operation import MacosFileOperationObservation
from evidenceforge.events.macos_filesystem_state import MacosFilesystemChange
from evidenceforge.generation.actions.macos_filesystem import (
    MacosFilesystemActionBundle,
    MacosFilesystemRequest,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid

if TYPE_CHECKING:
    from evidenceforge.events.dispatcher import (
        ActionCohortPublicationReceipt,
        PreparedActionCohortBatch,
        PreparedActionCohortCapability,
    )
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import System


def file_time(at: datetime) -> MacosFileTime:
    """Convert canonical UTC time without floating-point timestamp rounding."""
    delta = at.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return MacosFileTime(
        seconds=delta.days * 86400 + delta.seconds, nanoseconds=delta.microseconds * 1000
    )


def placement_owner(record: LocalArtifactVersionRecord) -> str:
    """Name only the current-placement lease, independent of loaded-image leases."""
    return "macos-document-placement:" + record.artifact.artifact_id


class MacosFilesystemWorkflow:
    """Retain one phase's exact receipt across commit and source-tail failures."""

    def __init__(
        self, bundle: MacosFilesystemActionBundle, requests: tuple[MacosFilesystemRequest, ...]
    ) -> None:
        self.bundle, self.requests = bundle, requests
        self.index = 0
        self.batch: PreparedActionCohortBatch | None = None
        self.capability: PreparedActionCohortCapability | None = None
        self.receipt: ActionCohortPublicationReceipt | None = None

    def run(self) -> None:
        """Finish every phase without repeating a committed file operation."""
        dispatcher = self.bundle.dispatcher
        while self.index < len(self.requests):
            request = self.requests[self.index]
            if self.batch is None:
                self.batch = self.bundle.prepare(request)
            try:
                if self.receipt is None:
                    with dispatcher.claimed_action_cohort(self.batch) as capability:
                        self.capability = capability
                        try:
                            capability.commit_no_fail()
                        finally:
                            if capability.committed:
                                self.receipt = capability.receipt
                elif not self.capability.projection_complete:
                    dispatcher.resume_action_cohort_projection(self.receipt)
            except BaseException:
                if self.receipt is None:
                    dispatcher.cancel_prepared_action_cohort_batch(self.batch)
                    self.batch = self.capability = None
                raise
            # Canonical commit is already authenticated. Idempotent lease cleanup
            # may be retried before moving on; it produces no new source rows.
            operation = request.observation
            retired = tuple(
                item
                for item in (
                    operation.previous,
                    operation.replacement,
                    operation.source if operation.operation in {"rename", "unlink"} else None,
                )
                if item is not None
            )
            for record in retired:
                dispatcher.local_artifact_registry.release_lease(
                    record.artifact.artifact_version_id, placement_owner(record)
                )
            self.index += 1
            self.batch = self.capability = self.receipt = None


def document_requests(
    engine: GenerationEngine,
    host: HostContext,
    actor: ProcessIdentity,
    at: datetime,
    filename: str,
    size: int,
    delay: float,
    action_id: str,
    *,
    mode: Literal["write_close", "atomic_replace"] = "write_close",
    cleanup: bool = False,
) -> tuple[MacosFilesystemRequest, ...]:
    """Plan a nominal save with shared, explicit directory and inode truth."""
    provider = engine.macos_execution_metadata
    if provider is None or provider.profile.filesystem_workload is None:
        raise StateError("Mac document activity requires its configured execution metadata")
    policy = provider.profile.filesystem_workload
    if mode not in {"write_close", "atomic_replace"} or filename not in policy.filenames:
        raise StateError("Mac document activity requires a configured filename and supported save")
    state, registry = engine.state_manager, engine.dispatcher.local_artifact_registry
    account = engine._identity_directory.macos_account(actor.principal, host.hostname)
    if account is None or actor.credentials is None or registry is None:
        raise StateError("Mac document save requires its compiled account and artifact owner")
    directory_path = account.home + "/" + policy.directory_name
    directory = provider.directory(host.hostname, directory_path, at)
    path = directory_path + "/" + filename
    existing = registry.resolve_record_for_execution_path(
        host.hostname, actor.principal, path, "macos"
    )
    if existing is not None and existing.artifact.family != "modeled-document":
        raise StateError("Mac document workload cannot overwrite an unrelated modeled file")
    requests: list[MacosFilesystemRequest] = []
    allocation = None
    after = directory
    if existing is None or mode == "atomic_replace":
        inode = state.macos_filesystem_next_inode(host.hostname, policy.first_inode)
        allocation = policy.first_inode, inode - 1, inode
        object_id = stable_uuid("macos-runtime-file-object", host.hostname.casefold(), inode)
        user = engine.deployment_registry.user_profile_for(host.hostname, actor.principal, "macos")
        installation = engine.deployment_registry.installation_for_image(
            host.hostname, actor.image, "macos", principal=actor.principal
        )
        profile = engine.deployment_registry.application_profile_for(
            user.profile_id, installation.installation_id, installation.application_id
        )
        if profile is None:
            raise StateError("Mac document save requires its exact installed application profile")
        stamp = file_time(at)
        metadata = MacosFileMetadata(
            volume_id=directory.metadata.volume_id,
            file_object_id=object_id,
            device=directory.metadata.device,
            inode=inode,
            mode=0o100000 | policy.file_permissions,
            link_count=1,
            uid=actor.credentials.effective_uid,
            gid=actor.credentials.effective_gid,
            special_device=0,
            accessed=stamp,
            modified=stamp,
            changed=stamp,
            born=stamp,
            size_bytes=0,
            allocated_blocks=0,
            preferred_block_size=directory.metadata.preferred_block_size,
            flags=0,
            generation=0,
        )
        content = FileContentIdentity(object_id, 1, 0, "text/plain", action_id)
        source_path = (
            path
            if mode == "write_close"
            else directory_path + "/." + filename + "." + action_id[:8] + ".tmp"
        )
        artifact = LocalArtifactIdentity(
            host.hostname,
            actor.principal,
            "macos",
            user.profile_id,
            profile.application_profile_id,
            installation.application_id,
            "modeled-document",
            object_id,
            source_path,
            content.content_id,
        )
        empty = LocalArtifactVersionRecord(artifact, content, macos_file=metadata)
        after = replace(
            directory,
            metadata=directory.metadata.model_copy(
                update={
                    "modified": stamp,
                    "changed": stamp,
                    "size_bytes": directory.metadata.size_bytes + policy.directory_entry_bytes,
                }
            ),
        )
        requests.append(
            MacosFilesystemRequest(
                action_id + ":create",
                host,
                actor,
                MacosFileOperationObservation("create", empty, at),
                filesystem_change=MacosFilesystemChange(directory, after, allocation),
            )
        )
    else:
        empty = existing
    closed_at = at + timedelta(seconds=delay)
    # Write completes before close; the native close observes its resulting stat.
    written = file_time(at + timedelta(seconds=delay / 2))
    content = FileContentIdentity(
        empty.content.file_object_id,
        empty.content.version + 1,
        size,
        empty.content.mime_type,
        action_id,
    )
    full = replace(
        empty,
        content=content,
        artifact=replace(
            empty.artifact, content_id=content.content_id, version=empty.artifact.version + 1
        ),
        macos_file=empty.macos_file.model_copy(
            update={
                "modified": written,
                "changed": written,
                "size_bytes": size,
                "allocated_blocks": policy.allocated_blocks,
            }
        ),
    )
    lease_until = engine.end_time + timedelta(hours=48, seconds=1)
    requests.append(
        MacosFilesystemRequest(
            action_id + ":close",
            host,
            actor,
            MacosFileOperationObservation(
                "close", full, closed_at, previous=empty, modified=True, was_mapped_writable=False
            ),
            placement_lease_owner=placement_owner(full) if mode == "write_close" else "",
            placement_lease_until=lease_until if mode == "write_close" else None,
        )
    )
    final = full
    finished_at = closed_at
    if mode == "atomic_replace":
        renamed_at = closed_at + timedelta(seconds=delay)
        before = replace(after, observed_at=renamed_at)
        stamp = file_time(renamed_at)
        final_directory = replace(
            before,
            metadata=before.metadata.model_copy(
                update={
                    "modified": stamp,
                    "changed": stamp,
                    "size_bytes": before.metadata.size_bytes
                    - (policy.directory_entry_bytes if existing else 0),
                }
            ),
        )
        target = replace(
            full,
            artifact=replace(full.artifact, native_path=path, version=full.artifact.version + 1),
            macos_file=full.macos_file.model_copy(update={"changed": stamp}),
        )
        requests.append(
            MacosFilesystemRequest(
                action_id + ":rename",
                host,
                actor,
                MacosFileOperationObservation(
                    "rename",
                    full,
                    renamed_at,
                    parent=before,
                    target=target,
                    replacement=existing,
                ),
                filesystem_change=MacosFilesystemChange(before, final_directory),
                placement_lease_owner=placement_owner(target),
                placement_lease_until=lease_until,
            )
        )
        after, final, finished_at = final_directory, target, renamed_at
    if cleanup:
        removed_at = finished_at + timedelta(seconds=delay)
        before = replace(after, observed_at=removed_at)
        stamp = file_time(removed_at)
        removed_directory = replace(
            before,
            metadata=before.metadata.model_copy(
                update={
                    "modified": stamp,
                    "changed": stamp,
                    "size_bytes": before.metadata.size_bytes - policy.directory_entry_bytes,
                }
            ),
        )
        requests.append(
            MacosFilesystemRequest(
                action_id + ":unlink",
                host,
                actor,
                MacosFileOperationObservation("unlink", final, removed_at, parent=before),
                filesystem_change=MacosFilesystemChange(before, removed_directory),
            )
        )
    return tuple(requests)


@dataclass(frozen=True, slots=True)
class MacosDocumentIntent:
    """One already sampled activity, retained without repeating RNG on retry."""

    actor: ProcessIdentity
    at: datetime
    filename: str
    size: int
    delay: float
    action_id: str
    mode: Literal["write_close", "atomic_replace"]
    cleanup: bool


class MacosFilesystemBatch:
    """Retain the complete bounded activity page and its current exact phase."""

    def __init__(
        self, engine: GenerationEngine, host: HostContext, intents: tuple[MacosDocumentIntent, ...]
    ) -> None:
        self.engine, self.host, self.intents = engine, host, intents
        self.index = 0
        self.workflow: MacosFilesystemWorkflow | None = None

    def run(self) -> None:
        while self.index < len(self.intents):
            item = self.intents[self.index]
            if self.workflow is None:
                self.workflow = MacosFilesystemWorkflow(
                    MacosFilesystemActionBundle(self.engine.dispatcher),
                    document_requests(
                        self.engine,
                        self.host,
                        item.actor,
                        item.at,
                        item.filename,
                        item.size,
                        item.delay,
                        item.action_id,
                        mode=item.mode,
                        cleanup=item.cleanup,
                    ),
                )
            self.workflow.run()
            self.workflow = None
            self.index += 1


def emit_macos_document_workload(
    engine: GenerationEngine,
    system: System,
    hour: datetime,
    rng: random.Random,
) -> None:
    """Run a small configured workload for actual eligible live app executions."""
    generator = engine.activity_generator
    provider = engine.macos_execution_metadata
    policy = provider.profile.filesystem_workload
    pending = generator._macos_filesystem_workflows
    batch_key = system.hostname.casefold() + ":" + hour.isoformat()
    if pending:
        if set(pending) != {batch_key}:
            raise StateError("Finish the pending filesystem activity page before another hour")
        pending[batch_key].run()
        del pending[batch_key]
        return
    if rng.random() < policy.idle_probability:
        return
    count = rng.randint(policy.count_min, policy.count_max)
    times = sorted(
        hour
        + generator._sample_activity_gap(
            relationship_key="macos.document.task_offset",
            stable_id=batch_key,
            host=system.hostname,
            ordinal=index,
            minimum_ms=0,
            maximum_ms=(3599 - 3 * policy.close_delay_max) * 1000,
        )
        for index in range(count)
    )
    intents: list[MacosDocumentIntent] = []
    previous_end = hour
    for index, at in enumerate(times):
        at = max(at, previous_end)
        delay = generator._sample_activity_gap(
            relationship_key="macos.document.modified_close",
            stable_id=batch_key,
            host=system.hostname,
            ordinal=index,
            minimum_ms=policy.close_delay_min * 1000,
            maximum_ms=policy.close_delay_max * 1000,
        ).total_seconds()
        end = at + timedelta(seconds=3 * delay)
        if not engine._baseline_pass_admits(hour, start=at) or end >= min(
            engine.end_time, hour + timedelta(hours=1)
        ):
            continue
        eligible: list[ProcessIdentity] = []
        for process in engine.state_manager.get_processes_on_system(system.hostname):
            if (
                process.start_time > at
                or not engine.state_manager.is_process_active_at(system.hostname, process.pid, at)
                or not engine.state_manager.is_process_active_at(system.hostname, process.pid, end)
                or generator._foreground_process_expired_for_attribution(system, process, end)
            ):
                continue
            actor = engine.state_manager.get_process_identity_at(system.hostname, process.pid, end)
            if (
                actor is None
                or actor.credentials is None
                or actor.executable_version is None
                or actor.primary_thread is None
                or actor.image_security is None
            ):
                continue
            installation = engine.deployment_registry.installation_for_image(
                system.hostname, actor.image, "macos", principal=actor.principal
            )
            if installation is not None and installation.application_id in policy.applications:
                eligible.append(actor)
        if not eligible:
            continue
        actor = rng.choice(sorted(eligible, key=lambda item: item.object_id))
        action_id = stable_uuid(
            "macos-document-save",
            system.hostname,
            actor.object_id,
            hour.isoformat(),
            index,
            at.isoformat(),
        )
        intents.append(
            MacosDocumentIntent(
                actor,
                at,
                rng.choice(policy.filenames),
                rng.randint(policy.size_min, policy.size_max),
                delay,
                action_id,
                "atomic_replace"
                if rng.random() < policy.atomic_replace_probability
                else "write_close",
                rng.random() < policy.cleanup_probability,
            )
        )
        previous_end = end + timedelta(microseconds=1)
    if intents:
        batch = MacosFilesystemBatch(engine, generator._build_host_context(system), tuple(intents))
        pending[batch_key] = batch
        batch.run()
        del pending[batch_key]
