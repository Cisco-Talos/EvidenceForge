# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Complete native process-cohort preparation from explicit canonical facts."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace

from evidenceforge.events.es_collector import (
    ESDeliveryBatchPreparation,
    PreparedESDeliveryBatchCommit,
)
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_file import MacosFileMetadata
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.formats.macos_endpoint_security import ESAction
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.actions.macos_es_exec import _exec_record
from evidenceforge.generation.actions.macos_es_exit import MacosExitRecordInput, _exit_record
from evidenceforge.generation.actions.macos_es_fork import _fork_record
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MacosBootClock
from evidenceforge.models.exceptions import StateError


@dataclass(frozen=True, slots=True)
class MacosForkRecordInput:
    """Exact explicitly selected fork observations and admitted historical wire profile."""

    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry
    parent: MacosProcessCollectionObservation
    child: MacosProcessCollectionObservation
    thread: ThreadIdentity
    action: ESAction
    version: int
    installed_file: MacosFileMetadata | None = None
    installed_filesystem: MacosInstalledFilesystem | None = None


@dataclass(frozen=True, slots=True)
class MacosExecRecordInput:
    """Exact before/after metadata for one selected image replacement."""

    executables: LocalArtifactVersionRegistry | None
    before: MacosProcessCollectionObservation
    after: MacosProcessCollectionObservation
    descriptors: MacosExecDescriptorObservation
    thread: ThreadIdentity
    action: ESAction
    version: int
    deployments: DeploymentContentRegistry | None = None
    before_installed_file: MacosFileMetadata | None = None
    after_installed_file: MacosFileMetadata | None = None
    installed_filesystem: MacosInstalledFilesystem | None = None


@dataclass(frozen=True, slots=True)
class PreparedMacosProcessRecords:
    """Frozen complete native records under one exact collector reservation."""

    ndjson: tuple[str | None, ...]
    collector: PreparedESDeliveryBatchCommit


@contextmanager
def prepared_es_process_records(
    owner: ESCollectionActionOwner,
    *,
    cohort: ActionCohortMaterializationPlan,
    delivery: ESDeliveryBatchPreparation,
    collector_process: ProcessIdentity,
    records: tuple[MacosForkRecordInput | MacosExecRecordInput | MacosExitRecordInput | None, ...],
    clock: MacosBootClock,
) -> Iterator[PreparedMacosProcessRecords]:
    """Freeze every selected canonical process phase without committing any owner.

    Each record selects its existing admitted historical codec. A heterogeneous
    historical test batch makes no assertion about one actual macOS build.
    Missing metadata rejects the entire preparation; native rows never generate
    canonical actions. Source admission remains separate.
    """
    if (
        type(owner) is not ESCollectionActionOwner
        or type(cohort) is not ActionCohortMaterializationPlan
        or type(delivery) is not ESDeliveryBatchPreparation
        or type(collector_process) is not ProcessIdentity
        or type(clock) is not MacosBootClock
        or type(records) is not tuple
        or not 1 <= len(records) <= 256
        or any(
            item is not None
            and type(item) not in {MacosForkRecordInput, MacosExecRecordInput, MacosExitRecordInput}
            for item in records
        )
    ):
        raise StateError("Native process batch requires exact bounded canonical owners")
    if owner.collectors.completed_batch(delivery) is not None:
        raise StateError("Completed process batch must reuse its retained native bytes")
    with owner.prepared_batch_commit(delivery, collector_process) as claimed:
        owner.state.validate_action_cohort_materialization(cohort)
        expected = [
            (item.identity.started_at, 0, 11, f"process-fork:{item.identity.object_id}")
            for item in cohort.processes
            if item.forked
        ]
        expected += [
            (item.after.execution_started_at, 1, 9, f"process-exec:{item.after.execution_id}")
            for item in cohort.process_executions
        ]
        expected += [
            (item.end_time, 2, 15, f"process-exit:{item.identity.object_id}")
            for item in cohort.process_terminations
        ]
        expected.sort(key=lambda item: item[:2])
        boundary = owner.observing_execution_boundary(cohort, collector_process)
        if boundary is not None:
            expected = [item for item in expected if item[0] < boundary]
        if any(not item.forked for item in cohort.processes):
            raise StateError("Native process batch requires authenticated fork births")
        if (
            len(records) != len(expected)
            or len(records) != len(claimed.observations)
            or any(
                (item.observed_at, item.event_type, item.occurrence_id)
                != (at, event_type, occurrence_id)
                for item, (at, _, event_type, occurrence_id) in zip(
                    claimed.observations, expected, strict=True
                )
            )
        ):
            raise StateError(
                "Native process batch must cover every available ordered canonical phase once"
            )
        rendered: list[str | None] = []
        for supplied, observation in zip(records, claimed.observations, strict=True):
            if supplied is None:
                if observation.status in {"visible", "delayed"}:
                    raise StateError("Visible process phases require complete native record inputs")
                rendered.append(None)
                continue
            item = replace(supplied)
            common = dict(
                cohort=cohort,
                observation=observation,
                collector_process=collector_process,
                clock=clock,
            )
            if type(item) is MacosForkRecordInput:
                record = _fork_record(
                    owner,
                    item.executables,
                    **common,
                    parent=item.parent,
                    child=item.child,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    installed_file=item.installed_file,
                    installed_filesystem=item.installed_filesystem,
                )
            elif type(item) is MacosExecRecordInput:
                record = _exec_record(
                    owner,
                    item.executables,
                    **common,
                    before=item.before,
                    after=item.after,
                    descriptors=item.descriptors,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    deployments=item.deployments,
                    before_installed_file=item.before_installed_file,
                    after_installed_file=item.after_installed_file,
                    installed_filesystem=item.installed_filesystem,
                )
            else:
                record = _exit_record(
                    owner,
                    item.executables,
                    **common,
                    process=item.process,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    installed_file=item.installed_file,
                    installed_filesystem=item.installed_filesystem,
                )
            rendered.append(record.to_ndjson())
        yield PreparedMacosProcessRecords(
            claimed.freeze_native_projections(
                tuple(rendered), canonical_token=cohort.publication_token
            ),
            claimed,
        )
