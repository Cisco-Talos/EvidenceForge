# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native file observations committed by the existing canonical action journal."""

from collections.abc import Iterator
from contextlib import contextmanager

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.formats.macos_endpoint_security import EndpointSecurityRecord, ESAction, ESThread
from evidenceforge.formats.macos_file_operation import es_file_operation_payload
from evidenceforge.generation.macos_endpoint_security import (
    prepare_installed_es_process_snapshot,
    prepare_runtime_es_process_snapshot,
)
from evidenceforge.generation.macos_es_ingress import ESProcessIngressRow
from evidenceforge.generation.macos_es_publication import (
    MacosESPublication,
    _binding,
    _decision,
    _observation,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc


def file_occurrence(event: CanonicalOccurrence) -> tuple[str, int]:
    """Name a file occurrence by its canonical key, never its rendered path."""
    observation = event.file.macos_operation if event.file is not None else None
    if observation is None or event.occurrence_key is None:
        raise StateError(
            "Native file observation requires its canonical operation and occurrence key"
        )
    return "file:" + event.occurrence_key.occurrence_id, {
        "create": 13,
        "close": 12,
        "rename": 25,
        "unlink": 32,
    }[observation.operation]


@contextmanager
def prepared_macos_es_file_publication(
    dispatcher: EventDispatcher,
    cohort: ActionCohortMaterializationPlan,
    events: tuple[CanonicalOccurrence, ...],
) -> Iterator[MacosESPublication | None]:
    """Freeze explicit file/process facts before any canonical owner commits."""
    host = events[0].src_host
    if host is None or host.os_category != "macos":
        raise StateError("Native filesystem publication requires a modeled Mac host")
    source = _binding(dispatcher, host.hostname)
    if source is None:
        if "macos_endpoint_security" in dispatcher.emitters:
            raise StateError(
                "Native filesystem publication requires an activated qualified ES source"
            )
        yield None
        return
    if source.profile.file_operations is None:
        if "macos_endpoint_security" in dispatcher.emitters:
            raise StateError(
                "Frozen ES profile does not admit filesystem operations; select the qualified process/file profile"
            )
        yield None
        return
    ingress = dispatcher.macos_es_ingress
    if ingress is None or not ingress.enabled:
        raise StateError("Native filesystem publication requires chronological occurrence ingress")
    dispatcher.state_manager.validate_action_cohort_materialization(cohort)
    connection = source.connection()
    if connection.closed_at is not None or any(
        not source.coverage.known_from <= event.timestamp < source.coverage.known_until
        for event in events
    ):
        yield None
        return
    collector = dispatcher.state_manager.get_process_identity_by_object_id(
        connection.process.object_id
    )
    if collector is None:
        raise StateError("Native filesystem publication lost its exact collector execution")
    rows: list[ESProcessIngressRow] = []
    for event in events:
        operation = event.file.macos_operation
        actor = event.identity_plan.actor if event.identity_plan is not None else None
        if (
            type(actor) is not ProcessIdentity
            or actor.hostname != host.hostname
            or event.src_host != host
            or operation is None
            or operation.observed_at != event.timestamp
            or actor.executable_version is None
            or actor.primary_thread is None
        ):
            raise StateError(
                "Native filesystem operation requires its exact live writer and file facts"
            )
        operation.__post_init__()
        occurrence, family = file_occurrence(event)
        decision = _decision(dispatcher, event)
        body = None
        if decision.status in {"visible", "delayed"}:
            collection = _observation(source, actor, event)
            if actor.executable_version.identity_kind == "installed_release":
                snapshot = prepare_installed_es_process_snapshot(
                    dispatcher.state_manager,
                    dispatcher.deployment_registry,
                    process=actor,
                    collection=collection,
                    version=11,
                    filesystem=dispatcher.macos_installed_filesystem,
                )
            else:
                snapshot = prepare_runtime_es_process_snapshot(
                    dispatcher.state_manager,
                    dispatcher.local_artifact_registry,
                    process=actor,
                    collection=collection,
                    version=11,
                )
            record = EndpointSecurityRecord(
                schema_version=1,
                version=11,
                event_type=family,
                action_type=1,
                action=ESAction.model_validate(
                    {"result": {"result_type": 0, "result": {"auth": 0}}}
                ),
                time=ensure_utc(event.timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
                mach_time=source.clock.ticks_at(event.timestamp),
                seq_num=0,
                global_seq_num=0,
                thread=ESThread(thread_id=actor.primary_thread.tid),
                process=snapshot,
                event=es_file_operation_payload(operation),
            )
            body = record.model_dump_json(exclude={"seq_num", "global_seq_num"}, exclude_unset=True)
        rows.append(
            ESProcessIngressRow(
                host=host,
                initial=connection,
                occurrence_id=occurrence,
                event_type=family,
                reason="supported",
                storyline_cluster_id=event.storyline_cluster_id,
                observed_at=event.timestamp,
                status=decision.status,
                delay=decision.delay,
                native_body=body,
            )
        )
    yield MacosESPublication(
        None, collector, None, ingress.prepare(cohort.publication_token, tuple(rows))
    )
