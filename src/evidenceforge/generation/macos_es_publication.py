# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Select and freeze native process observations before exact canonical publication."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.es_collector import (
    ESCollectorObservation,
    ESDeliveryBatchPreparation,
    ESDeliveryPreparation,
    ESDeliveryRequest,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_process_observation import (
    MacosGUIExecResponsibilityObservation,
    MacosProcessCollectionObservation,
)
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.formats.macos_endpoint_security import ESAction
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner, _process
from evidenceforge.generation.actions.macos_es_exec import _exec_record, prepared_es_exec_record
from evidenceforge.generation.actions.macos_es_exit import (
    MacosExitRecordInput,
    _exit_record,
    prepared_es_exit_record,
)
from evidenceforge.generation.actions.macos_es_fork import _fork_record, prepared_es_fork_record
from evidenceforge.generation.actions.macos_es_process_batch import (
    MacosExecRecordInput,
    MacosForkRecordInput,
    prepared_es_process_records,
)
from evidenceforge.generation.activity.macos_endpoint_security_profiles import (
    load_macos_endpoint_security_profile,
)
from evidenceforge.generation.macos_es_source import MacosESSource, macos_es_source_instance
from evidenceforge.generation.timing.macos import MachTimebase, MacosBootClock
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
    from evidenceforge.generation.macos_es_ingress import PreparedESIngress
    from evidenceforge.generation.state_manager import (
        ActionCohortMaterializationPlan,
        MaterializationBatchPlan,
    )

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MacosESPublication:
    """Existing collector reservation and optional exact sink; no commit authority."""

    delivery: ESDeliveryPreparation | ESDeliveryBatchPreparation | None
    collector: ProcessIdentity
    sink: ExternalSortedLineWriter | None
    ingress: PreparedESIngress | None = None


def _binding(dispatcher: EventDispatcher, hostname: str) -> MacosESSource | None:
    connection = dispatcher.es_collectors.connection(macos_es_source_instance(hostname))
    if connection is None or connection.source_profile is None:
        return None
    stamp = connection.source_profile
    profile = load_macos_endpoint_security_profile(profile_id=stamp.profile_id)
    coverage = dispatcher.es_collectors.complete_membership_coverage(hostname)
    if profile is None or coverage is None or connection.process is None:
        raise StateError("Native ES publication lost its active frozen profile or inventory")
    source = MacosESSource(
        ESCollectionActionOwner(dispatcher.state_manager, dispatcher.es_collectors),
        profile,
        connection.source_instance,
        coverage,
        stamp,
        MacosBootClock(
            connection.hostname,
            stamp.boot_time,
            stamp.boot_uuid,
            MachTimebase(stamp.timebase_numerator, stamp.timebase_denominator),
        ),
    )
    source.connection()
    return source


def _decision(dispatcher: EventDispatcher, event: CanonicalOccurrence) -> ObservationDecision:
    from evidenceforge.events.collection_policy import CollectionCapability, ProjectionAdmission
    from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id

    host = event.src_host
    assert host is not None
    if "macos_endpoint_security" not in dispatcher.emitters:
        return ObservationDecision("filtered")
    deployment = dispatcher.collection_deployment
    decision = ObservationDecision("visible")
    if deployment is not None:
        instance = exact_source_instance_id("macos_endpoint_security", host.hostname)
        ordinal = deployment.ordinal_for_instance(instance)
        if ordinal is None:
            return ObservationDecision("filtered")
        occurrence, _ = dispatcher._es_process_occurrence(event)
        envelope = deployment.projection_envelope_by_ordinal(
            occurrence_id=occurrence,
            target_id=f"macos_endpoint_security:host:{ordinal}",
            source_ordinal=ordinal,
            canonical_time=event.timestamp,
            requested_capabilities=CollectionCapability.PROCESS,
        )
        if not envelope.admitted:
            return ObservationDecision(
                "out_of_window"
                if envelope.admission is ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW
                else "filtered"
            )
        policy = deployment.policy_by_ordinal(ordinal)
        decision = dispatcher.observation_policy.decide_projection(
            "macos_endpoint_security",
            event,
            source_instance=instance,
            source_hostname=host.hostname,
            missingness=policy.missingness_for("macos_endpoint_security"),
            format_specific="macos_endpoint_security" in policy.format_missingness,
        )
    exported = event.timestamp + decision.delay
    if (dispatcher.output_start_time is not None and exported < dispatcher.output_start_time) or (
        dispatcher.output_end_time is not None and exported >= dispatcher.output_end_time
    ):
        return ObservationDecision("out_of_window")
    return decision


def _observation(
    source: MacosESSource, process: ProcessIdentity, event: CanonicalOccurrence
) -> MacosProcessCollectionObservation:
    if process.job_control is None:
        raise StateError("Native ES publication requires explicit process group and session facts")
    terminal = source.owner.state.known_macos_terminal(process.job_control.session, event.timestamp)
    client = source.owner.collectors.known_client_membership(
        process.hostname, _process(process), event.timestamp
    )
    if terminal is None or client is None:
        raise StateError("Native ES publication requires known terminal and client observations")
    return MacosProcessCollectionObservation(
        process,
        event.timestamp,
        client,
        terminal,
        source.profile.boot_parent_token if process.pid == 1 and process.parent_pid == 0 else None,
    )


@contextmanager
def prepared_macos_es_process_publication(
    dispatcher: EventDispatcher,
    cohort: ActionCohortMaterializationPlan | MaterializationBatchPlan,
    events: tuple[CanonicalOccurrence, ...],
) -> Iterator[MacosESPublication | None]:
    """Join supported canonical phases to their existing atomic source journal.

    No aggregate process-create row becomes an exec. Unstarted/closed collectors
    and unknown terminal results remain unavailable; no successful status is
    invented. Exact known process chains retain every phase and all its counters.
    """
    from evidenceforge.generation.emitters.macos_endpoint_security import (
        MacosEndpointSecurityEmitter,
    )
    from evidenceforge.generation.state_manager import MaterializationBatchPlan

    if type(cohort) is MaterializationBatchPlan:
        dispatcher.state_manager.validate_macos_process_observation_plan(cohort)
        birth = cohort.processes[0]
        if (
            len(events) != 1
            or events[0].event_type != "process_fork"
            or events[0].identity_plan is None
            or events[0].identity_plan.subject != birth.identity
            or events[0].identity_plan.actor != birth.parent_identity
            or events[0].identity_plan.session != cohort.session.identity
        ):
            raise StateError("Deferred native publication requires its exact initial SSH fork")
        if dispatcher.macos_es_ingress is None or not dispatcher.macos_es_ingress.enabled:
            raise StateError("Deferred native publication requires occurrence ingress")

    # Canonical endpoint effects remain members of the exact action journal;
    # they are not additional native process observations or generation triggers.
    if any(
        event.event_type
        not in {"process_create", "process_fork", "process_exec", "process_terminate"}
        for event in events
    ):
        for event in events:
            if event.event_type in {
                "process_create",
                "process_fork",
                "process_exec",
                "process_terminate",
            }:
                continue
            if (
                event.file is None
                or event.registry is not None
                or event.effect_provenance is None
                or event.identity_plan is None
                or not any(
                    event.identity_plan.actor == execution.after
                    for execution in cohort.process_executions
                )
            ):
                yield None
                return
        events = tuple(
            event
            for event in events
            if event.event_type
            in {"process_create", "process_fork", "process_exec", "process_terminate"}
        )

    if not events or any(
        event.event_type
        not in {"process_create", "process_fork", "process_exec", "process_terminate"}
        or event.src_host is None
        or event.src_host.os_category != "macos"
        for event in events
    ):
        yield None
        return
    # A staged GUI launcher has an aggregate birth followed by an authenticated
    # app exec. Its birth is not a native fork/exec and must remain a separate
    # completeness obligation; it must not suppress the app's exact exec record.
    for event in events:
        if event.event_type == "process_create" and not any(
            birth.identity == event.identity_plan.subject
            and not birth._payload.forked
            and any(
                execution.target == birth.identity and execution.gui_session is not None
                for execution in cohort.process_executions
            )
            for birth in cohort.processes
        ):
            yield None
            return
    events = tuple(event for event in events if event.event_type != "process_create")
    if not events:
        yield None
        return
    # Some compatibility SSH closures also carry auth/session contexts. They
    # are not the exact process-only occurrences admitted by this native source.
    from evidenceforge.events.process import process_exit_identity

    try:
        for event in events:
            if event.event_type == "process_terminate":
                process_exit_identity(event)
    except ValueError:
        yield None
        return
    host = events[0].src_host
    assert host is not None
    if any(event.src_host.hostname != host.hostname for event in events):
        yield None
        return
    source = _binding(dispatcher, host.hostname)
    if source is None:
        yield None
        return
    connection = source.connection()
    if connection.closed_at is not None or any(
        not source.coverage.known_from <= event.timestamp < source.coverage.known_until
        for event in events
    ):
        yield None
        return
    assert connection.process is not None
    collector = dispatcher.state_manager.get_process_identity_by_object_id(
        connection.process.object_id
    )
    if collector is None:
        raise StateError("Native ES publication lost its exact live collector")
    boundary = source.owner.observing_execution_boundary(cohort, collector)
    events = tuple(event for event in events if boundary is None or event.timestamp < boundary)
    if not events:
        yield None
        return

    # Unsupported individual phases retain counter observations, with no native
    # bytes. A known fork remains available when later exec metadata is unknown.
    def phase_reason(event: CanonicalOccurrence) -> str:
        # A known terminal result cannot qualify an image whose exact loaded
        # version was never supplied. This is an unavailable source phase, not
        # a malformed complete projection or a reason to invent executable facts.
        subject = event.identity_plan.subject
        if subject.executable_version is None:
            return "executable_version_unknown"
        if event.event_type == "process_fork":
            actor = event.identity_plan.actor
            if (
                actor.pid == 1
                and actor.parent_pid == 0
                and actor.parentage is not None
                and actor.parentage.current is None
                and source.profile.boot_parent_token is None
            ):
                return "boot_parent_token_unknown"
        if event.event_type == "process_exec":
            execution = next(
                item
                for item in cohort.process_executions
                if item.after == event.identity_plan.subject
            )
            if execution.target.executable_version is None:
                return "executable_version_unknown"
            if execution.gui_session is not None:
                for snapshot in (execution.target, execution.after):
                    if (
                        snapshot.credentials is None
                        or snapshot.credentials.audit_uid is None
                        or snapshot.credentials.audit_session_id is None
                        or snapshot.audit_pid_version is None
                        or snapshot.job_control is None
                        or snapshot.parentage is None
                        or snapshot.responsibility is None
                        or snapshot.image_security is None
                        or snapshot.image_security.validation_category is None
                        or dispatcher.resolve_loaded_process_binary_identity(
                            snapshot
                        ).code_signature
                        is None
                    ):
                        return "gui_exec_metadata_unknown"
                if (
                    execution.after.environment is None
                    or execution.after.execution_directory is None
                    or execution.after.exec_image is None
                    or execution.after.exec_script is None
                ):
                    return "gui_exec_metadata_unknown"
                try:
                    MacosGUIExecResponsibilityObservation.from_transition(
                        execution.target, execution.after
                    )
                except ValueError:
                    return "gui_exec_metadata_unknown"
            binary = dispatcher.resolve_loaded_process_binary_identity(execution.after)
            if binary.code_signature is None or binary.code_signature.entitlements is None:
                return "entitlements_unknown"
            entitlements = binary.code_signature.entitlements
            policy = source.profile.exec_entitlements
            if entitlements != "absent" and not (
                policy == "absent_or_bounded_integer_object"
                or (
                    policy == "absent_or_bounded_object"
                    and all(type(value) is not int for _, value in entitlements)
                )
                or (
                    bool(entitlements)
                    and (
                        policy == "absent_or_boolean_object"
                        and all(type(value) is bool for _, value in entitlements)
                        or policy == "absent_boolean_or_string_array_object"
                        and all(type(value) in (bool, tuple) for _, value in entitlements)
                    )
                )
            ):
                return "entitlements_present"
            if execution.descriptors_after is None:
                return "descriptors_unknown"
            if execution.target.primary_thread not in execution.retired_threads:
                return "thread_replacement_unknown"
            return "supported"
        if event.event_type == "process_terminate":
            return (
                "supported"
                if any(
                    item.identity == event.identity_plan.subject and item.exit_outcome is not None
                    for item in cohort.process_terminations
                )
                else "exit_outcome_unknown"
            )
        return "supported"

    action = ESAction.model_validate(
        {
            "result": {
                "result_type": source.profile.result_type,
                "result": {"auth": source.profile.auth_result},
            }
        }
    )
    artifacts = dispatcher.local_artifact_registry
    deployments = dispatcher.deployment_registry
    filesystem = dispatcher.macos_installed_filesystem
    records: list[MacosForkRecordInput | MacosExecRecordInput | MacosExitRecordInput | None] = []
    decisions = tuple(
        _decision(dispatcher, event)
        if phase_reason(event) == "supported"
        else ObservationDecision("filtered")
        for event in events
    )
    try:
        for event, decision in zip(events, decisions, strict=True):
            if decision.status not in {"visible", "delayed"}:
                records.append(None)
                continue
            subject = event.identity_plan.subject
            if type(subject) is not ProcessIdentity or subject.executable_version is None:
                raise StateError("Native ES publication requires an exact loaded process version")
            installed = subject.executable_version.identity_kind == "installed_release"
            executable_owner = deployments if installed else artifacts
            if executable_owner is None:
                raise StateError("Native ES publication lost its executable fact owner")
            if event.event_type == "process_fork":
                parent = event.identity_plan.actor
                if type(parent) is not ProcessIdentity or parent.primary_thread is None:
                    raise StateError("Native fork requires its exact performing parent thread")
                records.append(
                    MacosForkRecordInput(
                        executable_owner,
                        _observation(source, parent, event),
                        _observation(source, subject, event),
                        parent.primary_thread,
                        action,
                        source.profile.message_version,
                        installed_filesystem=filesystem if installed else None,
                    )
                )
            elif event.event_type == "process_exec":
                execution = next(
                    item for item in cohort.process_executions if item.after == subject
                )
                if execution.descriptors_after is None or not execution.retired_threads:
                    raise StateError(
                        "Native exec requires exact descriptor, artifact and thread owners"
                    )
                records.append(
                    MacosExecRecordInput(
                        artifacts,
                        _observation(source, execution.target, event),
                        _observation(source, subject, event),
                        MacosExecDescriptorObservation.from_modeled_table(
                            execution.descriptors_after
                        ),
                        execution.target.primary_thread,
                        action,
                        source.profile.message_version,
                        deployments=deployments,
                        installed_filesystem=filesystem
                        if installed
                        or execution.target.executable_version.identity_kind == "installed_release"
                        else None,
                    )
                )
            else:
                if subject.primary_thread is None:
                    raise StateError("Native exit requires an exact final thread")
                records.append(
                    MacosExitRecordInput(
                        executable_owner,
                        _observation(source, subject, event),
                        subject.primary_thread,
                        action,
                        installed_filesystem=filesystem if installed else None,
                        version=source.profile.message_version,
                    )
                )
    except (ValueError, StateError) as error:
        if not any(decision.status in {"visible", "delayed"} for decision in decisions):
            records = [None] * len(events)
        else:
            raise StateError(f"Incomplete macOS 27 native process facts: {error}") from error
    ingress = dispatcher.macos_es_ingress
    if ingress is not None and ingress.enabled:
        from evidenceforge.generation.macos_es_ingress import ESProcessIngressRow

        snapshots: list[ESProcessIngressRow] = []
        for event, item, decision in zip(events, records, decisions, strict=True):
            occurrence, family = dispatcher._es_process_occurrence(event)
            # These zeroes are validation scaffolding for a message body only.
            # They are removed before ingress admission, never exported as counters.
            observation = ESCollectorObservation(
                source_instance=connection.source_instance,
                hostname=host.hostname,
                generation=connection.generation,
                delivery=0,
                occurrence_id=occurrence,
                event_type=family,
                observed_at=event.timestamp,
                collector_process=connection.process,
                seq_num=0,
                global_seq_num=0,
                status=decision.status,
                delay=decision.delay,
            )
            common = dict(
                cohort=cohort,
                observation=observation,
                collector_process=collector,
                clock=source.clock,
            )
            body = None
            if type(item) is MacosForkRecordInput:
                record = _fork_record(
                    source.owner,
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
                body = record.model_dump_json(
                    exclude={"seq_num", "global_seq_num"}, exclude_unset=True
                )
            elif type(item) is MacosExecRecordInput:
                record = _exec_record(
                    source.owner,
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
                body = record.model_dump_json(
                    exclude={"seq_num", "global_seq_num"}, exclude_unset=True
                )
            elif type(item) is MacosExitRecordInput:
                record = _exit_record(
                    source.owner,
                    item.executables,
                    **common,
                    process=item.process,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    installed_file=item.installed_file,
                    installed_filesystem=item.installed_filesystem,
                )
                body = record.model_dump_json(
                    exclude={"seq_num", "global_seq_num"}, exclude_unset=True
                )
            snapshots.append(
                ESProcessIngressRow(
                    host=host,
                    initial=connection,
                    occurrence_id=occurrence,
                    event_type=family,
                    reason=phase_reason(event),
                    storyline_cluster_id=event.storyline_cluster_id,
                    observed_at=event.timestamp,
                    status=decision.status,
                    delay=decision.delay,
                    native_body=body,
                )
            )
        prepared = ingress.prepare(cohort.publication_token, tuple(snapshots))
        yield MacosESPublication(None, collector, None, prepared)
        return
    requests = tuple(
        ESDeliveryRequest(
            occurrence_id=dispatcher._es_process_occurrence(event)[0],
            event_type=dispatcher._es_process_occurrence(event)[1],
            observed_at=event.timestamp,
            decision=decision,
        )
        for event, decision in zip(events, decisions, strict=True)
    )
    common = dict(cohort=cohort, collector_process=collector, clock=source.clock)
    delivery = (
        source.owner.prepare_observable(
            cohort,
            source_instance=source.source_instance,
            process=collector,
            generation=connection.generation,
            delivery=connection.next_delivery,
            request=requests[0],
        )
        if len(requests) == 1
        else source.owner.prepare_batch(
            source_instance=source.source_instance,
            process=collector,
            generation=connection.generation,
            delivery=connection.next_delivery,
            requests=requests,
        )
    )
    if delivery is None:
        yield None
        return
    try:
        if len(records) == 1 and records[0] is None:
            # A source counter claim is sufficient for intentionally filtered
            # canonical occurrences: there are no native bytes to authenticate.
            pass
        elif type(delivery) is ESDeliveryBatchPreparation:
            with prepared_es_process_records(
                source.owner, delivery=delivery, records=tuple(records), **common
            ):
                pass
        else:
            item = records[0]
            assert item is not None
            if type(item) is MacosForkRecordInput:
                with prepared_es_fork_record(
                    source.owner,
                    item.executables,
                    delivery=delivery,
                    parent=item.parent,
                    child=item.child,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    installed_filesystem=item.installed_filesystem,
                    **common,
                ):
                    pass
            elif type(item) is MacosExecRecordInput:
                with prepared_es_exec_record(
                    source.owner,
                    item.executables,
                    delivery=delivery,
                    before=item.before,
                    after=item.after,
                    descriptors=item.descriptors,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    deployments=item.deployments,
                    installed_filesystem=item.installed_filesystem,
                    **common,
                ):
                    pass
            else:
                with prepared_es_exit_record(
                    source.owner,
                    item.executables,
                    delivery=delivery,
                    process=item.process,
                    thread=item.thread,
                    action=item.action,
                    version=item.version,
                    installed_file=item.installed_file,
                    installed_filesystem=item.installed_filesystem,
                    **common,
                ):
                    pass
        emitter = dispatcher.emitters.get("macos_endpoint_security")
        if emitter is not None and type(emitter) is not MacosEndpointSecurityEmitter:
            raise StateError("Native ES publication requires its exact host-output adapter")
        sink = (
            emitter.native_sink(host)
            if emitter is not None
            and any(decision.status in {"visible", "delayed"} for decision in decisions)
            else None
        )
        yield MacosESPublication(delivery, collector, sink)
    except BaseException:
        if type(delivery) is ESDeliveryBatchPreparation:
            if dispatcher.es_collectors.owns_pending_batch(delivery):
                dispatcher.es_collectors.cancel_batch(delivery)
        elif dispatcher.es_collectors.owns_pending_delivery(delivery):
            dispatcher.es_collectors.cancel(delivery)
        raise
