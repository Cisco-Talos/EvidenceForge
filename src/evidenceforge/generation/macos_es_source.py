# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native profile selection and modeled collector initialization.

An explicitly activated canonical collector is required. Installation, process
names and the generator host cannot establish an ES connection. The normal
source factory remains responsible for requesting activation and routing events.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from evidenceforge.config.schemas import MacosEndpointSecurityProfile
from evidenceforge.events.es_collector import (
    ESCollectorState,
    ESDeliveryPreparation,
    ESDeliveryRequest,
    ESEventCounter,
)
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.es_source_profile import ESCollectorSourceProfile
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.formats.macos_endpoint_security import ESAction
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner, _process
from evidenceforge.generation.actions.macos_es_fork import (
    PreparedMacosForkRecord,
    prepared_es_fork_record,
)
from evidenceforge.generation.activity.macos_endpoint_security_profiles import (
    load_macos_endpoint_security_profile,
)
from evidenceforge.generation.activity.macos_unified_log_profiles import (
    load_macos_unified_log_profiles,
)
from evidenceforge.generation.deployment_compiler import resolve_system_build
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MachTimebase, MacosBootClock
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System

if TYPE_CHECKING:
    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


@dataclass(frozen=True, slots=True)
class MacosESForkPublication:
    """Frozen native ownership passed to the existing exact cohort publisher."""

    delivery: ESDeliveryPreparation
    collector: ProcessIdentity
    sink: ExternalSortedLineWriter | None


@contextmanager
def prepared_macos_es_fork_publication(
    dispatcher: EventDispatcher,
    cohort: ActionCohortMaterializationPlan,
    event: OccurrenceBuilder,
) -> Iterator[MacosESForkPublication | None]:
    """Route actual canonical forks through the selected source and exact journal.

    Rebuild bindings from durable owners on every call, including after restore.
    Missing required metadata cannot become padded native records. Unselected
    sources need no projection of unavailable facts; selected sources fail with
    an actionable error before the fork commits.
    """
    from evidenceforge.events.collection_policy import CollectionCapability, ProjectionAdmission
    from evidenceforge.generation.emitters.macos_endpoint_security import (
        MacosEndpointSecurityEmitter,
    )
    from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id

    if (
        event.event_type != "process_fork"
        or event.src_host is None
        or event.src_host.os_category != "macos"
    ):
        yield None
        return
    state = dispatcher.state_manager
    emitter = dispatcher.emitters.get("macos_endpoint_security")
    connection = dispatcher.es_collectors.connection(
        macos_es_source_instance(event.src_host.hostname)
    )
    if connection is None or connection.source_profile is None:
        if emitter is not None:
            raise StateError("Native ES fork requires an activated macOS 27 arm64 source profile")
        yield None
        return
    profile = load_macos_endpoint_security_profile(profile_id=connection.source_profile.profile_id)
    coverage = dispatcher.es_collectors.complete_membership_coverage(connection.hostname)
    if profile is None or coverage is None or connection.process is None:
        raise StateError("Native ES fork lost its frozen source policy or complete inventory")
    stamp = connection.source_profile
    source = MacosESSource(
        ESCollectionActionOwner(state, dispatcher.es_collectors),
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
    if (
        connection.closed_at is not None
        or not coverage.known_from <= event.timestamp < coverage.known_until
    ):
        yield None
        return
    assert event.identity_plan is not None
    parent, child = event.identity_plan.actor, event.identity_plan.subject
    if type(parent) is not ProcessIdentity or type(child) is not ProcessIdentity:
        raise StateError("Native ES fork requires exact canonical parent and child identities")
    dispatcher.state_manager.validate_action_cohort_materialization(cohort)
    decision = ObservationDecision("filtered" if emitter is None else "visible")
    deployment = dispatcher.collection_deployment
    if emitter is not None and deployment is not None:
        instance = exact_source_instance_id("macos_endpoint_security", parent.hostname)
        ordinal = deployment.ordinal_for_instance(instance)
        if ordinal is None:
            decision = ObservationDecision("filtered")
        else:
            envelope = deployment.projection_envelope_by_ordinal(
                occurrence_id=f"process-fork:{child.object_id}",
                target_id=f"macos_endpoint_security:host:{ordinal}",
                source_ordinal=ordinal,
                canonical_time=event.timestamp,
                requested_capabilities=CollectionCapability.PROCESS,
            )
            if not envelope.admitted:
                decision = ObservationDecision(
                    "out_of_window"
                    if envelope.admission is ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW
                    else "filtered"
                )
            else:
                policy = deployment.policy_by_ordinal(ordinal)
                decision = dispatcher.observation_policy.decide_projection(
                    "macos_endpoint_security",
                    event,
                    source_instance=instance,
                    source_hostname=parent.hostname,
                    missingness=policy.missingness_for("macos_endpoint_security"),
                    format_specific="macos_endpoint_security" in policy.format_missingness,
                )
    exported_at = event.timestamp + decision.delay
    if (
        dispatcher.output_start_time is not None and exported_at < dispatcher.output_start_time
    ) or (dispatcher.output_end_time is not None and exported_at >= dispatcher.output_end_time):
        decision = ObservationDecision("out_of_window")
    # These facts are explicitly optional in canonical State. Do not substitute
    # a static signature for runtime validation or an absent terminal for unknown.
    observations: list[MacosProcessCollectionObservation] = []
    executables = (
        dispatcher.deployment_registry
        if parent.executable_version is not None
        and parent.executable_version.identity_kind == "installed_release"
        else dispatcher.local_artifact_registry
    )
    missing = executables is None
    for process in (parent, child):
        binary = (
            dispatcher.resolve_loaded_process_binary_identity(process)
            if process.executable_version is not None
            else None
        )
        terminal = (
            state.known_macos_terminal(process.job_control.session, event.timestamp)
            if process.job_control is not None
            else None
        )
        known = dispatcher.es_collectors.known_client_membership(
            process.hostname, _process(process), event.timestamp
        )
        if (
            process.image_security is None
            or process.image_security.validation_category is None
            or process.credentials is None
            or process.credentials.audit_uid is None
            or process.credentials.audit_session_id is None
            or process.audit_pid_version is None
            or process.parentage is None
            or process.responsibility is None
            or process.job_control is None
            or getattr(binary, "code_signature", None) is None
            or terminal is None
            or known is None
        ):
            missing = True
        else:
            observations.append(
                MacosProcessCollectionObservation(process, event.timestamp, known, terminal)
            )
    if missing:
        if emitter is not None and decision.status in {"visible", "delayed"}:
            raise StateError(
                "macos_endpoint_security cannot render this fork: complete static signing, "
                "execution validation, audit, parent/group, terminal and executable facts are "
                "required. Supply explicit modeled metadata or omit this experimental format."
            )
        yield None
        return
    delivery = source.prepare_fork(cohort, child, decision=decision)
    if delivery is None:
        yield None
        return
    try:
        collector = state.get_process_identity_by_object_id(connection.process.object_id)
        if collector is None or parent.primary_thread is None:
            raise StateError("Native ES fork lost its exact collector or performing thread")
        with source.prepared_fork_record(
            executables,
            cohort=cohort,
            delivery=delivery,
            parent=observations[0],
            child=observations[1],
            thread=parent.primary_thread,
            installed_filesystem=(
                dispatcher.macos_installed_filesystem
                if type(executables) is DeploymentContentRegistry
                else None
            ),
        ):
            pass
        if emitter is not None and type(emitter) is not MacosEndpointSecurityEmitter:
            raise StateError("Native ES routing requires the exact native host-output adapter")
        sink = (
            emitter.native_sink(event.src_host)
            if emitter is not None and decision.status in {"visible", "delayed"}
            else None
        )
        yield MacosESForkPublication(delivery, collector, sink)
    except BaseException:
        if dispatcher.es_collectors.owns_pending_delivery(delivery):
            dispatcher.es_collectors.cancel(delivery)
        raise


def select_macos_es_profile(system: System) -> MacosEndpointSecurityProfile | None:
    """Select an explicit workstation target from the active generation catalog.

    An exact authored build is retained as provenance, not declared empirically
    validated by this family-level modeled profile.
    """
    if type(system) is not System or system.type != "workstation" or system.architecture != "arm64":
        return None
    match = re.fullmatch(r"macos ([0-9]+)(?:\.[0-9]+){0,2}", system.os.strip(), re.IGNORECASE)
    if match is None:
        return None
    return load_macos_endpoint_security_profile(int(match.group(1)), system.architecture)


def macos_es_source_instance(hostname: str) -> str:
    """Return the stable modeled single-client source key across checkpoint restore."""
    return f"{hostname.casefold()}:macos_endpoint_security"


def _configuration_digest(profile: MacosEndpointSecurityProfile, timebase: MachTimebase) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "source": profile.model_dump(mode="json"),
                "timebase": {"numerator": timebase.numerator, "denominator": timebase.denominator},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class MacosESSource:
    """Rebuilt profile binding; the dispatcher registry owns every durable cursor."""

    owner: ESCollectionActionOwner
    profile: MacosEndpointSecurityProfile
    source_instance: str
    coverage: ESClientMembershipCoverage
    source_profile: ESCollectorSourceProfile
    clock: MacosBootClock

    def connection(self) -> ESCollectorState:
        """Validate retained profile ownership without resetting delivered counters."""
        with self.owner.state._lock:
            if (
                type(self.profile) is not MacosEndpointSecurityProfile
                or type(self.clock) is not MacosBootClock
            ):
                raise StateError("Native ES binding requires its exact frozen source and clock")
            connection = self.owner.collectors.connection(self.source_instance)
            if (
                connection is None
                or connection.hostname != self.coverage.hostname
                or connection.source_profile != self.source_profile
                or connection.opened_at != self.coverage.known_from
                or connection.generation != 1
                or connection.process is None
                or self.source_profile.configuration_sha256
                != _configuration_digest(self.profile, self.clock.timebase)
                or self.source_profile.message_version != self.profile.message_version
                or self.source_profile.architecture != self.profile.architecture
                or self.clock.hostname != self.coverage.hostname
                or self.clock.boot_time != self.source_profile.boot_time
                or self.clock.boot_uuid != self.source_profile.boot_uuid
                or self.clock.timebase.numerator != self.source_profile.timebase_numerator
                or self.clock.timebase.denominator != self.source_profile.timebase_denominator
                or tuple(item.event_type for item in connection.event_counters)
                != self.profile.event_types
                or self.owner.state.get_macos_boot_clock(
                    self.coverage.hostname, timebase=self.clock.timebase
                )
                != self.clock
            ):
                raise StateError("Native ES connection disagrees with its frozen source profile")
            return connection

    def prepare_fork(
        self,
        cohort: ActionCohortMaterializationPlan,
        child: ProcessIdentity,
        *,
        decision: ObservationDecision,
    ) -> ESDeliveryPreparation | None:
        """Reserve only an authenticated actual fork within the modeled inventory.

        Missing source availability consumes no counters. Ordinary process
        creation cannot be reinterpreted as fork to populate this source.
        """
        state = self.owner.state
        with state._lock:
            if type(child) is not ProcessIdentity:
                raise StateError("Native fork source requires an exact canonical child")
            state.validate_action_cohort_materialization(cohort)
            birth = next((item for item in cohort.processes if item.identity == child), None)
            if birth is None or not birth.forked or child.hostname != self.coverage.hostname:
                raise StateError("Native fork source requires its exact canonical fork birth")
            at = child.started_at
            connection = self.connection()
            if (
                not self.coverage.known_from <= at < self.coverage.known_until
                or connection.closed_at is not None
            ):
                return None
            assert connection.process is not None
            collector = state.get_process_identity_by_object_id(connection.process.object_id)
            if collector is None or _process(collector) != connection.process:
                raise StateError(
                    "Native ES delivery requires its exact current collector execution"
                )
            return self.owner.prepare_observable(
                cohort,
                source_instance=self.source_instance,
                process=collector,
                generation=connection.generation,
                delivery=connection.next_delivery,
                request=ESDeliveryRequest(
                    occurrence_id=f"process-fork:{child.object_id}",
                    event_type=11,
                    observed_at=at,
                    decision=decision,
                ),
            )

    @contextmanager
    def prepared_fork_record(
        self,
        executables: LocalArtifactVersionRegistry | DeploymentContentRegistry,
        *,
        cohort: ActionCohortMaterializationPlan,
        delivery: ESDeliveryPreparation,
        parent: MacosProcessCollectionObservation,
        child: MacosProcessCollectionObservation,
        thread: ThreadIdentity,
        installed_filesystem: MacosInstalledFilesystem | None = None,
    ) -> Iterator[PreparedMacosForkRecord]:
        """Apply the selected wire profile while requiring complete explicit facts."""
        if type(delivery) is not ESDeliveryPreparation:
            raise StateError("Native fork record requires an exact source delivery")
        connection = self.connection()
        assert connection.process is not None
        collector = self.owner.state.get_process_identity_by_object_id(connection.process.object_id)
        if (
            collector is None
            or _process(collector) != connection.process
            or delivery.observation.source_instance != self.source_instance
            or delivery.observation.generation != connection.generation
            or delivery.observation.event_type != 11
            or not self.coverage.known_from
            <= delivery.observation.observed_at
            < self.coverage.known_until
        ):
            raise StateError("Native fork record requires its selected collector execution")
        action = ESAction.model_validate(
            {
                "result": {
                    "result_type": self.profile.result_type,
                    "result": {"auth": self.profile.auth_result},
                }
            }
        )
        with prepared_es_fork_record(
            self.owner,
            executables,
            cohort=cohort,
            delivery=delivery,
            collector_process=collector,
            parent=parent,
            child=child,
            thread=thread,
            clock=self.clock,
            action=action,
            version=self.profile.message_version,
            installed_filesystem=installed_filesystem,
        ) as prepared:
            yield prepared


def initialize_macos_es_source(
    owner: ESCollectionActionOwner,
    system: System,
    collector: ProcessIdentity,
    *,
    known_from: datetime,
    known_until: datetime,
    restoring: bool = False,
) -> MacosESSource:
    """Initialize or rebind the bounded single-client modeled source inventory.

    Subscription and initial zero counters come from the frozen source policy.
    Restoring validates existing epoch/profile/coverage and never reinitializes
    counters. Client activation and canonical process lifecycle stay external.
    """
    if type(owner) is not ESCollectionActionOwner or type(collector) is not ProcessIdentity:
        raise StateError("Native ES initialization requires exact canonical owners")
    profile = select_macos_es_profile(system)
    if profile is None:
        raise StateError("Native ES source requires frozen macOS 27 arm64 workstation policy")
    profile = MacosEndpointSecurityProfile.model_validate_json(profile.model_dump_json())
    coverage = ESClientMembershipCoverage(
        hostname=system.hostname, known_from=known_from, known_until=known_until
    )
    if (
        collector.hostname != system.hostname
        or collector.image != profile.collector_arguments[0]
        or collector.arguments != profile.collector_arguments
        or collector.credentials is None
        or collector.credentials.effective_uid != 0
        or collector.execution_started_at > coverage.known_from
    ):
        raise StateError("Native ES source requires an activated privileged exact collector argv")
    clock_policy = load_macos_unified_log_profiles()
    if clock_policy.profile != profile.clock_profile:
        raise StateError("Native ES source requires its explicit shared native clock policy")
    ratio = clock_policy.mach_timebase
    clock = owner.state.get_macos_boot_clock(
        system.hostname, timebase=MachTimebase(ratio.numerator, ratio.denominator)
    )
    stamp = ESCollectorSourceProfile(
        profile_id=profile.profile,
        configuration_sha256=_configuration_digest(profile, clock.timebase),
        os_build=resolve_system_build(system, "macos"),
        architecture=profile.architecture,
        message_version=profile.message_version,
        boot_uuid=clock.boot_uuid,
        boot_time=clock.boot_time,
        timebase_numerator=clock.timebase.numerator,
        timebase_denominator=clock.timebase.denominator,
    )
    source = MacosESSource(
        owner,
        profile,
        macos_es_source_instance(system.hostname),
        coverage,
        stamp,
        clock,
    )
    with owner.state._lock, owner.collectors._lock:
        if owner.state.get_macos_boot_clock(system.hostname, timebase=clock.timebase) != clock:
            raise StateError("Native ES initialization lost its canonical boot snapshot")
        if restoring:
            connection = source.connection()
            if connection.process != _process(collector):
                raise StateError("Restored native ES source names another collector execution")
            restored = owner.state.get_process_identity_by_object_id(
                collector.object_id, event_time=known_from
            )
            if restored != collector:
                raise StateError("Restored native ES source requires its retained canonical owner")
            _, membership = owner.collectors.snapshot_with_membership()
            if coverage not in membership:
                raise StateError(
                    "Restored native ES source changed its complete inventory interval"
                )
        else:
            owner.initialize_inventory(
                coverage,
                (
                    (
                        ESCollectorState(
                            source_instance=source.source_instance,
                            hostname=system.hostname,
                            generation=1,
                            opened_at=known_from,
                            last_delivery_at=known_from,
                            next_delivery=0,
                            next_global_sequence=0,
                            event_counters=tuple(
                                ESEventCounter(event_type=event_type, next_sequence=0)
                                for event_type in profile.event_types
                            ),
                            source_profile=stamp,
                            process=_process(collector),
                        ),
                        collector,
                    ),
                ),
            )
    return source
