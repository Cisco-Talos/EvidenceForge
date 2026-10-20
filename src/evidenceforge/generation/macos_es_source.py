# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded fork-profile selection and modeled collector initialization.

An explicitly activated canonical collector is required. Installation, process
names and the generator host cannot establish an ES connection. The normal
source factory remains responsible for requesting activation and routing events.
"""

import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

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


def select_macos_es_profile(system: System) -> MacosEndpointSecurityProfile | None:
    """Select only explicit macOS 26 arm64 workstations with frozen source policy.

    An exact authored build is retained as provenance, not declared empirically
    validated by this family-level modeled profile.
    """
    if (
        type(system) is not System
        or system.type != "workstation"
        or system.architecture != "arm64"
        or re.fullmatch(r"macos 26(?:\.[0-9]+){0,2}", system.os.strip(), re.IGNORECASE) is None
    ):
        return None
    return load_macos_endpoint_security_profile()


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
                != (self.profile.event_type,)
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
                    event_type=self.profile.event_type,
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
            or delivery.observation.event_type != self.profile.event_type
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
        raise StateError("Native ES source requires frozen macOS 26 arm64 workstation policy")
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
                            event_counters=(
                                ESEventCounter(event_type=profile.event_type, next_sequence=0),
                            ),
                            source_profile=stamp,
                            process=_process(collector),
                        ),
                        collector,
                    ),
                ),
            )
    return source
