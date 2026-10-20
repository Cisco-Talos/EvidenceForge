# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact process admission for explicit ES client connections and deliveries.

This adapter supplies ownership only. It neither enables a native renderer nor
claims an atomic native sink. Unknown legacy owners cannot authorize delivery.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Literal

from evidenceforge.events.es_collector import (
    ESCollectorClosure,
    ESCollectorObservation,
    ESCollectorProcess,
    ESCollectorRegistry,
    ESCollectorState,
    ESDeliveryBatchPreparation,
    ESDeliveryPreparation,
    ESDeliveryRequest,
    ESKernelLoss,
    PreparedESCollectorClosures,
    PreparedESDeliveryBatchCommit,
    PreparedESDeliveryCommit,
)
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError


def _process(identity: ProcessIdentity) -> ESCollectorProcess:
    return ESCollectorProcess(
        object_id=identity.object_id,
        pid=identity.pid,
        started_at=identity.started_at,
        execution_ordinal=identity.execution_ordinal,
        execution_started_at=identity.execution_started_at,
    )


class ESCollectionActionOwner:
    """Bind explicit modeled clients to State-owned Mac executions."""

    def __init__(self, state: StateManager, collectors: ESCollectorRegistry) -> None:
        self.state = state
        self.collectors = collectors

    def _live_process(self, identity: ProcessIdentity, at: datetime) -> ESCollectorProcess:
        if (
            type(identity) is not ProcessIdentity
            or type(at) is not datetime
            or at.utcoffset() is None
            or self.state._pid_os.get(identity.hostname) != "macos"
            or self.state.get_process(identity.hostname, identity.pid) is None
            or not self.state.is_process_active_at(identity.hostname, identity.pid, at)
            or self.state.get_process_identity(identity.hostname, identity.pid) != identity
            or at < identity.execution_started_at
        ):
            raise StateError("Collector admission requires an exact live Mac execution")
        return _process(identity)

    def open(self, profile: ESCollectorState, process: ProcessIdentity) -> ESCollectorState:
        """Admit an explicitly opened connection; installation alone is insufficient."""
        if type(profile) is not ESCollectorState:
            raise StateError("Collector admission requires an exact connection profile")
        with self.state._lock:
            owner = self._live_process(process, profile.opened_at)
            if profile.hostname != process.hostname or profile.process not in (None, owner):
                raise StateError("Collector profile names another host or execution")
            bound = ESCollectorState.model_validate_json(
                profile.model_copy(update={"process": owner}).model_dump_json()
            )
            self.collectors.open(bound)
            return bound

    def declare_complete_membership(self, coverage: ESClientMembershipCoverage) -> None:
        """Declare explicit inventory completeness for an initialized modeled Mac host."""
        if type(coverage) is not ESClientMembershipCoverage:
            raise StateError("ES inventory declaration requires exact completeness bounds")
        with self.state._lock:
            if self.state._pid_os.get(coverage.hostname) != "macos":
                raise StateError("ES inventory declaration requires an initialized Mac host")
            self.collectors.declare_complete_membership(coverage)

    def initialize_inventory(
        self,
        coverage: ESClientMembershipCoverage,
        clients: tuple[tuple[ESCollectorState, ProcessIdentity], ...],
    ) -> tuple[ESCollectorState, ...]:
        """Bind every explicit initial client before publishing complete host knowledge."""
        if (
            type(coverage) is not ESClientMembershipCoverage
            or type(clients) is not tuple
            or len(clients) > 128
            or any(type(item) is not tuple or len(item) != 2 for item in clients)
        ):
            raise StateError("ES initialization requires an exact bounded client inventory")
        with self.state._lock:
            if self.state._pid_os.get(coverage.hostname) != "macos":
                raise StateError("ES initialization requires an initialized modeled Mac host")
            bound: list[ESCollectorState] = []
            for profile, process in clients:
                if type(profile) is not ESCollectorState:
                    raise StateError("ES initialization requires exact client profiles")
                owner = self._live_process(process, coverage.known_from)
                if profile.hostname != coverage.hostname or profile.process not in (None, owner):
                    raise StateError("ES initial profile disagrees with its exact execution")
                bound.append(
                    ESCollectorState.model_validate_json(
                        profile.model_copy(update={"process": owner}).model_dump_json()
                    )
                )
            return self.collectors.initialize_inventory(coverage, tuple(bound))

    def close(
        self,
        expected: ESCollectorState,
        process: ProcessIdentity,
        closed_at: datetime,
    ) -> ESCollectorState:
        """Close an explicitly bound idle connection while its execution is live.

        A matching current terminal snapshot can be replayed after process exit
        or exec without mutating counters or moving the closure time. A newer
        connection epoch cannot satisfy that retry. This is an explicit client
        disconnect, not automatic process-exit or native sink publication.
        """
        if (
            type(expected) is not ESCollectorState
            or type(process) is not ProcessIdentity
            or type(closed_at) is not datetime
            or closed_at.utcoffset() is None
            or expected.hostname != process.hostname
            or expected.process != _process(process)
            or (expected.closed_at is not None and expected.closed_at != closed_at)
        ):
            raise StateError("Bound collector closure requires its exact execution and time")
        after = ESCollectorState.model_validate_json(
            expected.model_copy(update={"closed_at": closed_at}).model_dump_json()
        )
        with self.state._lock:
            current = self.collectors.connection(expected.source_instance)
            if current == after:
                return current
            self._live_process(process, closed_at)
            self.collectors.close(expected, closed_at)
            return after

    def process_execution_closures(
        self, cohort: ActionCohortMaterializationPlan
    ) -> tuple[tuple[ESCollectorClosure, ...], tuple[ProcessIdentity, ...]]:
        """Plan disconnects when an explicitly bound execution exits or is replaced.

        Connections belong to an execution, not a reusable PID or process image.
        Successful exec retires that ownership at its canonical transition;
        a replacement execution needs an explicit new connection epoch. Failed
        exec has no image transition and keeps its attachment. This modeled
        ownership policy does not claim native disconnect-notification evidence.
        Unknown owners remain unknown.
        """
        if type(cohort) is not ActionCohortMaterializationPlan:
            raise StateError("Collector execution closure requires an exact canonical cohort")
        with self.state._lock:
            profiles = self.collectors.open_connections()
            if not profiles:
                return (), ()
            self.state.validate_action_cohort_materialization(cohort)
            endings = {
                (identity.hostname, _process(identity)): (identity, at)
                for identity, at in (
                    *((item.identity, item.end_time) for item in cohort.process_terminations),
                    *(
                        (item.target, item.after.execution_started_at)
                        for item in cohort.process_executions
                    ),
                )
                if self.state._pid_os.get(identity.hostname) == "macos"
            }
            requests: list[ESCollectorClosure] = []
            processes: list[ProcessIdentity] = []
            for profile in profiles:
                ending = endings.get((profile.hostname, profile.process))
                if ending is None:
                    continue
                identity, at = ending
                self._live_process(identity, at)
                try:
                    request = ESCollectorClosure(before=profile, closed_at=at)
                except ValueError as exc:
                    raise StateError("Collector delivery extends beyond its execution") from exc
                requests.append(request)
                processes.append(identity)
            return tuple(requests), tuple(processes)

    @contextmanager
    def prepared_closures(
        self,
        requests: tuple[ESCollectorClosure, ...],
        processes: tuple[ProcessIdentity, ...],
        *,
        after_deliveries: tuple[PreparedESDeliveryCommit | PreparedESDeliveryBatchCommit, ...] = (),
    ) -> Iterator[PreparedESCollectorClosures]:
        """Fence exact live executions and reversible connection disconnects.

        The outer canonical transaction owns process lifecycle; this scope closes
        only explicit connections and supplies no automatic native observation.
        """
        if (
            type(requests) is not tuple
            or type(processes) is not tuple
            or not 1 <= len(requests) == len(processes) <= 128
            or any(type(item) is not ESCollectorClosure for item in requests)
        ):
            raise StateError("Bound collector closures require matching exact requests and owners")
        with self.state._lock:
            for request, process in zip(requests, processes, strict=True):
                owner = self._live_process(process, request.closed_at)
                if request.before.hostname != process.hostname or request.before.process != owner:
                    raise StateError("Collector closure disagrees with its exact live execution")
            with self.collectors.prepared_closures(
                requests, after_deliveries=after_deliveries
            ) as prepared:
                yield prepared

    def validate_client_observation(self, observation: MacosProcessCollectionObservation) -> None:
        """Reject supplied facts contradicted by known modeled membership.

        Outside declared completeness, missing registry membership remains
        unknown and external clients may be modeled without a delivery profile.
        Canonical process authentication remains with the calling live/planned
        owner. Within completeness every client requires an exact profile.
        """
        if type(observation) is not MacosProcessCollectionObservation:
            raise StateError("ES client observation requires exact collection facts")
        observation.__post_init__()
        known = self.collectors.known_client_membership(
            observation.process.hostname, _process(observation.process), observation.observed_at
        )
        if known is not None and known != observation.is_es_client:
            raise StateError("ES client observation contradicts known modeled membership")
        if observation.process.job_control is not None:
            terminal = self.state.known_macos_terminal(
                observation.process.job_control.session, observation.observed_at
            )
            if terminal is not None and terminal != observation.terminal:
                raise StateError("ES terminal observation contradicts its canonical session device")

    def validate_observing_cohort(
        self,
        cohort: ActionCohortMaterializationPlan,
        collector: ProcessIdentity,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Admit only observations strictly before the collector changes or ends.

        Self-exec/self-exit notifications have no surviving same-execution
        connection under this model. They require a distinct live observer.
        Earlier events remain observable even when this cohort later retires
        its collector. Omitted time preserves the conservative legacy guard.
        """
        if observed_at is not None and (
            type(observed_at) is not datetime or observed_at.utcoffset() is None
        ):
            raise StateError("ES self-observation requires an aware observation time")
        boundary = self.observing_execution_boundary(cohort, collector)
        if boundary is not None and (observed_at is None or observed_at >= boundary):
            raise StateError(
                "Native preparation cannot observe the same observing collector at or after its transition"
            )

    def observing_execution_boundary(
        self, cohort: ActionCohortMaterializationPlan, collector: ProcessIdentity
    ) -> datetime | None:
        """Return the earliest modeled transition that retires this exact observer view."""
        if (
            type(cohort) is not ActionCohortMaterializationPlan
            or type(collector) is not ProcessIdentity
        ):
            raise StateError("ES self-observation requires exact cohort and execution facts")
        boundaries = (
            [
                item.end_time
                for item in cohort.process_terminations
                if item.identity.object_id == collector.object_id
            ]
            + [
                item.after.execution_started_at
                for item in cohort.process_executions
                if item.target.object_id == collector.object_id
            ]
            + [
                item.activity_time
                for item in cohort.process_activity_patches
                if self.state._action_process_identity(item.target).object_id == collector.object_id
                and any(
                    value is not None
                    for value in (
                        item.audit_binding,
                        item.privilege_drop,
                        item.service_drop,
                        item.job_control_change,
                        item.parentage_change,
                    )
                )
            ]
        )
        return min(boundaries) if boundaries else None

    def prepare_observable(
        self,
        cohort: ActionCohortMaterializationPlan,
        *,
        source_instance: str,
        process: ProcessIdentity,
        generation: int,
        delivery: int,
        request: ESDeliveryRequest,
    ) -> ESDeliveryPreparation | None:
        """Reserve a real delivery or withhold unavailable same-client self-observation.

        Withholding consumes no delivery/global/event counter and never implies
        kernel loss. A distinct surviving observer can collect the same canonical
        transition. Native source admission remains a separate contract.
        """
        if type(request) is not ESDeliveryRequest:
            raise StateError("ES observable preparation requires an exact delivery request")
        request = ESDeliveryRequest.model_validate_json(request.model_dump_json())
        with self.state._lock:
            self.state.validate_action_cohort_materialization(cohort)
            self._live_process(process, request.observed_at)
            connection = self.collectors.connection(source_instance)
            if (
                connection is None
                or connection.process != _process(process)
                or connection.hostname != process.hostname
                or type(generation) is not int
                or type(delivery) is not int
                or connection.generation != generation
                or connection.next_delivery != delivery
                or connection.closed_at is not None
                or request.event_type not in {item.event_type for item in connection.event_counters}
            ):
                raise StateError("ES observable preparation requires its established execution")
            boundary = self.observing_execution_boundary(cohort, process)
            if boundary is not None and request.observed_at >= boundary:
                return None
            return self.prepare(
                source_instance=source_instance,
                process=process,
                generation=generation,
                delivery=delivery,
                occurrence_id=request.occurrence_id,
                event_type=request.event_type,
                observed_at=request.observed_at,
                decision=request.decision,
                kernel_lost=request.kernel_lost,
            )

    def observe_process_collection(
        self,
        process: ProcessIdentity,
        *,
        observed_at: datetime,
        terminal: Literal["absent"] | MacosTerminalObservation | None = None,
    ) -> MacosProcessCollectionObservation:
        """Produce client facts for an exact live execution and known terminal facts.

        A negative result requires explicit inventory completeness at this time.
        Terminal ownership remains with its separate session/device producer.
        Planned or historical State authentication remains with native adapters.
        """
        with self.state._lock:
            execution = self._live_process(process, observed_at)
            known = self.collectors.known_client_membership(
                process.hostname, execution, observed_at
            )
            if known is None:
                raise StateError("ES process collection requires known client membership")
            if terminal is None and process.job_control is not None:
                terminal = self.state.known_macos_terminal(process.job_control.session, observed_at)
            if terminal is None:
                raise StateError("ES process collection requires known session terminal facts")
            observation = MacosProcessCollectionObservation(process, observed_at, known, terminal)
            self.validate_client_observation(observation)
            return observation

    def prepare(
        self,
        *,
        source_instance: str,
        process: ProcessIdentity,
        generation: int,
        delivery: int,
        occurrence_id: str,
        event_type: int,
        observed_at: datetime,
        decision: ObservationDecision,
        kernel_lost: tuple[ESKernelLoss, ...] = (),
    ) -> ESDeliveryPreparation:
        """Reserve counters only for a still-live, explicitly bound collector epoch."""
        with self.state._lock:
            owner = self._live_process(process, observed_at)
            connection = self.collectors.connection(source_instance)
            if (
                connection is None
                or connection.hostname != process.hostname
                or connection.process != owner
            ):
                raise StateError("ES delivery requires its exact established collector execution")
            return self.collectors.prepare(
                source_instance=source_instance,
                generation=generation,
                delivery=delivery,
                occurrence_id=occurrence_id,
                event_type=event_type,
                observed_at=observed_at,
                decision=decision,
                kernel_lost=kernel_lost,
            )

    @contextmanager
    def prepared_commit(
        self, capability: ESDeliveryPreparation, process: ProcessIdentity
    ) -> Iterator[PreparedESDeliveryCommit]:
        """Fence exact State ownership and counters for an outer atomic publication.

        Acquire State before the collector and retain both through the caller's
        commit. Completed proof retries remain admissible after owner exit or
        exec; they cannot allocate counters again. No source bytes are written.
        """
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
            or type(process) is not ProcessIdentity
            or capability.observation.hostname != process.hostname
            or capability.observation.collector_process != _process(process)
        ):
            raise StateError("Bound collector commit requires its exact owning execution")
        with self.state._lock:
            if self.collectors.completed_observation(capability) is None:
                self._live_process(process, capability.observation.observed_at)
            with self.collectors.prepared_delivery(capability) as prepared:
                yield prepared

    def commit(
        self, capability: ESDeliveryPreparation, process: ProcessIdentity
    ) -> ESCollectorObservation:
        """Revalidate ownership and commit once; retain proof across lost returns."""
        with self.prepared_commit(capability, process) as prepared:
            prepared.commit_no_fail()
            return prepared.observation

    def prepare_batch(
        self,
        *,
        source_instance: str,
        process: ProcessIdentity,
        generation: int,
        delivery: int,
        requests: tuple[ESDeliveryRequest, ...],
    ) -> ESDeliveryBatchPreparation:
        """Reserve one same-connection group after validating every delivery's live owner."""
        if (
            type(requests) is not tuple
            or not 1 <= len(requests) <= 256
            or any(type(item) is not ESDeliveryRequest for item in requests)
        ):
            raise StateError("Bound ES batch requires exact bounded requests")
        requests = tuple(
            ESDeliveryRequest.model_validate_json(item.model_dump_json()) for item in requests
        )
        with self.state._lock:
            for request in requests:
                owner = self._live_process(process, request.observed_at)
            connection = self.collectors.connection(source_instance)
            if (
                connection is None
                or connection.hostname != process.hostname
                or connection.process != owner
            ):
                raise StateError("ES batch requires its exact established collector execution")
            return self.collectors.prepare_batch(
                source_instance=source_instance,
                generation=generation,
                delivery=delivery,
                requests=requests,
            )

    @contextmanager
    def prepared_batch_commit(
        self, capability: ESDeliveryBatchPreparation, process: ProcessIdentity
    ) -> Iterator[PreparedESDeliveryBatchCommit]:
        """Hold State then collector ownership across an outer atomic batch publication."""
        if (
            type(capability) is not ESDeliveryBatchPreparation
            or type(process) is not ProcessIdentity
        ):
            raise StateError("Bound ES batch commit requires exact owning facts")
        self.collectors._validate_batch_capability(capability)
        if any(
            item.hostname != process.hostname or item.collector_process != _process(process)
            for item in capability.observations
        ):
            raise StateError("Bound ES batch commit requires its exact owning execution")
        with self.state._lock:
            if self.collectors.completed_batch(capability) is None:
                for observation in capability.observations:
                    self._live_process(process, observation.observed_at)
            with self.collectors.prepared_batch(capability) as prepared:
                yield prepared

    def commit_batch(
        self, capability: ESDeliveryBatchPreparation, process: ProcessIdentity
    ) -> tuple[ESCollectorObservation, ...]:
        """Advance one exact group once; completed proof retries survive collector exit/exec."""
        with self.prepared_batch_commit(capability, process) as prepared:
            prepared.commit_no_fail()
            return prepared.observations
