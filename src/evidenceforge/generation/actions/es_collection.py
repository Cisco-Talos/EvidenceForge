# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact process admission for explicit ES client connections and deliveries.

This adapter supplies ownership only. It neither enables a native renderer nor
claims an atomic native sink. Unknown legacy owners cannot authorize delivery.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from evidenceforge.events.es_collector import (
    ESCollectorObservation,
    ESCollectorProcess,
    ESCollectorRegistry,
    ESCollectorState,
    ESDeliveryBatchPreparation,
    ESDeliveryPreparation,
    ESDeliveryRequest,
    ESKernelLoss,
    PreparedESDeliveryBatchCommit,
    PreparedESDeliveryCommit,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.state_manager import StateManager
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
