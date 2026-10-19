# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact process admission for explicit ES client connections and deliveries.

This adapter supplies ownership only. It neither enables a native renderer nor
claims an atomic native sink. Unknown legacy owners cannot authorize delivery.
"""

from datetime import datetime

from evidenceforge.events.es_collector import (
    ESCollectorObservation,
    ESCollectorProcess,
    ESCollectorRegistry,
    ESCollectorState,
    ESDeliveryPreparation,
    ESKernelLoss,
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

    def commit(
        self, capability: ESDeliveryPreparation, process: ProcessIdentity
    ) -> ESCollectorObservation:
        """Revalidate live ownership before counter commit; authenticate completed retries.

        This couples State admission and counters, not native sink publication.
        A failed revalidation leaves the exact reservation available for cancellation.
        """
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
            or type(process) is not ProcessIdentity
            or capability.observation.hostname != process.hostname
            or capability.observation.collector_process != _process(process)
        ):
            raise StateError("Bound collector commit requires its exact owning execution")
        completed = self.collectors.completed_observation(capability)
        if completed is not None:
            return completed
        with self.state._lock:
            self._live_process(process, capability.observation.observed_at)
            return self.collectors.commit(capability)
