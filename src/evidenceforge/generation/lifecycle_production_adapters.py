# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Additive production adapters for service and transport lifecycle authority.

Action bundles use these adapters to freeze registry identity before executing
their existing semantic effects, then publish only after those effects reconcile
successfully.  The registry remains the sole canonical lifecycle authority; the
adapter retains no duplicate service, transport, or relationship state.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.events.content_identity import ServiceDeploymentIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleHold,
    LogicalServiceIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceInstanceLifecycleSnapshot,
    ServiceProcessBindingIdentity,
    TransportLifecycleIdentity,
    TransportLifecycleSnapshot,
    TransportSessionBindingIdentity,
    TransportSessionBindingRole,
)
from evidenceforge.events.network import NetworkTransactionPlan, NetworkTuple
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleClosedTransportPreparationCensus,
    LifecycleClosedTransportPublicationInProgressError,
    LifecycleClosedTransportPublicationRequest,
    LifecycleClosedTransportStartMember,
    LifecycleRegistry,
    LifecycleServiceAdmissionToken,
    LifecycleServiceClosureAdmissionToken,
    LifecycleServicePreparationCensus,
    LifecycleServiceProcessClosureRequest,
    LifecycleServicePublicationInProgressError,
    LifecycleServicePublicationRequest,
    LifecycleServiceStagedProcessBindingMember,
    PreparedLifecycleClosedTransportPublication,
    PreparedLifecycleServiceProcessClosure,
    PreparedLifecycleServicePublication,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc


class _LifecycleDispatcher(Protocol):
    """Minimal public dispatcher surface used to resolve lifecycle authority."""

    @property
    def lifecycle_shadow(self) -> object | None:
        """Return the engine-owned lifecycle adapter when one is configured."""
        ...

    @property
    def enforces_lifecycle_authority(self) -> bool:
        """Return whether missing lifecycle authority is a production error."""
        ...


class LifecycleAdapterExecutor(Protocol):
    """Action-executor surface required by lifecycle production adapters."""

    dispatcher: _LifecycleDispatcher


@dataclass(frozen=True, slots=True)
class ServiceLifecyclePublicationPlan:
    """Frozen logical and boot-scoped service identity ready for publication."""

    logical_identity: LogicalServiceIdentity
    instance_identity: ServiceInstanceLifecycleIdentity
    action_id: str
    transition_id: str
    transition_ordinal: int = 0
    process_bindings: tuple[ServiceProcessBindingIdentity, ...] = ()
    staged_process_bindings: tuple[LifecycleServiceStagedProcessBindingMember, ...] = ()

    def __post_init__(self) -> None:
        """Reject incomplete or internally inconsistent service plans."""

        if not self.action_id or not self.transition_id:
            raise ValueError("Service lifecycle publication requires action and transition IDs")
        if self.transition_ordinal < 0:
            raise ValueError("Service lifecycle publication ordinal must be non-negative")
        if self.logical_identity.hostname != self.instance_identity.hostname:
            raise ValueError("Logical service and instance hosts must match")
        if self.logical_identity.logical_service_id != self.instance_identity.logical_service_id:
            raise ValueError("Logical service and instance IDs must match")
        binding_ids: set[str] = set()
        process_ids: set[str] = set()
        for binding in self.process_bindings:
            if binding.service_object_id != self.instance_identity.object_id:
                raise ValueError("Service process binding references a different service")
            if binding.binding_id in binding_ids:
                raise ValueError("Service lifecycle publication repeats a binding ID")
            if binding.process_object_id in process_ids:
                raise ValueError("Service lifecycle publication repeats a process binding")
            binding_ids.add(binding.binding_id)
            process_ids.add(binding.process_object_id)
        staged_binding_ids = [member.binding_id for member in self.staged_process_bindings]
        if len(set(staged_binding_ids)) != len(staged_binding_ids):
            raise ValueError("Service lifecycle publication repeats a staged binding")
        if any(binding_id not in binding_ids for binding_id in staged_binding_ids):
            raise ValueError("Staged service process is missing its publication binding")


@dataclass(frozen=True, slots=True)
class TransportLifecyclePublicationPlan:
    """Frozen canonical transport and optional session relation to publish.

    The plan consumes an existing :class:`NetworkTransactionPlan`; it never
    allocates a tuple, connection ID, or Zeek UID. Closed network transactions
    are published as a complete lifecycle ledger: start, optional session
    binding, binding close, close barrier, and terminal close.
    """

    identity: TransportLifecycleIdentity
    binding_identity: TransportSessionBindingIdentity | None
    action_id: str
    transition_id: str
    close_barrier_id: str
    close_ticket_id: str

    def __post_init__(self) -> None:
        """Reject incomplete or internally inconsistent transport plans."""

        if not all(
            (
                self.action_id,
                self.transition_id,
                self.close_barrier_id,
                self.close_ticket_id,
            )
        ):
            raise ValueError("Transport lifecycle publication requires stable action IDs")
        binding = self.binding_identity
        if binding is None:
            return
        if binding.transport_object_id != self.identity.object_id:
            raise ValueError("Transport/session binding references a different transport")
        if not self.identity.opened_at <= binding.bound_at <= self.identity.close_deadline:
            raise ValueError("Transport/session binding time must lie inside the transport")


def service_boot_id(hostname: str, boot_time: datetime) -> str:
    """Return one deterministic boot-scope identity from canonical state time."""

    return stable_uuid(
        "lifecycle-service-boot",
        hostname.strip().casefold(),
        ensure_utc(boot_time).isoformat(),
    )


def installed_service_publication_plan(
    *,
    hostname: str,
    service_name: str,
    deployment_service_id: str,
    boot_time: datetime,
    started_at: datetime,
    action_id: str,
    deployment_identity: ServiceDeploymentIdentity | None = None,
    process_bindings: tuple[ServiceProcessBindingIdentity, ...] = (),
) -> ServiceLifecyclePublicationPlan:
    """Build one immutable dynamically installed Windows service instance."""

    normalized_host = hostname.strip().casefold()
    normalized_name = service_name.strip().casefold()
    if not normalized_host or not normalized_name or not deployment_service_id or not action_id:
        raise ValueError(
            "Installed service publication requires host, service, deployment, and action IDs"
        )
    if deployment_identity is not None:
        if deployment_identity.hostname != normalized_host:
            raise ValueError("Installed service deployment identity host does not match")
        if deployment_identity.deployment_service_id != deployment_service_id:
            raise ValueError("Installed service deployment identity does not match its ID")
    logical_service_id = stable_uuid(
        "lifecycle-logical-service",
        normalized_host,
        normalized_name,
    )
    boot_id = service_boot_id(hostname, boot_time)
    instance_id = stable_uuid(
        "lifecycle-installed-service-instance",
        action_id,
    )
    object_id = stable_uuid(
        "lifecycle-service-object",
        normalized_host,
        boot_id,
        logical_service_id,
        instance_id,
    )
    return ServiceLifecyclePublicationPlan(
        logical_identity=LogicalServiceIdentity(
            hostname=hostname,
            logical_service_id=logical_service_id,
            canonical_name=service_name,
            service_kind="installed",
            deployment_service_id=deployment_service_id,
            deployment_identity=deployment_identity,
        ),
        instance_identity=ServiceInstanceLifecycleIdentity(
            hostname=hostname,
            object_id=object_id,
            logical_service_id=logical_service_id,
            boot_id=boot_id,
            instance_id=instance_id,
            started_at=started_at,
        ),
        action_id=action_id,
        transition_id=stable_uuid("lifecycle-service-start", object_id),
        process_bindings=process_bindings,
    )


def builtin_service_publication_plan(
    *,
    hostname: str,
    logical_service_id: str,
    canonical_name: str,
    boot_time: datetime,
    started_at: datetime,
    deployment_identity: ServiceDeploymentIdentity | None = None,
    process_bindings: tuple[ServiceProcessBindingIdentity, ...] = (),
) -> ServiceLifecyclePublicationPlan:
    """Build one immutable boot-scoped built-in Windows service instance."""

    normalized_host = hostname.strip().casefold()
    normalized_logical = logical_service_id.strip().casefold()
    if not normalized_host or not normalized_logical or not canonical_name.strip():
        raise ValueError("Built-in service publication requires host, logical ID, and name")
    if deployment_identity is not None and deployment_identity.hostname != normalized_host:
        raise ValueError("Built-in service deployment identity host does not match")
    boot_id = service_boot_id(hostname, boot_time)
    instance_id = "builtin"
    object_id = stable_uuid(
        "lifecycle-service-object",
        normalized_host,
        boot_id,
        normalized_logical,
        instance_id,
    )
    action_id = stable_uuid("lifecycle-builtin-service", object_id)
    return ServiceLifecyclePublicationPlan(
        logical_identity=LogicalServiceIdentity(
            hostname=hostname,
            logical_service_id=logical_service_id,
            canonical_name=canonical_name,
            service_kind="builtin",
            deployment_service_id=(
                "" if deployment_identity is None else deployment_identity.deployment_service_id
            ),
            deployment_identity=deployment_identity,
        ),
        instance_identity=ServiceInstanceLifecycleIdentity(
            hostname=hostname,
            object_id=object_id,
            logical_service_id=logical_service_id,
            boot_id=boot_id,
            instance_id=instance_id,
            started_at=started_at,
        ),
        action_id=action_id,
        transition_id=stable_uuid("lifecycle-service-start", object_id),
        process_bindings=process_bindings,
    )


def closed_transport_publication_plan(
    *,
    transaction: NetworkTransactionPlan,
    authority_hostname: str,
    src_hostname: str,
    dst_hostname: str,
    session_object_id: str = "",
    binding_role: TransportSessionBindingRole = "session",
    bound_at: datetime | None = None,
    action_id: str = "",
) -> TransportLifecyclePublicationPlan:
    """Freeze lifecycle publication from one completed canonical transaction.

    ``authority_hostname`` selects the stable lifecycle partition. Explicit
    source and destination host identities preserve cross-host meaning and may
    be IP literals when one endpoint is outside the modeled environment.
    """

    if transaction.closed_at is None:
        raise ValueError("Lifecycle transport publication requires a closed transaction")
    if not transaction.zeek_uid:
        raise ValueError("Lifecycle transport publication requires the canonical Zeek UID")
    if not all((authority_hostname, src_hostname, dst_hostname)):
        raise ValueError(
            "Lifecycle transport publication requires authority, source, and destination hosts"
        )
    if bool(session_object_id) != (bound_at is not None):
        raise ValueError("Transport/session publication requires both session ID and bind time")

    object_id = stable_uuid(
        "lifecycle-transport-object",
        transaction.stable_id,
        transaction.zeek_uid,
    )
    lifecycle_action_id = action_id or stable_uuid(
        "lifecycle-transport-action",
        transaction.stable_id,
        transaction.zeek_uid,
    )
    identity = TransportLifecycleIdentity(
        hostname=authority_hostname,
        object_id=object_id,
        transport_id=transaction.stable_id,
        src_hostname=src_hostname,
        dst_hostname=dst_hostname,
        network_tuple=NetworkTuple(
            src_ip=transaction.src_ip,
            src_port=transaction.src_port,
            dst_ip=transaction.dst_ip,
            dst_port=transaction.dst_port,
            protocol=transaction.protocol,
        ),
        opened_at=transaction.started_at,
        close_deadline=transaction.closed_at,
        zeek_uid=transaction.zeek_uid,
        conn_id=transaction.conn_id,
    )
    binding = None
    if session_object_id:
        assert bound_at is not None
        binding = TransportSessionBindingIdentity(
            binding_id=stable_uuid(
                "lifecycle-transport-session-binding",
                object_id,
                session_object_id,
                binding_role,
            ),
            transport_object_id=object_id,
            session_object_id=session_object_id,
            bound_at=bound_at,
            role=binding_role,
            action_id=stable_uuid(
                "lifecycle-transport-bind-action",
                lifecycle_action_id,
                object_id,
            ),
            transition_ordinal=0,
        )
    return TransportLifecyclePublicationPlan(
        identity=identity,
        binding_identity=binding,
        action_id=lifecycle_action_id,
        transition_id=stable_uuid("lifecycle-transport-start", object_id),
        close_barrier_id=stable_uuid("lifecycle-transport-close-barrier", object_id),
        close_ticket_id=stable_uuid("lifecycle-transport-close-ticket", object_id),
    )


class LifecycleProductionAdapter:
    """Stateless action adapter over one engine-owned lifecycle registry."""

    __slots__ = ("_registry",)

    def __init__(self, registry: LifecycleRegistry) -> None:
        self._registry = registry

    @property
    def registry(self) -> LifecycleRegistry:
        """Return the sole canonical registry used by this adapter."""

        return self._registry

    def validate_service_publication(self, plan: ServiceLifecyclePublicationPlan) -> None:
        """Validate exact identity and overlap without publishing registry state."""

        token = self.prepare_service_publication(plan)
        self.cancel_service_publication(token)

    @staticmethod
    def _service_publication_request(
        plan: ServiceLifecyclePublicationPlan,
    ) -> LifecycleServicePublicationRequest:
        """Freeze one adapter plan into the registry-owned authenticated request."""

        return LifecycleServicePublicationRequest(
            logical_identity=plan.logical_identity,
            identity=plan.instance_identity,
            process_bindings=plan.process_bindings,
            action_id=plan.action_id,
            transition_id=plan.transition_id,
            transition_ordinal=plan.transition_ordinal,
            staged_process_bindings=plan.staged_process_bindings,
        )

    def prepare_service_publication(
        self,
        plan: ServiceLifecyclePublicationPlan,
    ) -> LifecycleServiceAdmissionToken:
        """Reserve one atomic service publication without canonical rows."""

        return self._registry.prepare_service_publication(self._service_publication_request(plan))

    def cancel_service_publication(self, token: LifecycleServiceAdmissionToken) -> None:
        """Cancel one unclaimed service publication reservation."""

        self._registry.cancel_service_publication(token)

    def authenticates_service_admission_token(
        self,
        token: object,
        *,
        plan: ServiceLifecyclePublicationPlan | None = None,
    ) -> bool:
        """Authenticate one active service token and optional exact adapter plan."""

        request = None if plan is None else self._service_publication_request(plan)
        return self._registry.authenticates_service_admission_token(token, request=request)

    def service_preparation_census(self) -> LifecycleServicePreparationCensus:
        """Return constant-time transient service reservation counts."""

        return self._registry.service_preparation_census()

    @contextmanager
    def claimed_service_publication(
        self,
        token: LifecycleServiceAdmissionToken,
    ) -> Iterator[PreparedLifecycleServicePublication]:
        """Yield a one-shot service commit capability without retaining locks."""

        with self._registry.claimed_service_publication(token) as claimed:
            yield claimed

    def authenticates_service_publication_receipt(
        self,
        receipt: object,
        *,
        plan: ServiceLifecyclePublicationPlan | None = None,
    ) -> bool:
        """Authenticate one signed service receipt and optional exact adapter plan."""

        request = None if plan is None else self._service_publication_request(plan)
        return self._registry.authenticates_service_publication_receipt(
            receipt,
            request=request,
        )

    def prepare_service_process_closure(
        self,
        request: LifecycleServiceProcessClosureRequest,
    ) -> LifecycleServiceClosureAdmissionToken:
        """Reserve one binding-first process/service closure without mutation."""

        return self._registry.prepare_service_process_closure(request)

    def cancel_service_process_closure(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        """Cancel one unclaimed service/process closure reservation."""

        self._registry.cancel_service_process_closure(token)

    def authenticates_service_closure_admission_token(
        self,
        token: object,
        *,
        request: LifecycleServiceProcessClosureRequest | None = None,
    ) -> bool:
        """Authenticate one active service closure token and optional request."""

        return self._registry.authenticates_service_closure_admission_token(
            token,
            request=request,
        )

    @contextmanager
    def claimed_service_process_closure(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> Iterator[PreparedLifecycleServiceProcessClosure]:
        """Yield a one-shot closure capability without retaining registry locks."""

        with self._registry.claimed_service_process_closure(token) as claimed:
            yield claimed

    def authenticates_service_process_closure_receipt(
        self,
        receipt: object,
        *,
        request: LifecycleServiceProcessClosureRequest | None = None,
    ) -> bool:
        """Authenticate one signed closure receipt and optional exact request."""

        return self._registry.authenticates_service_process_closure_receipt(
            receipt,
            request=request,
        )

    def publish_service(
        self,
        plan: ServiceLifecyclePublicationPlan,
    ) -> ServiceInstanceLifecycleSnapshot:
        """Publish one validated service identity idempotently."""

        request = self._service_publication_request(plan)
        while True:
            try:
                token = self._registry.prepare_service_publication(request)
                break
            except LifecycleServicePublicationInProgressError:
                self._registry.wait_for_service_publication(request)
        with self.claimed_service_publication(token) as claimed:
            return claimed.commit_no_fail().service

    @staticmethod
    def _same_terminal_transport(
        plan: TransportLifecyclePublicationPlan,
        existing: TransportLifecycleSnapshot | None,
        binding_closed_at: datetime | None,
    ) -> bool:
        """Return whether an exact retry already published the complete ledger."""

        if existing is None or existing.identity != plan.identity:
            return False
        if existing.closed_at != plan.identity.close_deadline:
            return False
        if plan.binding_identity is None:
            return True
        return binding_closed_at == plan.identity.close_deadline

    def validate_transport_publication(
        self,
        plan: TransportLifecyclePublicationPlan,
    ) -> None:
        """Preflight exact transport/session identity without registry mutation."""

        token = self.prepare_closed_transport_publication(plan)
        self.cancel_closed_transport_publication(token)

    @staticmethod
    def _closed_transport_request(
        plan: TransportLifecyclePublicationPlan,
        *,
        start_members: tuple[LifecycleClosedTransportStartMember, ...] = (),
        process_holds: tuple[LifecycleHold, ...] = (),
    ) -> LifecycleClosedTransportPublicationRequest:
        """Freeze every exact ledger ID consumed by one prepared publication."""

        identity = plan.identity
        barrier = LifecycleCloseBarrier(
            barrier_id=plan.close_barrier_id,
            subject=identity.ref,
            requested_at=identity.close_deadline,
            authority="generated",
            action_id=stable_uuid(
                "lifecycle-transport-close-action",
                plan.action_id,
                identity.object_id,
            ),
        )
        return LifecycleClosedTransportPublicationRequest(
            identity=identity,
            start_members=start_members,
            process_holds=process_holds,
            binding_identity=plan.binding_identity,
            start_action_id=stable_uuid(
                "lifecycle-transport-start-action",
                plan.action_id,
                identity.object_id,
            ),
            start_transition_id=plan.transition_id,
            start_transition_ordinal=0,
            binding_close_action_id=(
                ""
                if plan.binding_identity is None
                else stable_uuid(
                    "lifecycle-transport-unbind-action",
                    plan.action_id,
                    identity.object_id,
                )
            ),
            binding_close_transition_ordinal=0,
            barrier=barrier,
            ticket_id=plan.close_ticket_id,
        )

    def prepare_closed_transport_publication(
        self,
        plan: TransportLifecyclePublicationPlan,
        *,
        start_members: tuple[LifecycleClosedTransportStartMember, ...] = (),
        process_holds: tuple[LifecycleHold, ...] = (),
    ) -> LifecycleClosedTransportAdmissionToken:
        """Reserve a full lifecycle start/transport/closure batch without rows."""

        return self._registry.prepare_closed_transport_publication(
            self._closed_transport_request(
                plan,
                start_members=start_members,
                process_holds=process_holds,
            )
        )

    def cancel_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> None:
        """Cancel one unclaimed transport reservation."""

        self._registry.cancel_closed_transport_publication(token)

    def authenticates_closed_transport_admission_token(
        self,
        token: object,
        *,
        plan: TransportLifecyclePublicationPlan | None = None,
        start_members: tuple[LifecycleClosedTransportStartMember, ...] = (),
        process_holds: tuple[LifecycleHold, ...] = (),
    ) -> bool:
        """Authenticate an active one-shot token and optional composite inputs."""

        request = (
            None
            if plan is None
            else self._closed_transport_request(
                plan,
                start_members=start_members,
                process_holds=process_holds,
            )
        )
        return self._registry.authenticates_closed_transport_admission_token(
            token,
            request=request,
            start_plan_tokens=tuple(member.publication_token for member in start_members),
        )

    def closed_transport_preparation_census(
        self,
    ) -> LifecycleClosedTransportPreparationCensus:
        """Return constant-time transient reservation counts."""

        return self._registry.closed_transport_preparation_census()

    @contextmanager
    def claimed_closed_transport_publication(
        self,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> Iterator[PreparedLifecycleClosedTransportPublication]:
        """Yield a one-shot commit capability without retaining registry locks."""

        with self._registry.claimed_closed_transport_publication(token) as claimed:
            yield claimed

    def authenticates_closed_transport_publication_receipt(
        self,
        receipt: object,
        *,
        plan: TransportLifecyclePublicationPlan | None = None,
        start_members: tuple[LifecycleClosedTransportStartMember, ...] = (),
        start_plan_tokens: tuple[str, ...] = (),
        process_holds: tuple[LifecycleHold, ...] = (),
    ) -> bool:
        """Authenticate a receipt and optional exact composite inputs."""

        request = (
            None
            if plan is None
            else self._closed_transport_request(
                plan,
                start_members=start_members,
                process_holds=process_holds,
            )
        )
        exact_start_tokens = (
            start_plan_tokens
            if start_plan_tokens
            else tuple(member.publication_token for member in start_members)
        )
        return self._registry.authenticates_closed_transport_publication_receipt(
            receipt,
            request=request,
            start_plan_tokens=exact_start_tokens,
        )

    def publish_closed_transport(
        self,
        plan: TransportLifecyclePublicationPlan,
    ) -> TransportLifecycleSnapshot:
        """Publish and terminalize one completed canonical transport ledger."""

        request = self._closed_transport_request(plan)
        while True:
            try:
                token = self._registry.prepare_closed_transport_publication(request)
                break
            except LifecycleClosedTransportPublicationInProgressError:
                self._registry.wait_for_closed_transport_publication(request)
        with self.claimed_closed_transport_publication(token) as claimed:
            return claimed.commit_no_fail().transport


def lifecycle_production_adapter_for(
    executor: LifecycleAdapterExecutor,
) -> LifecycleProductionAdapter | None:
    """Resolve the shared registry without retaining parallel action state.

    Lightweight direct-test dispatchers may intentionally omit lifecycle
    authority.  A dispatcher that declares strict enforcement may never do so.
    """

    dispatcher = getattr(executor, "dispatcher", None)
    if dispatcher is None or not hasattr(dispatcher, "lifecycle_shadow"):
        return None
    shadow = getattr(dispatcher, "lifecycle_shadow", None)
    if shadow is None:
        if bool(getattr(dispatcher, "enforces_lifecycle_authority", False)):
            raise StateError("Strict action execution requires lifecycle registry authority")
        return None
    registry = getattr(shadow, "registry", None)
    if registry is None:
        raise StateError("Injected lifecycle adapter does not expose registry authority")
    if not isinstance(registry, LifecycleRegistry):
        raise StateError("Action dispatcher exposes an incompatible lifecycle registry")
    return LifecycleProductionAdapter(registry)
