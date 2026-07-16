# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Windows remote-authentication action planning."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from evidenceforge.events.authentication import (
    RemoteAuthenticationOutcome,
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
    RemoteAuthenticationTransportRole,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionActionBundle,
    NetworkConnectionRequest,
)
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class WindowsRemoteAuthenticationRequest:
    """Intent for one Windows remote-authentication occurrence."""

    target_system: System
    time: datetime
    source_ip: str
    source_port: int
    logon_type: int
    auth_protocol: str
    outcome: RemoteAuthenticationOutcome
    destination_port: int
    source_system: System | None = None
    session_object_id: str = ""
    logon_id: str = ""
    emit_transport: bool = True
    transport_role: RemoteAuthenticationTransportRole = "target_service"
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return the durable action-group identity."""

        source_hostname = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:windows_remote_authentication:"
            f"{self.target_system.hostname}:{self.time.isoformat()}:{self.source_ip}:"
            f"{self.source_port}:{self.logon_type}:{self.auth_protocol}:{self.outcome}:"
            f"{self.destination_port}:{source_hostname}:{self.logon_id}:{self.source}"
        )
        return f"windows-remote-auth-{seed:016x}"


class WindowsRemoteAuthenticationExecutor(Protocol):
    """Services required by the remote-authentication action planner."""

    state_manager: object


class WindowsRemoteAuthenticationPlanner:
    """Plan and execute one Windows transport-to-authentication occurrence."""

    def __init__(self, executor: WindowsRemoteAuthenticationExecutor) -> None:
        self._executor = executor

    def execute(self, request: WindowsRemoteAuthenticationRequest) -> RemoteAuthenticationPlan:
        """Emit the primary transport and return frozen canonical authentication truth."""

        if not request.emit_transport:
            return self.without_transport(request)

        network_request = self._network_request(request)
        transaction_id = network_request.stable_id
        uid = NetworkConnectionActionBundle(self._executor, network_request).execute()
        connection = next(
            (
                candidate
                for candidate in self._executor.state_manager.list_open_connections()
                if candidate.zeek_uid == uid
            ),
            None,
        )
        if connection is None:
            raise ValueError(
                "Remote-authentication transport did not persist canonical connection state"
            )
        transport = RemoteAuthenticationTransportPlan(
            role=request.transport_role,
            transaction_id=transaction_id,
            tuple=NetworkTuple(
                src_ip=connection.src_ip,
                src_port=connection.src_port,
                dst_ip=connection.dst_ip,
                dst_port=connection.dst_port,
                protocol=connection.protocol,
            ),
            started_at=connection.start_time,
            closed_at=connection.close_time,
            primary=True,
        )
        return self._plan(request, transports=(transport,))

    def without_transport(
        self,
        request: WindowsRemoteAuthenticationRequest,
    ) -> RemoteAuthenticationPlan:
        """Return canonical authentication truth when collection models no transport."""

        return self._plan(request, transports=())

    def from_existing_transport(
        self,
        request: WindowsRemoteAuthenticationRequest,
        *,
        transaction_id: str,
        tuple_view: NetworkTuple,
        started_at: datetime,
        closed_at: datetime | None,
    ) -> RemoteAuthenticationPlan:
        """Adapt an already-executed specialized transport such as RDP."""

        transport = RemoteAuthenticationTransportPlan(
            role=request.transport_role,
            transaction_id=transaction_id,
            tuple=tuple_view,
            started_at=started_at,
            closed_at=closed_at,
            primary=True,
        )
        return self._plan(request, transports=(transport,))

    @staticmethod
    def _plan(
        request: WindowsRemoteAuthenticationRequest,
        *,
        transports: tuple[RemoteAuthenticationTransportPlan, ...],
    ) -> RemoteAuthenticationPlan:
        return RemoteAuthenticationPlan(
            stable_id=request.stable_id,
            source_hostname=(
                request.source_system.hostname if request.source_system is not None else ""
            ),
            target_hostname=request.target_system.hostname,
            logon_type=request.logon_type,
            auth_protocol=request.auth_protocol,
            outcome=request.outcome,
            canonical_auth_time=request.time,
            transports=transports,
            session_object_id=(request.session_object_id if request.outcome == "success" else ""),
            logon_id=request.logon_id if request.outcome == "success" else "",
        )

    def _network_request(
        self,
        request: WindowsRemoteAuthenticationRequest,
    ) -> NetworkConnectionRequest:
        seed = _stable_seed(
            "windows_remote_auth_transport:"
            f"{request.stable_id}:{request.source_ip}:{request.source_port}:"
            f"{request.target_system.ip}:{request.destination_port}"
        )
        rng = random.Random(seed)
        if request.outcome == "success":
            start_gap_ms = rng.randint(150, 900)
            duration = rng.uniform(1.5, 45.0)
            conn_state = "SF"
            orig_bytes = rng.randint(800, 8000)
            resp_bytes = rng.randint(500, 12000)
        else:
            start_gap_ms = rng.randint(20, 250)
            duration = rng.uniform(0.02, 1.5)
            conn_state = rng.choices(["SF", "RSTR"], weights=[70, 30], k=1)[0]
            orig_bytes = rng.randint(120, 900)
            resp_bytes = rng.randint(0, 500)

        started_at = request.time - timedelta(milliseconds=start_gap_ms)
        if request.outcome == "success":
            minimum_duration = (request.time - started_at).total_seconds() + 0.25
            duration = max(duration, minimum_duration)
        service = {
            88: "kerberos",
            389: "ldap",
            445: "smb",
            3389: "rdp",
        }.get(request.destination_port)
        return NetworkConnectionRequest(
            src_ip=request.source_ip,
            dst_ip=request.target_system.ip,
            time=started_at,
            dst_port=request.destination_port,
            proto="tcp",
            service=service,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            src_port=request.source_port,
            source_system=request.source_system,
            conn_state=conn_state,
            parent_action_group_id=request.stable_id,
            preserve_start_time=True,
            source="windows_remote_authentication",
        )


class WindowsRemoteAuthenticationActionBundle:
    """Expand one remote-authentication intent through its canonical planner."""

    def __init__(
        self,
        executor: WindowsRemoteAuthenticationExecutor,
        request: WindowsRemoteAuthenticationRequest,
    ) -> None:
        self._planner = WindowsRemoteAuthenticationPlanner(executor)
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="windows_remote_authentication",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> RemoteAuthenticationPlan:
        """Emit the planned transport and return canonical action truth."""

        return self._planner.execute(self._request)
