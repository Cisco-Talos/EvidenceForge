# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable canonical Windows remote-authentication types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from evidenceforge.events.network import NetworkTuple

RemoteAuthenticationOutcome = Literal["success", "failure"]
RemoteAuthenticationTransportRole = Literal[
    "target_service",
    "kerberos_validation",
    "ntlm_validation",
    "rdp",
]


@dataclass(frozen=True, slots=True)
class RemoteAuthenticationTransportPlan:
    """One role-labelled transport participating in remote authentication."""

    role: RemoteAuthenticationTransportRole
    transaction_id: str
    tuple: NetworkTuple
    started_at: datetime
    closed_at: datetime | None
    primary: bool = False

    def __post_init__(self) -> None:
        """Validate transport identity and interval semantics."""

        if not self.transaction_id:
            raise ValueError("Remote-authentication transports require a transaction ID")
        if self.closed_at is not None and self.closed_at < self.started_at:
            raise ValueError("Remote-authentication transport close cannot precede its start")


@dataclass(frozen=True, slots=True)
class RemoteAuthenticationPlan:
    """Final canonical phase and correlation truth for one remote authentication."""

    stable_id: str
    source_hostname: str
    target_hostname: str
    logon_type: int
    auth_protocol: str
    outcome: RemoteAuthenticationOutcome
    canonical_auth_time: datetime
    transports: tuple[RemoteAuthenticationTransportPlan, ...] = ()
    session_object_id: str = ""
    logon_id: str = ""

    def __post_init__(self) -> None:
        """Reject ambiguous transport ownership and invalid session outcomes."""

        if not self.stable_id or not self.target_hostname:
            raise ValueError("Remote-authentication plans require stable and target identities")
        transaction_ids = [transport.transaction_id for transport in self.transports]
        if len(transaction_ids) != len(set(transaction_ids)):
            raise ValueError("Remote-authentication transaction IDs must be unique")
        primary_transports = [transport for transport in self.transports if transport.primary]
        if len(primary_transports) > 1:
            raise ValueError("Remote-authentication plans permit at most one primary transport")
        if self.outcome == "failure" and (self.session_object_id or self.logon_id):
            raise ValueError("Failed remote authentication cannot own a durable session")

    @property
    def primary_transport(self) -> RemoteAuthenticationTransportPlan | None:
        """Return the target transport that anchors source-visible authentication."""

        return next((transport for transport in self.transports if transport.primary), None)
