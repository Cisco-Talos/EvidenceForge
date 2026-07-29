# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Kerberos/DC action bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class KerberosLogonTicketsRequest:
    """Intent for DC-side TGT/TGS evidence that supports a member-host logon."""

    user: User
    system: System
    time: datetime
    auth_package: str
    source_ip: str
    source: str = "causal_logon"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:kerberos_logon_tickets:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.auth_package}:{self.source_ip}:{self.source}"
        )
        return f"kerberos-logon-tickets-{seed:016x}"


@dataclass(frozen=True, slots=True)
class KerberosConnectionAuditRequest:
    """Intent for DC-side Kerberos audit companions for a visible KDC flow."""

    src_ip: str
    src_port: int
    dst_ip: str
    time: datetime
    dst_port: int
    proto: str
    service: str
    source_system: System | None
    conn_state: str = "SF"
    source: str = "network_connection"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        hostname = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:kerberos_connection_audit:"
            f"{self.src_ip}:{self.src_port}:{self.dst_ip}:{self.dst_port}:"
            f"{self.proto}:{self.conn_state}:{self.service}:"
            f"{self.time.isoformat()}:{hostname}:{self.source}"
        )
        return f"kerberos-connection-audit-{seed:016x}"


@dataclass(frozen=True, slots=True)
class KerberosTgtRequest:
    """Intent for one DC-side Kerberos TGT request event."""

    username: str
    source_ip: str
    dc_hostname: str
    time: datetime
    domain: str = ""
    source_port: int | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:kerberos_tgt:"
            f"{self.username}:{self.source_ip}:{self.dc_hostname}:{self.time.isoformat()}:"
            f"{self.domain}:{self.source_port or ''}:{self.source}"
        )
        return f"kerberos-tgt-{seed:016x}"


@dataclass(frozen=True, slots=True)
class KerberosTgtRenewalRequest:
    """Intent for one DC-side Kerberos TGT renewal event."""

    username: str
    source_ip: str
    dc_hostname: str
    time: datetime
    domain: str = ""
    source_port: int | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:kerberos_tgt_renewal:"
            f"{self.username}:{self.source_ip}:{self.dc_hostname}:{self.time.isoformat()}:"
            f"{self.domain}:{self.source_port or ''}:{self.source}"
        )
        return f"kerberos-tgt-renewal-{seed:016x}"


@dataclass(frozen=True, slots=True)
class KerberosServiceTicketRequest:
    """Intent for one DC-side Kerberos service-ticket request event."""

    username: str
    service_name: str
    source_ip: str
    dc_hostname: str
    time: datetime
    domain: str = ""
    source_port: int | None = None
    service_account_name: str = ""
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:kerberos_service_ticket:"
            f"{self.username}:{self.service_name}:{self.source_ip}:{self.dc_hostname}:"
            f"{self.time.isoformat()}:{self.domain}:{self.source_port or ''}:"
            f"{self.service_account_name}:{self.source}"
        )
        return f"kerberos-service-ticket-{seed:016x}"


@dataclass(frozen=True, slots=True)
class KerberosPreauthFailureRequest:
    """Intent for one DC-side Kerberos pre-authentication failure."""

    username: str
    source_ip: str
    dc_hostname: str
    time: datetime
    status: str = "0x18"
    source_port: int | None = None
    emit_connection: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:kerberos_preauth_failure:"
            f"{self.username}:{self.source_ip}:{self.dc_hostname}:{self.time.isoformat()}:"
            f"{self.status}:{self.source_port or ''}:{self.emit_connection}:{self.source}"
        )
        return f"kerberos-preauth-failure-{seed:016x}"


class KerberosDcExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_kerberos_logon_tickets_bundle(
        self,
        request: KerberosLogonTicketsRequest,
    ) -> None:
        """Expand logon-supporting DC Kerberos evidence."""
        ...

    def _execute_kerberos_connection_audit_bundle(
        self,
        request: KerberosConnectionAuditRequest,
    ) -> None:
        """Expand DC Kerberos audit companions for one visible KDC flow."""
        ...

    def _execute_kerberos_tgt_bundle(self, request: KerberosTgtRequest) -> None:
        """Expand one Kerberos TGT event."""
        ...

    def _execute_kerberos_tgt_renewal_bundle(
        self,
        request: KerberosTgtRenewalRequest,
    ) -> None:
        """Expand one Kerberos TGT renewal event."""
        ...

    def _execute_kerberos_service_ticket_bundle(
        self,
        request: KerberosServiceTicketRequest,
    ) -> None:
        """Expand one Kerberos service-ticket event."""
        ...

    def _execute_kerberos_preauth_failure_bundle(
        self,
        request: KerberosPreauthFailureRequest,
    ) -> None:
        """Expand one Kerberos pre-authentication failure event."""
        ...


class KerberosLogonTicketsActionBundle:
    """Expand a member-host Kerberos logon into DC-side TGT/TGS evidence."""

    def __init__(
        self,
        executor: KerberosDcExecutor,
        request: KerberosLogonTicketsRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_logon_tickets",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit DC-side TGT/TGS evidence for the logon."""

        self._executor._execute_kerberos_logon_tickets_bundle(self._request)


class KerberosConnectionAuditActionBundle:
    """Expand a visible KDC flow into nearby DC audit evidence when needed."""

    def __init__(
        self,
        executor: KerberosDcExecutor,
        request: KerberosConnectionAuditRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_connection_audit",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit DC audit companions for a visible KDC flow."""

        self._executor._execute_kerberos_connection_audit_bundle(self._request)


class KerberosTgtActionBundle:
    """Expand one Kerberos TGT intent into canonical DC evidence."""

    def __init__(self, executor: KerberosDcExecutor, request: KerberosTgtRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_tgt",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Kerberos TGT event."""

        self._executor._execute_kerberos_tgt_bundle(self._request)


class KerberosTgtRenewalActionBundle:
    """Expand one Kerberos TGT renewal intent into canonical DC evidence."""

    def __init__(
        self,
        executor: KerberosDcExecutor,
        request: KerberosTgtRenewalRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_tgt_renewal",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Kerberos TGT renewal event."""

        self._executor._execute_kerberos_tgt_renewal_bundle(self._request)


class KerberosServiceTicketActionBundle:
    """Expand one Kerberos service-ticket intent into canonical DC evidence."""

    def __init__(
        self,
        executor: KerberosDcExecutor,
        request: KerberosServiceTicketRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_service_ticket",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Kerberos service-ticket event."""

        self._executor._execute_kerberos_service_ticket_bundle(self._request)


class KerberosPreauthFailureActionBundle:
    """Expand one Kerberos pre-authentication failure into DC evidence."""

    def __init__(
        self,
        executor: KerberosDcExecutor,
        request: KerberosPreauthFailureRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="kerberos_preauth_failure",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Kerberos pre-authentication failure event."""

        self._executor._execute_kerberos_preauth_failure_bundle(self._request)
