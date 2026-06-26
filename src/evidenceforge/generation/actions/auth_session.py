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

"""Authentication and session lifecycle action bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class LogonRequest:
    """Intent for one successful authentication/session start."""

    user: User
    system: System
    time: datetime
    logon_type: int = 2
    source_ip: str | None = None
    source_system: System | None = None
    source_port: int | None = None
    emit_transport_syslog: bool = True
    emit_network_evidence: bool = True
    logon_id: str | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_host = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:logon:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_type}:{self.source_ip or ''}:{self.source_port or ''}:"
            f"{self.emit_transport_syslog}:{self.emit_network_evidence}:"
            f"{self.logon_id or ''}:{source_host}:{self.source}"
        )
        return f"logon-{seed:016x}"


@dataclass(frozen=True, slots=True)
class LogoffRequest:
    """Intent for one session termination."""

    user: User
    system: System
    time: datetime
    logon_id: str
    logon_type: int = 2
    from_storyline: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:logoff:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_id}:{self.logon_type}:{self.from_storyline}:{self.source}"
        )
        return f"logoff-{seed:016x}"


@dataclass(frozen=True, slots=True)
class FailedLogonRequest:
    """Intent for one failed authentication attempt."""

    user: User
    system: System
    time: datetime
    logon_type: int = 2
    source_ip: str | None = None
    target_username: str | None = None
    dc_system: System | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        dc_name = self.dc_system.hostname if self.dc_system is not None else ""
        seed = _stable_seed(
            "action_bundle:failed_logon:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_type}:{self.source_ip or ''}:{self.target_username or ''}:"
            f"{dc_name}:{self.source}"
        )
        return f"failed-logon-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ServiceLogonRequest:
    """Intent for one Windows service logon."""

    system: System
    time: datetime
    service_account: str = "SYSTEM"
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:service_logon:"
            f"{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.service_account}:{self.source}"
        )
        return f"service-logon-{seed:016x}"


@dataclass(frozen=True, slots=True)
class MachineAccountLogonRequest:
    """Intent for one machine-account DC logon lifecycle."""

    hostname: str
    machine_username: str
    dc_hostname: str
    source_ip: str
    dc_ip: str
    time: datetime
    domain: str = ""
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:machine_account_logon:"
            f"{self.hostname}:{self.machine_username}:{self.dc_hostname}:"
            f"{self.source_ip}:{self.dc_ip}:{self.time.isoformat()}:"
            f"{self.domain}:{self.source}"
        )
        return f"machine-account-logon-{seed:016x}"


@dataclass(frozen=True, slots=True)
class NtlmValidationRequest:
    """Intent for one DC-side NTLM credential validation."""

    username: str
    workstation: str
    dc_hostname: str
    time: datetime
    status: str = "0x0"
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:ntlm_validation:"
            f"{self.username}:{self.workstation}:{self.dc_hostname}:"
            f"{self.time.isoformat()}:{self.status}:{self.source}"
        )
        return f"ntlm-validation-{seed:016x}"


@dataclass(frozen=True, slots=True)
class AnonymousLogonRequest:
    """Intent for one anonymous Windows network logon."""

    system: System
    time: datetime
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:anonymous_logon:"
            f"{self.system.hostname}:{self.time.isoformat()}:{self.source}"
        )
        return f"anonymous-logon-{seed:016x}"


@dataclass(frozen=True, slots=True)
class WorkstationLockRequest:
    """Intent for one workstation lock event."""

    user: User
    system: System
    time: datetime
    logon_id: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:workstation_lock:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_id}:{self.source}"
        )
        return f"workstation-lock-{seed:016x}"


@dataclass(frozen=True, slots=True)
class WorkstationUnlockRequest:
    """Intent for one workstation unlock event."""

    user: User
    system: System
    time: datetime
    logon_id: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:workstation_unlock:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_id}:{self.source}"
        )
        return f"workstation-unlock-{seed:016x}"


class AuthSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_logon_bundle(self, request: LogonRequest) -> str:
        """Expand one successful logon request into canonical evidence."""
        ...

    def _execute_logoff_bundle(self, request: LogoffRequest) -> None:
        """Expand one logoff request into canonical evidence."""
        ...

    def _execute_failed_logon_bundle(self, request: FailedLogonRequest) -> None:
        """Expand one failed logon request into canonical evidence."""
        ...

    def _execute_service_logon_bundle(self, request: ServiceLogonRequest) -> str:
        """Expand one service logon request into canonical evidence."""
        ...

    def _execute_machine_account_logon_bundle(
        self,
        request: MachineAccountLogonRequest,
    ) -> None:
        """Expand one machine account logon request into canonical evidence."""
        ...

    def _execute_ntlm_validation_bundle(self, request: NtlmValidationRequest) -> None:
        """Expand one NTLM validation request into canonical evidence."""
        ...

    def _execute_anonymous_logon_bundle(self, request: AnonymousLogonRequest) -> None:
        """Expand one anonymous logon request into canonical evidence."""
        ...

    def _execute_workstation_lock_bundle(self, request: WorkstationLockRequest) -> None:
        """Expand one workstation lock request into canonical evidence."""
        ...

    def _execute_workstation_unlock_bundle(self, request: WorkstationUnlockRequest) -> None:
        """Expand one workstation unlock request into canonical evidence."""
        ...


class LogonActionBundle:
    """Expand one successful logon intent into session/auth evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: LogonRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="logon",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Emit successful logon/session-start evidence."""

        return self._executor._execute_logon_bundle(self._request)


class LogoffActionBundle:
    """Expand one logoff intent into session termination evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: LogoffRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="logoff",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit logoff/session-end evidence."""

        self._executor._execute_logoff_bundle(self._request)


class FailedLogonActionBundle:
    """Expand one failed-authentication intent into auth failure evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: FailedLogonRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="failed_logon",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit failed logon evidence and companion validation/network evidence."""

        self._executor._execute_failed_logon_bundle(self._request)


class ServiceLogonActionBundle:
    """Expand one service-logon intent into service session evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: ServiceLogonRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="service_logon",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Emit service logon evidence."""

        return self._executor._execute_service_logon_bundle(self._request)


class MachineAccountLogonActionBundle:
    """Expand one machine-account logon intent into DC auth lifecycle evidence."""

    def __init__(
        self,
        executor: AuthSessionExecutor,
        request: MachineAccountLogonRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="machine_account_logon",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit machine-account DC auth lifecycle evidence."""

        self._executor._execute_machine_account_logon_bundle(self._request)


class NtlmValidationActionBundle:
    """Expand one NTLM validation intent into DC validation evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: NtlmValidationRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="ntlm_validation",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit NTLM validation evidence."""

        self._executor._execute_ntlm_validation_bundle(self._request)


class AnonymousLogonActionBundle:
    """Expand one anonymous logon intent into Windows network-logon evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: AnonymousLogonRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="anonymous_logon",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit anonymous logon evidence."""

        self._executor._execute_anonymous_logon_bundle(self._request)


class WorkstationLockActionBundle:
    """Expand one workstation-lock intent into lock evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: WorkstationLockRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="workstation_lock",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit workstation-lock evidence."""

        self._executor._execute_workstation_lock_bundle(self._request)


class WorkstationUnlockActionBundle:
    """Expand one workstation-unlock intent into unlock and reauth evidence."""

    def __init__(self, executor: AuthSessionExecutor, request: WorkstationUnlockRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="workstation_unlock",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit workstation-unlock evidence."""

        self._executor._execute_workstation_unlock_bundle(self._request)
