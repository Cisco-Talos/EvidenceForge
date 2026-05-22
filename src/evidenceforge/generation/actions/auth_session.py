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
    source_port: int | None = None
    emit_transport_syslog: bool = True
    emit_network_evidence: bool = True
    logon_id: str | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:logon:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_type}:{self.source_ip or ''}:{self.source_port or ''}:"
            f"{self.emit_transport_syslog}:{self.emit_network_evidence}:"
            f"{self.logon_id or ''}:{self.source}"
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
