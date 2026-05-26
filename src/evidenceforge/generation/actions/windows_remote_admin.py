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

"""Windows remote administration action bundles."""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    FileContext,
    HostContext,
    ProcessContext,
    ServiceContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

_LINUX_LOCAL_ACCOUNTS = {
    "apache",
    "mysql",
    "nginx",
    "postgres",
    "root",
    "sshd",
    "www-data",
}


@dataclass(frozen=True, slots=True)
class ExplicitCredentialUseRequest:
    """Intent for one Windows explicit-credential use event."""

    user: User
    system: System
    time: datetime
    target_username: str
    target_server: str
    process_name: str
    process_pid: int | None
    source_ip: str = ""
    source_port: int = 0
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:windows_explicit_credentials:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_server}:{self.process_name}:"
            f"{self.process_pid or ''}:{self.source_ip}:{self.source_port}:{self.source}"
        )
        return f"windows-explicit-credentials-{seed:016x}"


@dataclass(frozen=True, slots=True)
class WindowsServiceInstallRequest:
    """Intent for one modeled Windows remote service installation."""

    user: User
    system: System
    time: datetime
    service_name: str
    service_file_name: str
    service_type: str = "0x10"
    service_start_type: str = "3"
    service_account: str = "LocalSystem"
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:windows_service_install:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.service_name}:{self.service_file_name}:{self.service_type}:"
            f"{self.service_start_type}:{self.service_account}:{self.source}"
        )
        return f"windows-service-install-{seed:016x}"


class WindowsRemoteAdminExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    dispatcher: EventDispatcher
    state_manager: StateManager

    def _coerce_windows_explicit_credentials_subject(
        self,
        user: User,
        system: System,
        target_username: str,
    ) -> User:
        """Return the source-native 4648 subject user."""
        ...

    def _ensure_explicit_credentials_subject_logon(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> str:
        """Return a visible subject logon ID for 4648."""
        ...

    def _account_subject_fields(
        self,
        username: str,
        system: System,
        logon_id: str = "",
    ) -> dict[str, str]:
        """Return Windows subject account fields."""
        ...

    def _get_system_pid(self, hostname: str, process: str, default: int) -> int:
        """Return a stable seeded system process PID."""
        ...

    def _get_sid(self, username: str) -> str:
        """Return a SID for a username."""
        ...

    def _build_host_context(self, system: System) -> HostContext:
        """Build canonical host context for a scenario system."""
        ...

    def generate_process(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        **kwargs: Any,
    ) -> int:
        """Generate canonical process-create evidence."""
        ...

    def _clamp_after_visible_process_create(
        self,
        system: System,
        pid: int,
        time: datetime,
        relationship_name: str,
    ) -> datetime:
        """Clamp source-visible activity after process creation."""
        ...

    def _explicit_credentials_source_ip(
        self,
        system: System,
        target_server: str,
        source_ip: str = "",
    ) -> str:
        """Return source-native network endpoint metadata for 4648."""
        ...

    def _explicit_credentials_target_domain(
        self,
        target_username: str,
        target_server: str,
        source_system: System,
    ) -> str:
        """Return source-native 4648 target domain."""
        ...

    def _emit_remote_service_control_network_evidence(
        self,
        user: User,
        target_system: System,
        time: datetime,
    ) -> None:
        """Emit SMB/RPC service-control transport evidence."""
        ...

    def _get_user_logon_id(
        self,
        username: str,
        hostname: str,
        at_time: datetime | None = None,
    ) -> str:
        """Return a user's active logon ID on a host."""
        ...


class ExplicitCredentialUseActionBundle:
    """Expand one explicit-credential use into coordinated source evidence."""

    def __init__(
        self,
        executor: WindowsRemoteAdminExecutor,
        request: ExplicitCredentialUseRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="windows_explicit_credentials",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit Windows Security 4648 evidence for explicit credential use."""

        target_account = self._request.target_username.split("\\")[-1].split("@", 1)[0].lower()
        if _get_os_category(self._request.system.os) == "windows" and (
            target_account in _LINUX_LOCAL_ACCOUNTS
        ):
            return

        subject_user = self._executor._coerce_windows_explicit_credentials_subject(
            self._request.user,
            self._request.system,
            self._request.target_username,
        )
        reporting_pid = self._executor._get_system_pid(
            self._request.system.hostname,
            "lsass",
            0x2E0,
        )
        subject_logon_id = self._executor._ensure_explicit_credentials_subject_logon(
            subject_user,
            self._request.system,
            self._request.time,
        )
        subject = self._executor._account_subject_fields(
            subject_user.username,
            self._request.system,
            subject_logon_id,
        )
        process_pid = self._resolve_process_pid(subject_user, subject_logon_id)
        event_time = self._request.time
        if process_pid > 0:
            event_time = self._executor._clamp_after_visible_process_create(
                self._request.system,
                process_pid,
                event_time,
                "source.windows_explicit_credentials_after_process_create",
            )
        network_source_ip = self._executor._explicit_credentials_source_ip(
            self._request.system,
            self._request.target_server,
            self._request.source_ip,
        )
        network_source_port = (
            self._request.source_port
            if not self._request.source_ip or self._request.source_ip.strip() == network_source_ip
            else 0
        )
        if network_source_ip not in {"", "-"} and network_source_port <= 0:
            network_source_port = self._sample_source_port()
        event = SecurityEvent(
            timestamp=event_time,
            event_type="explicit_credentials",
            dst_host=self._executor._build_host_context(self._request.system),
            auth=AuthContext(
                username=self._request.target_username,
                user_sid=self._executor._get_sid(self._request.target_username),
                target_domain=self._executor._explicit_credentials_target_domain(
                    self._request.target_username,
                    self._request.target_server,
                    self._request.system,
                ),
                subject_sid=subject["sid"],
                subject_username=subject["username"],
                subject_domain=subject["domain"],
                subject_logon_id=subject["logon_id"],
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                reporting_pid=reporting_pid,
                process_pid=process_pid,
                target_server=self._request.target_server,
                process_name=self._request.process_name,
                source_ip=network_source_ip or "-",
                source_port=network_source_port,
            ),
        )
        self._executor.dispatcher.dispatch(event)

    def _resolve_process_pid(self, subject_user: User, subject_logon_id: str) -> int:
        """Return or materialize the caller process for the 4648 event."""

        process_pid = self._request.process_pid or 0
        if process_pid > 0 and self._request.process_name:
            running_process = self._executor.state_manager.get_process(
                self._request.system.hostname,
                process_pid,
            )
            running_image = running_process.image if running_process is not None else ""
            if (
                running_image
                and ntpath.basename(running_image).lower()
                != ntpath.basename(self._request.process_name).lower()
            ):
                process_pid = 0
        if process_pid <= 0 and self._request.process_name:
            process_time = self._request.time - timedelta(seconds=1)
            scenario_start = getattr(self._executor, "_scenario_start_time", None)
            if scenario_start is not None and ensure_utc(process_time) < ensure_utc(scenario_start):
                process_time = self._request.time - timedelta(milliseconds=500)
            process_pid = self._executor.generate_process(
                subject_user,
                self._request.system,
                process_time,
                subject_logon_id,
                self._request.process_name,
                ntpath.basename(self._request.process_name),
            )
        return process_pid

    def _sample_source_port(self) -> int:
        """Return a source-native ephemeral port for explicit credential network metadata."""

        rng = _get_rng()
        os_category = _get_os_category(self._request.system.os)
        if os_category == "linux":
            return rng.randint(32768, 60999)
        return rng.randint(49152, 65535)


class WindowsServiceInstallActionBundle:
    """Expand one Windows service install into remote-admin evidence."""

    def __init__(
        self,
        executor: WindowsRemoteAdminExecutor,
        request: WindowsServiceInstallRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="windows_service_install",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit remote service-control, payload, and service-install evidence."""

        self._executor._emit_remote_service_control_network_evidence(
            self._request.user,
            self._request.system,
            self._request.time,
        )
        self._emit_payload_file_create()
        reporting_pid = self._executor._get_system_pid(
            self._request.system.hostname,
            "lsass",
            0x2E0,
        )
        host = self._executor._build_host_context(self._request.system)
        event = SecurityEvent(
            timestamp=self._request.time,
            event_type="service_installed",
            src_host=host,
            auth=AuthContext(
                username=self._request.user.username,
                subject_sid=self._executor._get_sid(self._request.user.username),
                subject_username=self._request.user.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._executor._get_user_logon_id(
                    self._request.user.username,
                    self._request.system.hostname,
                    self._request.time,
                ),
                reporting_pid=reporting_pid,
            ),
            service=ServiceContext(
                service_name=self._request.service_name,
                service_file_name=self._request.service_file_name,
                service_type=self._request.service_type,
                service_start_type=self._request.service_start_type,
                service_account=self._request.service_account,
            ),
        )
        self._executor.dispatcher.dispatch(event)

    def _emit_payload_file_create(self) -> None:
        """Emit dropped service binary evidence when the service path is not preexisting."""

        if _get_os_category(self._request.system.os) != "windows":
            return
        service_path = self._request.service_file_name.replace("%SystemRoot%", r"C:\Windows")
        service_path = service_path.replace("%systemroot%", r"C:\Windows")
        service_path_lower = service_path.lower().replace("/", "\\")
        is_preexisting_binary = (
            service_path_lower.startswith("c:\\windows\\system32\\")
            or service_path_lower.startswith("c:\\windows\\syswow64\\")
            or service_path_lower.startswith("c:\\program files\\")
            or service_path_lower.startswith("c:\\program files (x86)\\")
        )
        if is_preexisting_binary:
            return
        services_pid = self._executor._get_system_pid(
            self._request.system.hostname,
            "services",
            0x2BC,
        )
        services_obj_id = self._executor.state_manager.get_process_object_id(
            self._request.system.hostname,
            services_pid,
        )
        file_time = self._request.time - timedelta(milliseconds=250)
        self._executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=file_time,
                event_type="file_create",
                src_host=self._executor._build_host_context(self._request.system),
                auth=AuthContext(username="SYSTEM"),
                process=ProcessContext(
                    pid=services_pid,
                    parent_pid=self._executor._get_system_pid(
                        self._request.system.hostname,
                        "wininit",
                        0x1F4,
                    ),
                    image=r"C:\Windows\System32\services.exe",
                    command_line=r"C:\Windows\System32\services.exe",
                    username="SYSTEM",
                    logon_id="0x3e7",
                ),
                file=FileContext(path=service_path, action="create", pid=services_pid),
                edr=EdrContext(
                    object_id=stable_uuid(
                        "service-install-file-edr",
                        self._request.system.hostname,
                        services_pid,
                        service_path,
                        file_time.isoformat(),
                    ),
                    actor_id=services_obj_id,
                ),
            )
        )
