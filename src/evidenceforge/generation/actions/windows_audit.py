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

"""Windows audit and endpoint audit action bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class LogClearedRequest:
    """Intent for one Windows Security log clear event."""

    user: User
    system: System
    time: datetime
    from_storyline: bool = False
    subject_logon_id: str | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:log_cleared:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.from_storyline}:{self.subject_logon_id or ''}:{self.source}"
        )
        return f"log-cleared-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ScheduledTaskRequest:
    """Intent for one Windows scheduled-task audit event."""

    user: User
    system: System
    time: datetime
    task_name: str
    action: str = "created"
    task_content: str = ""
    source_command_line: str = ""
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:scheduled_task:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.task_name}:{self.action}:{self.task_content}:"
            f"{self.source_command_line}:{self.source}"
        )
        return f"scheduled-task-{seed:016x}"


@dataclass(frozen=True, slots=True)
class GroupMembershipChangeRequest:
    """Intent for one Windows group-membership audit event."""

    actor: User
    system: System
    time: datetime
    action: str
    scope: str
    group_name: str
    group_sid: str
    member_username: str
    member_sid: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:group_membership_change:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.action}:{self.scope}:{self.group_name}:{self.group_sid}:"
            f"{self.member_username}:{self.member_sid}:{self.source}"
        )
        return f"group-membership-change-{seed:016x}"


@dataclass(frozen=True, slots=True)
class AccountCreatedRequest:
    """Intent for one Windows account-created audit event."""

    actor: User
    system: System
    time: datetime
    target_username: str
    target_sid: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:account_created:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_sid}:{self.source}"
        )
        return f"account-created-{seed:016x}"


@dataclass(frozen=True, slots=True)
class AccountDeletedRequest:
    """Intent for one Windows account-deleted audit event."""

    actor: User
    system: System
    time: datetime
    target_username: str
    target_sid: str
    from_storyline: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:account_deleted:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_sid}:{self.from_storyline}:{self.source}"
        )
        return f"account-deleted-{seed:016x}"


@dataclass(frozen=True, slots=True)
class PasswordResetRequest:
    """Intent for one Windows password-reset audit event."""

    actor: User
    system: System
    time: datetime
    target_username: str
    target_sid: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:password_reset:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_sid}:{self.source}"
        )
        return f"password-reset-{seed:016x}"


@dataclass(frozen=True, slots=True)
class PasswordChangeRequest:
    """Intent for one Windows password-change audit event."""

    user: User
    system: System
    time: datetime
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:password_change:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:{self.source}"
        )
        return f"password-change-{seed:016x}"


@dataclass(frozen=True, slots=True)
class AccountChangedRequest:
    """Intent for one Windows account-changed audit event."""

    actor: User
    system: System
    time: datetime
    target_username: str
    target_sid: str
    password_last_set_to_event_time: bool = False
    old_uac_value: str | None = None
    new_uac_value: str | None = None
    user_account_control: str | None = None
    primary_group_id: str | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:account_changed:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_sid}:"
            f"{self.password_last_set_to_event_time}:{self.old_uac_value or ''}:"
            f"{self.new_uac_value or ''}:{self.user_account_control or ''}:"
            f"{self.primary_group_id or ''}:{self.source}"
        )
        return f"account-changed-{seed:016x}"


@dataclass(frozen=True, slots=True)
class CreateRemoteThreadRequest:
    """Intent for one Sysmon/eCAR remote-thread creation event."""

    user: User
    system: System
    time: datetime
    source_pid: int
    source_image: str
    target_pid: int
    target_image: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:create_remote_thread:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.source_pid}:{self.source_image}:{self.target_pid}:"
            f"{self.target_image}:{self.source}"
        )
        return f"create-remote-thread-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ProcessAccessRequest:
    """Intent for one Sysmon/eCAR process-access event."""

    user: User
    system: System
    time: datetime
    source_pid: int
    source_image: str
    target_pid: int
    target_image: str = r"C:\Windows\System32\lsass.exe"
    granted_access: str = "0x1010"
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:process_access:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.source_pid}:{self.source_image}:{self.target_pid}:"
            f"{self.target_image}:{self.granted_access}:{self.source}"
        )
        return f"process-access-{seed:016x}"


class WindowsAuditExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_log_cleared_bundle(self, request: LogClearedRequest) -> None:
        """Expand one log clear request."""
        ...

    def _execute_scheduled_task_bundle(self, request: ScheduledTaskRequest) -> None:
        """Expand one scheduled task audit request."""
        ...

    def _execute_group_membership_change_bundle(
        self,
        request: GroupMembershipChangeRequest,
    ) -> None:
        """Expand one group membership audit request."""
        ...

    def _execute_account_created_bundle(self, request: AccountCreatedRequest) -> None:
        """Expand one account-created audit request."""
        ...

    def _execute_account_deleted_bundle(self, request: AccountDeletedRequest) -> None:
        """Expand one account-deleted audit request."""
        ...

    def _execute_password_reset_bundle(self, request: PasswordResetRequest) -> None:
        """Expand one password-reset audit request."""
        ...

    def _execute_password_change_bundle(self, request: PasswordChangeRequest) -> None:
        """Expand one password-change audit request."""
        ...

    def _execute_account_changed_bundle(self, request: AccountChangedRequest) -> None:
        """Expand one account-changed audit request."""
        ...

    def _execute_create_remote_thread_bundle(
        self,
        request: CreateRemoteThreadRequest,
    ) -> bool:
        """Expand one remote-thread audit request."""
        ...

    def _execute_process_access_bundle(self, request: ProcessAccessRequest) -> bool:
        """Expand one process-access audit request."""
        ...


class LogClearedActionBundle:
    """Expand one Windows Security log-clear intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: LogClearedRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="log_cleared",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows Security log-clear event."""

        self._executor._execute_log_cleared_bundle(self._request)


class ScheduledTaskActionBundle:
    """Expand one Windows scheduled-task audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: ScheduledTaskRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="scheduled_task",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows scheduled-task audit event."""

        self._executor._execute_scheduled_task_bundle(self._request)


class GroupMembershipChangeActionBundle:
    """Expand one Windows group-membership audit intent."""

    def __init__(
        self,
        executor: WindowsAuditExecutor,
        request: GroupMembershipChangeRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="group_membership_change",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows group-membership audit event."""

        self._executor._execute_group_membership_change_bundle(self._request)


class AccountCreatedActionBundle:
    """Expand one Windows account-created audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: AccountCreatedRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="account_created",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows account-created audit event."""

        self._executor._execute_account_created_bundle(self._request)


class AccountDeletedActionBundle:
    """Expand one Windows account-deleted audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: AccountDeletedRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="account_deleted",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows account-deleted audit event."""

        self._executor._execute_account_deleted_bundle(self._request)


class PasswordResetActionBundle:
    """Expand one Windows password-reset audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: PasswordResetRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="password_reset",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows password-reset audit event."""

        self._executor._execute_password_reset_bundle(self._request)


class PasswordChangeActionBundle:
    """Expand one Windows password-change audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: PasswordChangeRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="password_change",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows password-change audit event."""

        self._executor._execute_password_change_bundle(self._request)


class AccountChangedActionBundle:
    """Expand one Windows account-changed audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: AccountChangedRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="account_changed",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one Windows account-changed audit event."""

        self._executor._execute_account_changed_bundle(self._request)


class CreateRemoteThreadActionBundle:
    """Expand one remote-thread audit intent."""

    def __init__(
        self,
        executor: WindowsAuditExecutor,
        request: CreateRemoteThreadRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="create_remote_thread",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> bool:
        """Emit one remote-thread audit event when lifecycle validation allows it."""

        return self._executor._execute_create_remote_thread_bundle(self._request)


class ProcessAccessActionBundle:
    """Expand one process-access audit intent."""

    def __init__(self, executor: WindowsAuditExecutor, request: ProcessAccessRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="process_access",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> bool:
        """Emit one process-access audit event when lifecycle validation allows it."""

        return self._executor._execute_process_access_bundle(self._request)
