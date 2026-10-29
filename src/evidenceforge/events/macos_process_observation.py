# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit event-time Mac collection facts that cannot be inferred from an image."""

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Literal

from evidenceforge.events.es_collector import ESCollectorState
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.events.macos_terminal import MacosTerminalObservation


@dataclass(frozen=True, slots=True)
class MacosGUIExecResponsibilityObservation:
    """Bounded v11 launcher token sampling, separate from process credentials.

    The reviewed Finder preimage's responsibility token retains its audit origin,
    PID and PID version but has zero POSIX credential words. This observation
    describes that export only; it grants no exec authority and makes no claim
    about when or why those words were sampled. Native preparation must first
    authenticate the exact GUI transition in State.
    """

    before: ProcessIdentity
    after: ProcessIdentity
    credentials: PosixProcessCredentials

    def __post_init__(self) -> None:
        before, after = self.before, self.after
        if type(before) is not ProcessIdentity or type(after) is not ProcessIdentity:
            raise ValueError("GUI responsibility sampling requires exact execution identities")
        old, new = before.credentials, after.credentials
        if (
            before.image != "/usr/libexec/xpcproxy"
            or ".app/Contents/MacOS/" not in after.image
            or (before.hostname, before.object_id, before.pid, before.started_at)
            != (after.hostname, after.object_id, after.pid, after.started_at)
            or after.execution_ordinal != before.execution_ordinal + 1
            or before.execution_started_at >= after.execution_started_at
            or before.audit_pid_version is None
            or after.audit_pid_version is None
            or before.audit_pid_version == after.audit_pid_version
            or before.parent_pid != 1
            or before.parentage != after.parentage
            or before.job_control is None
            or after.job_control is None
            or before.job_control.session != after.job_control.session
            or before.job_control.session.sid != 1
            or before.job_control.pgid != 1
            or after.job_control.pgid != after.pid
            or old is None
            or new is None
            or old.audit_uid != 2**32 - 1
            or old.audit_session_id in {None, 0}
            or new.audit_uid != new.real_uid
            or new.audit_session_id is None
            or old.audit_session_id == new.audit_session_id
            or replace(old, audit_uid=new.audit_uid, audit_session_id=new.audit_session_id) != new
            or before.responsibility is None
            or before.responsibility.responsible is not None
            or after.responsibility is None
            or after.responsibility.responsible is not None
            or type(self.credentials) is not PosixProcessCredentials
            or self.credentials
            != replace(old, real_uid=0, effective_uid=0, real_gid=0, effective_gid=0)
        ):
            raise ValueError("GUI responsibility sampling requires the reviewed launcher boundary")

    @classmethod
    def from_transition(
        cls, before: ProcessIdentity, after: ProcessIdentity
    ) -> "MacosGUIExecResponsibilityObservation":
        """Freeze the observed token words without changing either process snapshot."""
        if type(before) is not ProcessIdentity or before.credentials is None:
            raise ValueError("GUI responsibility sampling requires known launcher credentials")
        return cls(
            before,
            after,
            replace(before.credentials, real_uid=0, effective_uid=0, real_gid=0, effective_gid=0),
        )


@dataclass(frozen=True, slots=True)
class MacosProcessCollectionObservation:
    """Known collection facts for one execution at one canonical instant.

    Terminal state is known absence or an exact session-owned device observation.
    Missing terminal/client knowledge cannot construct a snapshot. Producers
    must establish these facts; this value does not infer them from ancestry,
    installation, registry absence, or the generator host.
    """

    process: ProcessIdentity
    observed_at: datetime
    is_es_client: bool
    terminal: Literal["absent"] | MacosTerminalObservation

    def __post_init__(self) -> None:
        if (
            type(self.process) is not ProcessIdentity
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.observed_at < self.process.execution_started_at
            or type(self.is_es_client) is not bool
            or not (
                (type(self.terminal) is str and self.terminal == "absent")
                or type(self.terminal) is MacosTerminalObservation
            )
        ):
            raise ValueError(
                "Mac collection observation requires exact timed client/terminal facts"
            )
        if type(self.terminal) is MacosTerminalObservation:
            self.terminal.__post_init__()
            if (
                self.process.job_control is None
                or self.process.job_control.session != self.terminal.session
                or self.observed_at != self.terminal.observed_at
            ):
                raise ValueError("Mac terminal observation belongs to another session or instant")

    @classmethod
    def from_attached_collector(
        cls,
        process: ProcessIdentity,
        connection: ESCollectorState,
        *,
        observed_at: datetime,
        terminal: Literal["absent"] | MacosTerminalObservation,
    ) -> "MacosProcessCollectionObservation":
        """Project positive attachment from an exact explicitly established connection.

        This is not a negative-membership query. A caller must separately supply
        known terminal facts; connection ownership cannot establish a terminal.
        """
        if type(connection) is not ESCollectorState or type(process) is not ProcessIdentity:
            raise ValueError("Collection observation requires an exact connection and process")
        connection = ESCollectorState.model_validate_json(connection.model_dump_json())
        owner = connection.process
        if (
            owner is None
            or connection.hostname != process.hostname
            or owner.object_id != process.object_id
            or owner.pid != process.pid
            or owner.started_at != process.started_at
            or owner.execution_ordinal != process.execution_ordinal
            or owner.execution_started_at != process.execution_started_at
            or type(observed_at) is not datetime
            or observed_at.utcoffset() is None
            or observed_at < connection.opened_at
            or (connection.closed_at is not None and observed_at >= connection.closed_at)
        ):
            raise ValueError("Collection observation requires the attached execution and interval")
        return cls(process, observed_at, True, terminal)
