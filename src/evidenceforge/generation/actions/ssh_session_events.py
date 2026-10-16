# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SSH session observations shared by platform-specific lifecycle owners."""

from datetime import datetime

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext, SyslogContext
from evidenceforge.events.identity import EventIdentityPlan, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.models.exceptions import EventContractError


def ssh_logout_occurrence(
    *,
    host: HostContext,
    session: SessionIdentity,
    timestamp: datetime,
    source_ip: str,
    source_port: int,
    linux_receiver_pid: int | None = None,
) -> OccurrenceBuilder:
    """Project one session close without inventing unsupported native Mac messages.

    The enclosing SSH owner must bind this occurrence to the exact session close
    plan. The Linux observation retains its established PAM text. A Mac close
    supplies canonical/eCAR evidence only; it does not imply Unified Log coverage.
    """
    if (
        type(session) is not SessionIdentity
        or type(host) is not HostContext
        or host.hostname != session.hostname
        or host.os_category not in {"linux", "macos"}
        or session.session_kind != "ssh"
        or type(timestamp) is not datetime
        or timestamp.utcoffset() is None
        or timestamp <= session.started_at
        or type(source_ip) is not str
        or source_ip in {"", "-"}
        or type(source_port) is not int
        or not 1 <= source_port <= 65_535
    ):
        raise EventContractError(
            "SSH logout requires its exact session, host, time and source tuple"
        )
    syslog = None
    if host.os_category == "linux":
        if type(linux_receiver_pid) is not int or linux_receiver_pid <= 0:
            raise EventContractError("Linux SSH logout requires its native receiver PID")
        syslog = SyslogContext(
            app_name="sshd",
            pid=linux_receiver_pid,
            facility=10,
            severity=6,
            message=f"pam_unix(sshd:session): session closed for user {session.principal}",
        )
    elif linux_receiver_pid is not None:
        raise EventContractError("Mac SSH logout cannot include Linux PAM observation facts")
    return OccurrenceBuilder(
        timestamp=timestamp,
        event_type="logoff",
        dst_host=host,
        auth=AuthContext(
            username=session.principal,
            source_ip=source_ip,
            source_port=source_port,
            logon_id=session.logon_id,
            session_id=session.session_id,
            logon_type=10,
        ),
        syslog=syslog,
        identity_plan=EventIdentityPlan(subject=session, session=session),
        lifecycle=ActionLifecycleContext(
            group_id=session.lifecycle_group_id,
            canonical_start=session.started_at,
            phase="closure",
            parent_group_id=session.parent_lifecycle_group_id or None,
        ),
    )
