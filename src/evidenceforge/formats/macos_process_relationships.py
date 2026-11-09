# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded ES identity projection; this is not a complete native process record."""

from __future__ import annotations

from datetime import UTC
from typing import Literal

from pydantic import BaseModel, ConfigDict

from evidenceforge.events.macos_process_observation import MacosGUIExecResponsibilityObservation
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import (
    AuditTokenArray,
    ESAuditToken,
    ProcessStartTime,
    UInt32,
)


class ESProcessRelationshipFields(BaseModel):
    """Native identity fields derived only from one complete canonical observation.

    Executable/file/runtime/collector facts remain separate required owners. This
    projection admits no event family, supplies no missing native fields and does
    not read mutable State during delayed rendering.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    audit_token: ESAuditToken | AuditTokenArray
    parent_audit_token: ESAuditToken | AuditTokenArray
    responsible_audit_token: ESAuditToken | AuditTokenArray
    ppid: UInt32
    original_ppid: UInt32
    group_id: UInt32
    session_id: UInt32
    start_time: ProcessStartTime

    @classmethod
    def from_observation(
        cls,
        observation: ProcessRelationshipObservation,
        *,
        version: int,
        gui_responsibility: MacosGUIExecResponsibilityObservation | None = None,
        boot_parent_token: Literal["all_zero", "default_unattributed_kernel"] | None = None,
    ) -> ESProcessRelationshipFields:
        """Map known audit and POSIX identities using the versioned token layout."""
        if type(version) is not int or version not in {6, 9, 10, 11}:
            raise ValueError("ES process identity projection requires an admitted wire version")
        if type(observation) is not ProcessRelationshipObservation:
            raise ValueError("ES process identity projection requires exact relationship facts")
        parent = observation.parent.parent
        process = observation.parent.process
        parentage = process.parentage
        group = process.job_control
        no_parent_identity = (
            version == 11
            and parent is None
            and parentage is not None
            and parentage.original is None
            and parentage.current is None
            and process.pid == 1
            and process.parent_pid == 0
            and process.image == "/sbin/launchd"
            and process.principal == "root"
            and process.credentials is not None
            and process.credentials.is_unattributed_root
            and group is not None
            and group.pgid == group.session.sid == 1
        )
        if no_parent_identity and boot_parent_token is None:
            raise ValueError(
                "ES boot launchd snapshot requires a qualified no-parent audit-token policy"
            )
        no_parent = no_parent_identity and boot_parent_token in {
            "all_zero",
            "default_unattributed_kernel",
        }
        if (
            group is None
            or parentage is None
            or not no_parent
            and (parent is None or parentage.original is None)
        ):
            raise ValueError(
                "ES process identity projection requires known original/current parent and group"
            )
        if boot_parent_token is not None and not no_parent:
            raise ValueError("ES boot-parent policy cannot substitute for an ordinary parent")
        parent_token = (
            ESAuditToken(
                auid=0 if boot_parent_token == "all_zero" else 2**32 - 1,
                euid=0,
                egid=0,
                ruid=0,
                rgid=0,
                pid=0,
                asid=0,
                pidversion=0,
            )
            if no_parent
            else ESAuditToken.from_process_identity(parent)
        )
        tokens = (
            ESAuditToken.from_process_identity(process),
            parent_token,
            ESAuditToken.from_process_identity(observation.responsibility.responsible),
        )
        if gui_responsibility is not None:
            if type(gui_responsibility) is not MacosGUIExecResponsibilityObservation:
                raise ValueError("ES GUI responsibility requires its exact token observation")
            gui_responsibility.__post_init__()
            if (
                version != 11
                or gui_responsibility.before != process
                or gui_responsibility.after.execution_started_at != observation.parent.observed_at
                or observation.responsibility.reason != "absent"
            ):
                raise ValueError("ES GUI responsibility belongs to another execution or instant")
            credentials = gui_responsibility.credentials
            responsible = ESAuditToken(
                auid=credentials.audit_uid,
                euid=credentials.effective_uid,
                egid=credentials.effective_gid,
                ruid=credentials.real_uid,
                rgid=credentials.real_gid,
                pid=process.pid,
                asid=credentials.audit_session_id,
                pidversion=process.audit_pid_version,
            )
            tokens = (tokens[0], tokens[1], responsible)
        rendered: tuple[ESAuditToken | AuditTokenArray, ...]
        if version == 10:
            rendered = tuple(token.as_native_array() for token in tokens)
        else:
            rendered = tokens
        return cls(
            audit_token=rendered[0],
            parent_audit_token=rendered[1],
            responsible_audit_token=rendered[2],
            ppid=parentage.current_pid,
            original_ppid=parentage.original_pid,
            group_id=group.pgid,
            session_id=group.session.sid,
            start_time=process.started_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
