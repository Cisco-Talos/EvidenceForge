# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded ES identity projection; this is not a complete native process record."""

from __future__ import annotations

from datetime import UTC

from pydantic import BaseModel, ConfigDict

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
        cls, observation: ProcessRelationshipObservation, *, version: int
    ) -> ESProcessRelationshipFields:
        """Map known audit and POSIX identities using the versioned token layout."""
        if type(version) is not int or version not in {6, 9, 10}:
            raise ValueError("ES process identity projection requires an admitted wire version")
        if type(observation) is not ProcessRelationshipObservation:
            raise ValueError("ES process identity projection requires exact relationship facts")
        parent = observation.parent.parent
        process = observation.parent.process
        parentage = process.parentage
        group = process.job_control
        if parent is None or parentage is None or parentage.original is None or group is None:
            raise ValueError(
                "ES process identity projection requires known original/current parent and group"
            )
        tokens = tuple(
            ESAuditToken.from_process_identity(identity)
            for identity in (process, parent, observation.responsibility.responsible)
        )
        rendered: tuple[ESAuditToken | AuditTokenArray, ...]
        if version == 10:
            rendered = tuple(token.as_native_array() for token in tokens)
        else:
            rendered = tokens
        return cls(
            audit_token=rendered[0],
            parent_audit_token=rendered[1],
            responsible_audit_token=rendered[2],
            ppid=parent.pid,
            original_ppid=parentage.original.pid,
            group_id=group.pgid,
            session_id=group.session.sid,
            start_time=process.started_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
