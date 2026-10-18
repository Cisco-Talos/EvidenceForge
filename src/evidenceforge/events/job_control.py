# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable POSIX job-control lifetimes, separate from login and audit sessions."""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

type JobControlPid = Annotated[int, Field(strict=True, gt=0, lt=2**31)]


def _check_identity(hostname: str, leader: str, number: int, started_at: datetime) -> None:
    if (
        type(hostname) is not str
        or not hostname
        or type(leader) is not str
        or not leader
        or type(number) is not int
        or not 0 < number < 2**31
        or type(started_at) is not datetime
        or started_at.utcoffset() is None
    ):
        raise ValueError("POSIX job control requires exact host, leader, PID and aware start time")


@dataclass(frozen=True, slots=True)
class PosixSessionIdentity:
    """One session lifetime, which can outlive its creating process."""

    hostname: str
    sid: JobControlPid
    leader_object_id: str
    started_at: datetime

    def __post_init__(self) -> None:
        _check_identity(self.hostname, self.leader_object_id, self.sid, self.started_at)


@dataclass(frozen=True, slots=True)
class PosixGroupIdentity:
    """One process-group lifetime contained in exactly one POSIX session."""

    session: PosixSessionIdentity
    pgid: JobControlPid
    leader_object_id: str
    started_at: datetime

    def __post_init__(self) -> None:
        if type(self.session) is not PosixSessionIdentity:
            raise ValueError("POSIX group requires an exact session identity")
        _check_identity(self.session.hostname, self.leader_object_id, self.pgid, self.started_at)
        if self.started_at < self.session.started_at:
            raise ValueError("POSIX group cannot precede its session")


@dataclass(frozen=True, slots=True)
class PosixJobControlChange:
    """One membership transition; it does not create an execution epoch."""

    operation: Literal["bootstrap", "setsid", "setpgid"]
    before: PosixGroupIdentity | None
    after: PosixGroupIdentity
    changed_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.operation) is not str
            or self.operation not in {"bootstrap", "setsid", "setpgid"}
            or type(self.after) is not PosixGroupIdentity
            or (self.before is not None and type(self.before) is not PosixGroupIdentity)
            or type(self.changed_at) is not datetime
            or self.changed_at.utcoffset() is None
            or self.changed_at < self.after.started_at
            or (self.operation == "bootstrap") != (self.before is None)
            or self.before == self.after
        ):
            raise ValueError("POSIX membership change requires distinct, ordered exact snapshots")
        if self.before is not None and (
            self.before.session.hostname != self.after.session.hostname
            or self.changed_at < self.before.started_at
        ):
            raise ValueError("POSIX membership change cannot cross hosts or precede its group")


@dataclass(frozen=True, slots=True)
class PosixJobControlReservation:
    """Indexed live membership count or retained closed numeric-ID interval."""

    identity: PosixSessionIdentity | PosixGroupIdentity
    members: Annotated[int, Field(strict=True, ge=0)]
    updated_at: datetime
    ended_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            type(self.identity) not in {PosixSessionIdentity, PosixGroupIdentity}
            or type(self.members) is not int
            or self.members < 0
            or type(self.updated_at) is not datetime
            or self.updated_at.utcoffset() is None
            or self.updated_at < self.identity.started_at
            or (self.members == 0) != (self.ended_at is not None)
            or (self.ended_at is not None and self.ended_at != self.updated_at)
        ):
            raise ValueError("POSIX numeric reservation has inconsistent membership or lifetime")
