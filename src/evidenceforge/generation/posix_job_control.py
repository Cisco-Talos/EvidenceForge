# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded job-control reservation calculations used only by StateManager."""

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from typing import Literal

from evidenceforge.events.job_control import (
    PosixGroupIdentity,
    PosixJobControlChange,
    PosixJobControlReservation,
    PosixSessionIdentity,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import RunningProcess

type ReservationKey = tuple[Literal["group", "session"], str, int]
type ReservationRows = tuple[PosixJobControlReservation, ...]

# Runtime admission bounds, not operating-system limits. Closed intervals retire
# at the existing authoritative PID watermark instead of accumulating for a run.
MAX_OPEN_EPOCHS_PER_NUMBER = 128
MAX_MEMBERSHIP_CHANGES = 64


def reservation_key(identity: PosixSessionIdentity | PosixGroupIdentity) -> ReservationKey:
    """Return a host-local numeric key without confusing group and session IDs."""
    if type(identity) is PosixGroupIdentity:
        return ("group", identity.session.hostname, identity.pgid)
    return ("session", identity.hostname, identity.sid)


def membership_updates(
    reservations: Mapping[ReservationKey, ReservationRows],
    before: PosixGroupIdentity | None,
    after: PosixGroupIdentity | None,
    at: datetime,
) -> dict[ReservationKey, ReservationRows]:
    """Preflight one membership delta without mutating any state or allocator."""
    updates: dict[ReservationKey, ReservationRows] = {}
    old = (before, before.session if before else None)
    new = (after, after.session if after else None)
    for previous, following in zip(old, new, strict=True):
        if previous == following:
            continue
        for identity, delta in ((previous, -1), (following, 1)):
            if identity is None:
                continue
            key = reservation_key(identity)
            rows = updates.get(key, reservations.get(key, ()))
            active = rows[-1] if rows and rows[-1].ended_at is None else None
            if active is not None:
                if active.identity != identity or at < active.updated_at:
                    raise StateError(
                        "POSIX membership uses a stale lifetime or backdated transition"
                    )
                members = active.members + delta
                updates[key] = (
                    *rows[:-1],
                    replace(
                        active, members=members, updated_at=at, ended_at=at if not members else None
                    ),
                )
            elif delta < 0:
                raise StateError("POSIX membership leaves an inactive group or session")
            else:
                if at != identity.started_at:
                    raise StateError("POSIX membership cannot resurrect a retired group or session")
                if rows and (rows[-1].ended_at >= at or rows[-1].identity == identity):
                    raise StateError("POSIX numeric-ID reuse overlaps its previous lifetime")
                if len(rows) >= MAX_OPEN_EPOCHS_PER_NUMBER:
                    raise StateError("POSIX numeric-ID history exceeds its open-window budget")
                updates[key] = (*rows, PosixJobControlReservation(identity, 1, at))
    return updates


def numeric_id_reserved(
    reservations: Mapping[ReservationKey, ReservationRows],
    hostname: str,
    pid: int,
    start: datetime,
    end: datetime | None,
) -> bool:
    """Check only the two matching numeric buckets, including retained intervals."""
    return any(
        (end is None or row.identity.started_at <= end)
        and (row.ended_at is None or start <= row.ended_at)
        for kind in ("group", "session")
        for row in reservations.get((kind, hostname, pid), ())
    )


def validate_restored_job_control(
    reservations: dict[ReservationKey, ReservationRows],
    counts: dict[str, int],
    processes: tuple[RunningProcess, ...],
    platforms: dict[str, str],
    *,
    legacy: bool,
) -> None:
    """Cross-check restored immutable intervals against live process membership."""
    expected_counts: dict[str, int] = {}
    live: dict[PosixGroupIdentity | PosixSessionIdentity, int] = {}
    for process in processes:
        group = process.job_control
        history = process.job_control_history
        if type(history) is not tuple or len(history) > MAX_MEMBERSHIP_CHANGES:
            raise ValueError("Invalid POSIX membership history")
        if legacy and (
            group is not None or history or any(row.job_control for row in process.prior_executions)
        ):
            raise ValueError("Legacy state cannot carry new POSIX membership facts")
        if (group is not None or history) and platforms.get(process.system) not in {
            "macos",
            "linux",
        }:
            raise ValueError("POSIX membership requires a POSIX host")
        previous = history[0].before if history else group
        frontier = process.start_time
        for index, change in enumerate(history):
            if (
                type(change) is not PosixJobControlChange
                or change.before != previous
                or change.changed_at < frontier
                or (index > 0 and change.changed_at == frontier)
                or change.after.session.hostname != process.system
                or (process.end_time is not None and change.changed_at > process.end_time)
            ):
                raise ValueError("Invalid POSIX membership transition history")
            if change.operation in {"bootstrap", "setsid"} and (
                change.after.pgid != process.pid
                or change.after.leader_object_id != process.ecar_object_id
                or change.after.session.sid != process.pid
                or change.after.session.leader_object_id != process.ecar_object_id
                or change.after.started_at != change.changed_at
                or change.after.session.started_at != change.changed_at
                or (
                    change.operation == "bootstrap"
                    and (process.pid != 1 or change.changed_at != process.start_time)
                )
                or (change.before is not None and change.before.pgid == process.pid)
            ):
                raise ValueError("Invalid POSIX session creation history")
            if change.operation == "setpgid" and (
                change.before is None
                or change.before.session != change.after.session
                or change.before.session.sid == process.pid
            ):
                raise ValueError("Invalid POSIX group change history")
            previous, frontier = change.after, change.changed_at
        if not history and group is not None and group.started_at > process.start_time:
            raise ValueError("Inherited POSIX group cannot start after its member")
        if previous != group:
            raise ValueError("POSIX membership history disagrees with current group")
        if group is not None:
            if type(group) is not PosixGroupIdentity or group.session.hostname != process.system:
                raise ValueError("POSIX membership crosses host boundary")
            if process.end_time is None:
                for identity in (group, group.session):
                    live[identity] = live.get(identity, 0) + 1
    for key, rows in reservations.items():
        if (
            type(key) is not tuple
            or len(key) != 3
            or type(key[0]) is not str
            or type(key[1]) is not str
            or type(key[2]) is not int
            or type(rows) is not tuple
            or not rows
            or len(rows) > MAX_OPEN_EPOCHS_PER_NUMBER
        ):
            raise ValueError("Invalid POSIX reservation bucket")
        previous_end: datetime | None = None
        for index, row in enumerate(rows):
            if (
                type(row) is not PosixJobControlReservation
                or reservation_key(row.identity) != key
                or platforms.get(key[1]) not in {"macos", "linux"}
                or (index and (previous_end is None or previous_end >= row.identity.started_at))
                or (row.ended_at is None and index != len(rows) - 1)
                or row.members != live.pop(row.identity, 0)
            ):
                raise ValueError("POSIX reservation disagrees with lifetime or live members")
            previous_end = row.ended_at
        expected_counts[key[1]] = expected_counts.get(key[1], 0) + len(rows)
    if (
        live
        or counts != expected_counts
        or any(type(count) is not int for count in counts.values())
    ):
        raise ValueError("POSIX reservation counts disagree with current membership")
