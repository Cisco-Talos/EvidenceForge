# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Checkpoint validation for bounded immutable process responsibility."""

from evidenceforge.events.responsibility import (
    ResponsibleProcessReference,
    validate_process_responsibility,
)
from evidenceforge.models.state import RunningProcess


def validate_restored_responsibility(
    processes: tuple[RunningProcess, ...], platforms: dict[str, str]
) -> None:
    """Reject conflicting retained lifetimes; preserve explicitly expired references."""
    retained = {process.ecar_object_id: process for process in processes}
    for process in processes:
        facts = process.responsibility
        validate_process_responsibility(
            facts,
            hostname=process.system,
            object_id=process.ecar_object_id,
            started_at=process.start_time,
        )
        if facts is not None and platforms.get(process.system) != "macos":
            raise ValueError("Process responsibility requires a Mac host")
        if any(prior.responsibility != facts for prior in process.prior_executions):
            raise ValueError("Responsibility cannot change across this profile's exec history")
        reference = facts.responsible if facts else None
        if reference is None:
            continue
        owner = retained.get(reference.object_id)
        if owner is not None and reference != ResponsibleProcessReference(
            owner.system, owner.ecar_object_id, owner.pid, owner.start_time
        ):
            raise ValueError("Responsibility disagrees with its retained exact lifetime")

    # Launch establishes a reference to an already-admitted lifetime. Since this
    # profile cannot reassign responsibility, a restored cycle has no legal
    # creation history, including when timestamp precision makes births equal.
    complete: set[str] = set()
    for object_id in retained:
        path: set[str] = set()
        cursor: str | None = object_id
        while cursor is not None and cursor in retained and cursor not in complete:
            if cursor in path:
                raise ValueError("Responsibility cannot contain cyclic lifetime ownership")
            path.add(cursor)
            facts = retained[cursor].responsibility
            cursor = facts.responsible.object_id if facts and facts.responsible else None
        complete.update(path)
