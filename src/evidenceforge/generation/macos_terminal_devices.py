# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free modeled terminal plans, committed by canonical State owners."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal

from evidenceforge.config.schemas import MacosTerminalDeviceProfile
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.events.job_control import PosixSessionIdentity
from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
from evidenceforge.events.macos_file import MacosFileTime, MacosTerminalMetadata
from evidenceforge.events.macos_terminal import MacosTerminalSession
from evidenceforge.generation.posix_job_control import (
    ReservationKey,
    ReservationRows,
    reservation_key,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import RunningProcess
from evidenceforge.utils.rng import stable_uuid


def plan_macos_terminal(
    identity: ProcessIdentity,
    intent: Literal["absent"] | MacosTerminalDeviceProfile | None,
    *,
    ordinal: int,
    occupied: tuple[int, ...],
) -> MacosTerminalSession | None:
    """Allocate only in a newly created explicit session; no State is changed."""
    if intent is None:
        return None
    session = identity.job_control.session if identity.job_control is not None else None
    if (
        session is None
        or session.leader_object_id != identity.object_id
        or session.started_at != identity.started_at
    ):
        raise StateError("Mac terminal intent requires its exact new session leader")
    if type(intent) is str and intent == "absent":
        return MacosTerminalSession(session, 0)
    if type(intent) is not MacosTerminalDeviceProfile:
        raise StateError("Mac terminal intent requires exact modeled device policy or absence")
    profile = MacosTerminalDeviceProfile.model_validate_json(intent.model_dump_json())
    credentials = identity.credentials
    if type(credentials) is not PosixProcessCredentials:
        raise StateError("Mac terminal allocation requires known local credentials")
    slot = next((index for index in range(profile.max_devices) if index not in occupied), None)
    if slot is None or not 0 < ordinal < 2**63 - profile.first_inode:
        raise StateError("Mac terminal allocation exceeds its retained device/inode budget")
    delta = session.started_at - datetime(1970, 1, 1, tzinfo=UTC)
    born = MacosFileTime(
        seconds=delta.days * 86400 + delta.seconds, nanoseconds=delta.microseconds * 1000
    )
    inode = profile.first_inode + ordinal
    metadata = MacosTerminalMetadata(
        volume_id=profile.volume_id,
        file_object_id=f"{session.hostname}:{profile.volume_id}:{inode}",
        device=profile.device,
        inode=inode,
        mode=0o020000 | profile.permissions,
        link_count=1,
        uid=credentials.effective_uid,
        gid=credentials.effective_gid,
        special_device=profile.special_device_base + slot,
        accessed=born,
        modified=born,
        changed=born,
        born=born,
        size_bytes=0,
        allocated_blocks=0,
        preferred_block_size=profile.preferred_block_size,
        flags=0,
        generation=0,
    )
    return MacosTerminalSession(
        session, ordinal, slot, f"/dev/ttys{slot:03d}", metadata.canonical_json()
    )


def validate_terminal_state(
    sessions: dict[PosixSessionIdentity, MacosTerminalSession],
    slots: dict[str, tuple[tuple[int, PosixSessionIdentity], ...]],
    ordinals: dict[str, int],
    reservations: Mapping[ReservationKey, ReservationRows],
    platforms: dict[str, str],
) -> None:
    """Validate retained device ownership and reverse indexes before checkpoint adoption."""
    expected: dict[str, list[tuple[int, PosixSessionIdentity]]] = {}
    objects: set[tuple[str, int, int]] = set()
    devices: set[tuple[str, int]] = set()
    used_ordinals: set[tuple[str, int]] = set()
    for session, terminal in sessions.items():
        if (
            type(session) is not PosixSessionIdentity
            or type(terminal) is not MacosTerminalSession
            or terminal.session != session
            or platforms.get(session.hostname) != "macos"
            or not any(
                row.identity == session for row in reservations.get(reservation_key(session), ())
            )
        ):
            raise ValueError("Mac terminal has no exact retained Mac session")
        terminal.__post_init__()
        if not terminal.ordinal:
            continue
        host = session.hostname
        metadata = terminal.observe(session.started_at).metadata
        object_key = host, metadata.device, metadata.inode
        device_key = host, metadata.special_device
        ordinal_key = host, terminal.ordinal
        if (
            object_key in objects
            or device_key in devices
            or ordinal_key in used_ordinals
            or terminal.ordinal > ordinals.get(host, 0)
        ):
            raise ValueError("Mac terminal object, device or allocation ordinal is duplicated")
        objects.add(object_key)
        devices.add(device_key)
        used_ordinals.add(ordinal_key)
        expected.setdefault(host, []).append((terminal.slot, session))
    if {host: tuple(sorted(rows)) for host, rows in expected.items()} != slots:
        raise ValueError("Mac terminal slot index disagrees with session ownership")
    if any(
        type(host) is not str
        or type(value) is not int
        or not 0 < value < 2**63
        or platforms.get(host) != "macos"
        for host, value in ordinals.items()
    ):
        raise ValueError("Mac terminal allocation counter is invalid")


def plan_macos_standard_io(
    identity: ProcessIdentity,
    intent: Literal["terminal", "null", "inherit"] | None,
    *,
    terminal: MacosTerminalSession | None,
    parent: MacosDescriptorTable | None,
) -> MacosDescriptorTable | None:
    """Create explicit stdio opens/duplication or inherit a known complete table."""
    if intent is None:
        return None
    if intent == "inherit":
        # Unknown inheritance remains unknown; no empty table is fabricated.
        return parent.after_exec(identity.started_at) if parent is not None else None
    if intent not in {"terminal", "null"}:
        raise StateError("Mac standard I/O requires an explicit supported launch intent")
    if intent == "terminal" and (terminal is None or not terminal.ordinal):
        raise StateError("Terminal standard I/O requires its exact allocated session device")
    if intent == "terminal":
        object_id = stable_uuid("macos-tty-open", identity.object_id, terminal.metadata_json)
        bindings = tuple(MacosDescriptorBinding(fd, "file", object_id, False) for fd in range(3))
    else:
        bindings = tuple(
            MacosDescriptorBinding(
                fd, "file", stable_uuid("macos-null-open", identity.object_id, fd), False
            )
            for fd in range(3)
        )
    return MacosDescriptorTable(identity.hostname, identity.started_at, bindings, 2)


def validate_native_pipe_state(
    counters: dict[str, tuple[int, int]],
    processes: tuple[RunningProcess, ...],
    platforms: dict[str, str],
) -> None:
    """Check native pipe allocation/share identities once before checkpoint adoption."""
    for host, value in counters.items():
        if (
            type(host) is not str
            or platforms.get(host) != "macos"
            or type(value) is not tuple
            or len(value) != 2
            or any(type(item) is not int for item in value)
            or not 0 < value[0] <= value[1] < 2**64
        ):
            raise ValueError("Mac native pipe counter is invalid")
    ids: dict[tuple[str, int], str] = {}
    objects: dict[tuple[str, str], int] = {}
    for process in processes:
        for table in process.descriptor_history:
            for binding in table.bindings:
                if binding.native_pipe_id is None:
                    continue
                native_id = binding.native_pipe_id
                counter = counters.get(process.system)
                if (
                    counter is None
                    or not counter[0] <= native_id <= counter[1]
                    or ids.setdefault((process.system, native_id), binding.object_id)
                    != binding.object_id
                    or objects.setdefault((process.system, binding.object_id), native_id)
                    != native_id
                ):
                    raise ValueError("Mac native pipe identity disagrees with its allocation owner")
