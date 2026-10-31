# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free exec file actions, committed by the existing process State cohort."""

from typing import Literal

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid


def plan_spawn_descriptors(
    process: ProcessIdentity,
    intent: MacosSpawnIO,
    *,
    inherited: MacosDescriptorTable | None,
    terminal: Literal["absent"] | MacosTerminalObservation | None,
    pipe_counter: tuple[int, int] | None,
) -> tuple[MacosDescriptorTable, tuple[int, int, int] | None]:
    """Plan one complete post-exec table and an optional exact pipe-counter transition.

    Only the final retained endpoints are asserted. The server's socket/file
    backing is selected synthetic state, with no invented native path or peer.
    """
    intent.__post_init__()
    at, host = process.execution_started_at, process.hostname
    if (
        inherited is None
        or inherited.hostname != host
        or inherited.observed_at > at
        or inherited.native_last_fd is None
        or process.job_control is None
    ):
        raise StateError(
            "Mac spawn file actions require complete inherited descriptors and membership"
        )
    is_server = intent.kind == "server_channels"
    if is_server:
        if terminal != "absent":
            raise StateError("Mac server channels require explicitly absent controlling terminal")
        bindings = [
            MacosDescriptorBinding(
                fd, "socket", stable_uuid("macos-server-socket", host, process.object_id, fd), False
            )
            for fd in (0, 1)
        ]
    else:
        if (
            type(terminal) is not MacosTerminalObservation
            or terminal.session != process.job_control.session
        ):
            raise StateError(
                "Mac terminal file actions require the exact live controlling terminal"
            )
        if intent.kind == "standard_only":
            bindings = [binding for binding in inherited.bindings if binding.fd <= 2]
            if tuple(binding.fd for binding in bindings) != (0, 1, 2) or any(
                binding.kind != "file" or binding.close_on_exec for binding in bindings
            ):
                raise StateError(
                    "Mac login shell requires three retained standard vnode descriptors"
                )
        else:
            object_id = stable_uuid(
                "macos-tty-open", process.object_id, terminal.metadata.canonical_json()
            )
            bindings = [MacosDescriptorBinding(fd, "file", object_id, False) for fd in (0, 1, 2)]
    allocation = None
    count = 2 if is_server else 1 if intent.kind == "login_pipes" else 0
    if count:
        first = intent.first_pipe_id
        assert first is not None
        if pipe_counter is not None and (
            type(pipe_counter) is not tuple
            or len(pipe_counter) != 2
            or any(type(value) is not int for value in pipe_counter)
        ):
            raise StateError("Mac spawn pipe allocation requires an exact retained counter")
        base, previous = pipe_counter if pipe_counter is not None else (first, first - 1)
        if base != first or not first - 1 <= previous < 2**64 - count:
            raise StateError("Mac spawn pipe namespace changed or is exhausted")
        for offset in range(count):
            native_id = previous + offset + 1
            object_id = stable_uuid("macos-native-pipe", host, native_id)
            fds = (2 + offset,) if is_server else (4, 5)
            bindings.extend(
                MacosDescriptorBinding(fd, "pipe", object_id, False, native_id) for fd in fds
            )
        allocation = first, previous, previous + count
    if is_server:
        bindings.append(
            MacosDescriptorBinding(
                4, "file", stable_uuid("macos-server-file", host, process.object_id), False
            )
        )
    return MacosDescriptorTable(
        host,
        at,
        tuple(sorted(bindings, key=lambda binding: binding.fd)),
        max(binding.fd for binding in bindings),
    ), allocation
