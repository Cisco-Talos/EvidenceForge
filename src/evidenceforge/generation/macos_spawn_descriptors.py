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
    is_ssh = intent.kind in {"ssh_inetd", "ssh_session", "ssh_auth"}
    if is_server or is_ssh:
        if terminal != "absent":
            raise StateError("Mac server channels require explicitly absent controlling terminal")
        if is_ssh:
            bindings = _ssh_bindings(process, intent, inherited)
        else:
            bindings = [
                MacosDescriptorBinding(
                    fd,
                    "socket",
                    stable_uuid("macos-server-socket", host, process.object_id, fd),
                    False,
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
    count = 2 if is_server else 1 if intent.kind in {"login_pipes", "ssh_auth"} else 0
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
            fds = (2 + offset,) if is_server else (4,) if intent.kind == "ssh_auth" else (4, 5)
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


def _ssh_bindings(
    process: ProcessIdentity, intent: MacosSpawnIO, inherited: MacosDescriptorTable
) -> list[MacosDescriptorBinding]:
    """Apply measured helper tables while preserving retained standard open objects.

    The inetd accepted socket backs both stdin and stdout. Subsequent workers
    retain those open objects; extra worker sockets/files are separate modeled
    handles. Native ES exports their descriptor kinds, not socket peer values.
    """
    standard = tuple(binding for binding in inherited.bindings if binding.fd <= 2)
    if tuple(binding.fd for binding in standard) != (0, 1, 2) or any(
        binding.close_on_exec for binding in standard
    ):
        raise StateError("Mac SSH helper requires three open inherited standard descriptors")
    if intent.kind == "ssh_inetd":
        if any(binding.kind != "file" for binding in standard):
            raise StateError("Mac inetd file actions require the launcher vnode standards")
        socket = stable_uuid("macos-ssh-accepted-socket", process.hostname, process.object_id)
        return [
            MacosDescriptorBinding(0, "socket", socket, False),
            MacosDescriptorBinding(1, "socket", socket, False),
            standard[2],
        ]
    if tuple(binding.kind for binding in standard) != ("socket", "socket", "file"):
        raise StateError("Mac SSH worker requires inherited network and stderr descriptors")
    bindings = list(standard)
    if intent.kind == "ssh_session":
        bindings.extend(
            (
                MacosDescriptorBinding(
                    3,
                    "file",
                    stable_uuid("macos-ssh-session-file", process.hostname, process.object_id),
                    False,
                ),
                MacosDescriptorBinding(
                    4,
                    "socket",
                    stable_uuid("macos-ssh-session-socket", process.hostname, process.object_id),
                    False,
                ),
            )
        )
    else:
        bindings.append(
            MacosDescriptorBinding(
                3,
                "socket",
                stable_uuid("macos-ssh-auth-socket", process.hostname, process.object_id),
                False,
            )
        )
    return bindings
