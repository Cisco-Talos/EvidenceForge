# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit descriptor file actions for qualified terminal and SSH exec boundaries."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class MacosSpawnIO:
    """Selected file actions, independent of the executable's display name.

    The startup owner selects a measured layout. State allocates its synthetic
    pipe identities within the exec transaction; renderers do not allocate FDs.
    """

    kind: Literal[
        "login_standard",
        "login_pipes",
        "server_channels",
        "standard_only",
        "ssh_inetd",
        "ssh_session",
        "ssh_auth",
        "ssh_launcher",
        "ssh_shell",
    ]
    first_pipe_id: int | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in {
            "login_standard",
            "login_pipes",
            "server_channels",
            "standard_only",
            "ssh_inetd",
            "ssh_session",
            "ssh_auth",
            "ssh_launcher",
            "ssh_shell",
        }:
            raise ValueError("Mac spawn I/O requires a supported explicit file-action layout")
        if self.kind in {"login_pipes", "server_channels", "ssh_auth"}:
            if type(self.first_pipe_id) is not int or not 0 < self.first_pipe_id < 2**63:
                raise ValueError("Mac spawn pipes require their host-local native ID policy")
        elif self.first_pipe_id is not None:
            raise ValueError("Mac spawn layout without pipes cannot reserve native pipe IDs")
