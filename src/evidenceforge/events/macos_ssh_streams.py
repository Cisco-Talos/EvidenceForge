# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SSH-channel stream ownership, separate from any helper's complete FD table."""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable


@dataclass(frozen=True, slots=True)
class MacosSshCommandStreams:
    """Reserved no-PTY streams for a bounded external-command exec contract.

    This is not a shell/sshd descriptor table or a pipe-open syscall claim.
    The channel owns three distinct pipe objects; commands consume their known
    standard-stream bindings after successful exec. Other descriptors must have
    been closed by that explicit command-launch contract.
    """

    hostname: str
    session_object_id: str
    available_at: datetime
    bindings: tuple[MacosDescriptorBinding, ...]

    def __post_init__(self) -> None:
        if (
            type(self.hostname) is not str
            or not self.hostname.strip()
            or "\0" in self.hostname
            or type(self.session_object_id) is not str
            or not self.session_object_id.strip()
            or "\0" in self.session_object_id
            or type(self.available_at) is not datetime
            or self.available_at.utcoffset() is None
            or type(self.bindings) is not tuple
            or len(self.bindings) != 3
            or any(type(item) is not MacosDescriptorBinding for item in self.bindings)
        ):
            raise ValueError("SSH command streams require an exact host/session and three pipes")
        for item in self.bindings:
            item.__post_init__()
        if (
            tuple(item.fd for item in self.bindings) != (0, 1, 2)
            or any(item.kind != "pipe" or item.close_on_exec for item in self.bindings)
            or any(item.native_pipe_id is None for item in self.bindings)
            or len({item.object_id for item in self.bindings}) != 3
            or len({item.native_pipe_id for item in self.bindings}) != 3
        ):
            raise ValueError("SSH command standard streams require three distinct retained pipes")

    def after_command_exec(self, at: datetime) -> MacosDescriptorTable:
        """Observe the explicit external-command boundary, never a helper inventory."""
        if type(at) is not datetime or at.utcoffset() is None or at < self.available_at:
            raise ValueError("SSH command descriptors cannot precede channel readiness")
        return MacosDescriptorTable(self.hostname, at, self.bindings, 2)
