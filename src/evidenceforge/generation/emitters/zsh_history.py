# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded zsh extended incremental history using the shared durable journal."""

from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter


class ZshHistoryEmitter(BashHistoryEmitter):
    """Project explicit interactive command submissions, not arbitrary process creation.

    The initial profile models EXTENDED_HISTORY with incremental append: elapsed
    time is zero because the entry is persisted before command completion. Multiline
    and binary/metafied history records and history mutation are not implemented.
    """

    _supported_types: set[str] = {"zsh_command"}
    _history_directory = "zsh_history"
    _history_suffix = ".zsh_history"

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Accept only the canonical Mac interactive zsh command family."""
        return (
            event.event_type in self._supported_types
            and event.src_host is not None
            and event.src_host.os_category == "macos"
        )

    def _render_history_entry(self, event_data: dict[str, Any]) -> str:
        """Validate before journal admission and preserve command whitespace."""
        command = event_data.get("command")
        if (
            not isinstance(command, str)
            or not command
            or any(character in command for character in ("\n", "\r", "\x00"))
        ):
            raise ValueError("zsh_history requires one nonempty, single-line command")
        if command.endswith("\\"):
            raise ValueError("zsh_history multiline continuations are not implemented")
        if any(ord(character) >= 128 for character in command):
            raise ValueError("zsh_history metafied non-ASCII commands are not implemented")
        return self._template.render(timestamp=event_data.get("timestamp"), command=command).rstrip(
            "\n"
        )
