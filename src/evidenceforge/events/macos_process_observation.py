# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit event-time Mac collection facts that cannot be inferred from an image."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from evidenceforge.events.es_collector import ESCollectorState
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_terminal import MacosTerminalObservation


@dataclass(frozen=True, slots=True)
class MacosProcessCollectionObservation:
    """Known collection facts for one execution at one canonical instant.

    Terminal state is known absence or an exact session-owned device observation.
    Missing terminal/client knowledge cannot construct a snapshot. Producers
    must establish these facts; this value does not infer them from ancestry,
    installation, registry absence, or the generator host.
    """

    process: ProcessIdentity
    observed_at: datetime
    is_es_client: bool
    terminal: Literal["absent"] | MacosTerminalObservation

    def __post_init__(self) -> None:
        if (
            type(self.process) is not ProcessIdentity
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.observed_at < self.process.execution_started_at
            or type(self.is_es_client) is not bool
            or not (
                (type(self.terminal) is str and self.terminal == "absent")
                or type(self.terminal) is MacosTerminalObservation
            )
        ):
            raise ValueError(
                "Mac collection observation requires exact timed client/terminal facts"
            )
        if type(self.terminal) is MacosTerminalObservation:
            self.terminal.__post_init__()
            if (
                self.process.job_control is None
                or self.process.job_control.session != self.terminal.session
                or self.observed_at != self.terminal.observed_at
            ):
                raise ValueError("Mac terminal observation belongs to another session or instant")

    @classmethod
    def from_attached_collector(
        cls,
        process: ProcessIdentity,
        connection: ESCollectorState,
        *,
        observed_at: datetime,
        terminal: Literal["absent"] | MacosTerminalObservation,
    ) -> "MacosProcessCollectionObservation":
        """Project positive attachment from an exact explicitly established connection.

        This is not a negative-membership query. A caller must separately supply
        known terminal facts; connection ownership cannot establish a terminal.
        """
        if type(connection) is not ESCollectorState or type(process) is not ProcessIdentity:
            raise ValueError("Collection observation requires an exact connection and process")
        connection = ESCollectorState.model_validate_json(connection.model_dump_json())
        owner = connection.process
        if (
            owner is None
            or connection.hostname != process.hostname
            or owner.object_id != process.object_id
            or owner.pid != process.pid
            or owner.started_at != process.started_at
            or owner.execution_ordinal != process.execution_ordinal
            or owner.execution_started_at != process.execution_started_at
            or type(observed_at) is not datetime
            or observed_at.utcoffset() is None
            or observed_at < connection.opened_at
            or (connection.closed_at is not None and observed_at >= connection.closed_at)
        ):
            raise ValueError("Collection observation requires the attached execution and interval")
        return cls(process, observed_at, True, terminal)
