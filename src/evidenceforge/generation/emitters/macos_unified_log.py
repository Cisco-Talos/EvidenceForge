# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded experimental native Unified Log export using canonical writer facts."""

import json
from datetime import UTC
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.formats.macos_unified_log import project_unified_log_observation
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


def _native_sort_key(line: str) -> tuple[str, int, int, int, str]:
    record = json.loads(line)
    return (
        record["timestamp"],
        record["machTimestamp"],
        record["processID"],
        record["threadID"],
        line,
    )


class MacosUnifiedLogEmitter(HostMultiplexEmitter):
    """Render only workspace method entry, as a UTC NDJSON export.

    This is not a login success, complete GUI lifecycle or native archive. The
    standard host writer owns threading, sorting, publication and checkpoints.
    """

    _log_filename = "macos_unified_log.ndjson"
    _flat_filename = "macos_unified_log.ndjson"
    _sort_flat_file = True
    _sort_key = staticmethod(_native_sort_key)
    _defer_sorted_flush_until_close = True
    _external_sorting = True
    supports_exact_projection_publication = True
    _supported_types: set[str] = {"macos_workspace_request"}

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Require the supported stage and an available native writer snapshot."""
        return (
            event.event_type in self._supported_types
            and event.src_host is not None
            and event.src_host.os_category == "macos"
            and event.macos_workspace is not None
            and event.macos_workspace.native is not None
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Project supplied identities and the already planned source time."""
        if not self.can_handle(event):
            raise ValueError(
                "Unified Log emitter requires a supported native workspace observation"
            )
        request = event.macos_workspace
        host = event.src_host
        assert request is not None and request.native is not None and host is not None
        record = project_unified_log_observation(
            request.native, wall_time=event.timestamp.astimezone(UTC), timezone_name="UTC"
        )
        self.emit_event(
            {"native_json": record.to_ndjson(), "_host_fqdn": host.fqdn or host.hostname}
        )

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return event_data["native_json"]
