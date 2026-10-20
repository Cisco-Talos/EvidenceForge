# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Internal host output adapter for authenticated Endpoint Security records.

This adapter participates in the normal emitter barrier, close and incremental
spool contracts. It does not select a build profile or subscribe to canonical
events. Source admission must supply a format definition and an exact native
publication through the dispatcher before this adapter can produce evidence.
"""

from pathlib import Path
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import HostContext
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.macos_es_native_sink import _native_sort_key, validate_es_native_sink
from evidenceforge.models.exceptions import StateError


class MacosEndpointSecurityEmitter(HostMultiplexEmitter):
    """Own exact native sinks through the shared host-output lifecycle.

    Native records are already rendered and authenticated by the collection
    owner. They bypass the ordinary event queue and enter the dispatcher's
    existing exact journal directly. An aggregate process-create event cannot
    authorize a native fork, exec or exit observation.
    """

    _log_filename = "macos_endpoint_security.ndjson"
    _flat_filename = "macos_endpoint_security.ndjson"
    _sort_flat_file = True
    _sort_key = staticmethod(_native_sort_key)
    _defer_sorted_flush_until_close = True
    _external_sorting = True
    _supported_types: set[str] = set()

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10_000,
        threaded: bool = False,
    ) -> None:
        if (
            format_def.name != "macos_endpoint_security"
            or format_def.output.header_template
            or format_def.output.footer_template
        ):
            raise StateError("Native ES output requires its explicit format definition")
        super().__init__(format_def, output_path, buffer_size, threaded)
        # Intermediate barriers seal immutable runs; only successful terminal
        # close exports the destination, including in non-checkpoint runs.
        self.enable_deferred_sorted_publication()

    def native_sink(self, host: HostContext) -> ExternalSortedLineWriter:
        """Return the modeled Mac host's exact writer without rendering a row."""
        if type(host) is not HostContext or host.os_category != "macos" or not host.hostname:
            raise StateError("Native ES output requires an explicit modeled Mac host")
        self._begin_queue_admission()
        try:
            writer = self._get_writer(host.fqdn or host.hostname)._sorted_writer
            if writer is None:
                raise StateError("Native ES output lost its external sorted writer")
            validate_es_native_sink(writer)
            return writer
        finally:
            self._finish_queue_admission()

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        path = super()._writer_path_for_key(safe_writer_key)
        if path.exists():
            raise FileExistsError("Native ES output requires a fresh output path")
        return path

    def enable_incremental_checkpointing(self) -> None:
        """Require recovery mode before any route can allocate its writer."""
        if self._writers and not self._incremental_checkpointing:
            raise StateError("Native ES checkpointing must precede sink allocation")
        super().enable_incremental_checkpointing()

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Leave native admission to the exact canonical collection owner."""
        return False

    def emit(self, event: CanonicalOccurrence) -> None:
        """Reject ordinary dispatch, including aggregate process events."""
        raise StateError("Native ES output requires authenticated exact native publication")

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Reject dictionaries that bypass native preparation and its proof."""
        raise StateError("Native ES output requires authenticated exact native publication")

    def emit_to_host(self, rendered: str, host_fqdn: str = "") -> None:
        """Reject unbound rendered text rather than claiming native evidence."""
        raise StateError("Native ES output requires authenticated exact native publication")

    def _render_event(self, event_data: dict[str, Any]) -> str:
        raise StateError("Native ES output requires authenticated exact native publication")

    @property
    def event_count(self) -> int:
        """Read committed native row counts from their exact final writers."""
        return sum(
            writer._sorted_writer.event_count
            for writer in self._writers.values()
            if writer._sorted_writer is not None
        )

    @event_count.setter
    def event_count(self, value: int) -> None:
        # LogEmitter construction initializes a scalar; the journal owns this
        # adapter's count, just as route writers own HostMultiplexEmitter's.
        pass
