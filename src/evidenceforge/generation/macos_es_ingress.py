# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-owned immutable ES occurrence ingress, sequenced after canonical work.

Canonical producers need not execute in simulated-time order. This private spool
is committed with each action's exact source journal. It contains message facts,
not delivered ES records: sequence fields are deliberately absent until replay.
The ordered collector API remains the sole owner of final sequence allocation.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.es_collector import ESCollectorRegistry, ESCollectorState
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.formats.macos_endpoint_security import EndpointSecurityRecord
from evidenceforge.generation.emitters.base import ExactPublicationAuthority, ExactPublicationBatch
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.events.dispatcher import EventDispatcher

_MAX_INGRESS_BYTES = 2 * 1024 * 1024
_PHASE_ORDER = {11: 0, 9: 1, 15: 2}


class ESProcessIngressRow(BaseModel):
    """One authenticated canonical occurrence awaiting chronological delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: HostContext
    initial: ESCollectorState
    occurrence_id: str = Field(min_length=1, max_length=256)
    event_type: Literal[9, 11, 15]
    observed_at: AwareDatetime
    status: Literal["visible", "delayed", "dropped", "filtered", "out_of_window"]
    delay: timedelta
    native_body: str | None = Field(default=None, max_length=1024 * 1024)

    @model_validator(mode="after")
    def coherent(self) -> ESProcessIngressRow:
        """Keep native facts separate from late-bound delivery counters."""
        if (
            self.host.os_category != "macos"
            or self.host.hostname != self.initial.hostname
            or self.initial.process is None
            or self.initial.source_profile is None
            or self.initial.next_delivery != 0
            or self.initial.last_delivery_at != self.initial.opened_at
            or self.initial.closed_at is not None
            or self.observed_at < self.initial.opened_at
            or self.delay < timedelta(0)
        ):
            raise ValueError("ES ingress requires an exact initial source epoch and Mac host")
        if self.status in {"visible", "delayed"} and self.native_body is None:
            raise ValueError("Visible ES ingress requires complete native message facts")
        if self.native_body is not None:
            payload = json.loads(self.native_body)
            if type(payload) is not dict or {"seq_num", "global_seq_num"} & payload.keys():
                raise ValueError("ES ingress cannot contain assigned delivery sequences")
            record = EndpointSecurityRecord.model_validate_json(
                json.dumps(payload | {"seq_num": 0, "global_seq_num": 0})
            )
            if (
                record.event_type != self.event_type
                or datetime.fromisoformat(record.time) != self.observed_at
            ):
                raise ValueError("ES ingress message must preserve its occurrence family and time")
        return self

    def encode(self) -> str:
        """Serialize a private ingress row, never an exported native record."""
        value = self.model_dump_json() + "\n"
        if len(value.encode()) > _MAX_INGRESS_BYTES:
            raise StateError("ES occurrence ingress exceeds its bounded row budget")
        return value


def _ingress_sort_key(line: str) -> tuple[str, int, str, int, str]:
    value = json.loads(line)
    return (
        value["initial"]["source_instance"],
        value["initial"]["generation"],
        datetime.fromisoformat(value["observed_at"])
        .astimezone(UTC)
        .isoformat(timespec="microseconds"),
        _PHASE_ORDER[value["event_type"]],
        value["occurrence_id"],
    )


class _IngressSpool(HostMultiplexEmitter):
    """Private exact-journal participant using the ordinary checkpoint spool."""

    _log_filename = "es-occurrences.snapshot"
    _flat_filename = "es-occurrences.snapshot"
    _sort_key = staticmethod(_ingress_sort_key)
    _sort_flat_file = True
    _defer_sorted_flush_until_close = True
    _external_sorting = True
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        raise StateError("ES ingress accepts only authenticated exact occurrence snapshots")


@dataclass(frozen=True, slots=True)
class PreparedESIngress:
    """Source-owned snapshot rows participating in one canonical exact journal."""

    owner: MacosESIngress
    sink: ExternalSortedLineWriter
    cohort_token: str
    rows: tuple[ESProcessIngressRow, ...]
    encoded: tuple[str, ...]
    _seal: object


class MacosESIngress:
    """Retain canonical message facts, then deliver them in source-time order.

    Ingress runs live on disk and reuse the existing incremental spool participant.
    Finalization streams sorted runs and owns one resumable exact native-output
    page at a time. No host inspection, timestamp clamp or native metadata inference
    occurs in this owner.
    """

    def __init__(self, root: Path) -> None:
        definition = FormatDefinition.model_validate(
            {
                "name": "macos_es_ingress",
                "description": "Private ES occurrence ingress",
                "category": "host",
                "fields": [],
                "output": {
                    "format": "json",
                    "file_extension": ".snapshot",
                    "template": "{{ native_json }}",
                },
            }
        )
        self.root = root
        self.spool = _IngressSpool(definition, root)
        self.enabled = True
        self.finalized = False
        self._seal = object()
        self._authority = ExactPublicationAuthority()
        self._pending: ExactPublicationBatch | None = None
        self._cursor = 0
        self._expected_restored_count: int | None = None

    def prepare(
        self, cohort_token: str, rows: tuple[ESProcessIngressRow, ...]
    ) -> PreparedESIngress:
        """Freeze bounded source facts before any canonical mutation."""
        if not self.enabled or self.finalized or not 1 <= len(rows) <= 256:
            raise StateError("ES occurrence ingress is unavailable or has an invalid batch")
        if len({row.initial.source_instance for row in rows}) != 1:
            raise StateError("ES ingress cohort requires one source instance")
        writer = self.spool._get_writer(rows[0].host.fqdn or rows[0].host.hostname)._sorted_writer
        if type(writer) is not ExternalSortedLineWriter:
            raise StateError("ES occurrence ingress lost its exact sorted journal")
        encoded = tuple(row.encode() for row in rows)
        if sum(len(line.encode()) for line in encoded) > 16 * 1024 * 1024:
            raise StateError("ES occurrence cohort exceeds its bounded journal budget")
        return PreparedESIngress(self, writer, cohort_token, rows, encoded, self._seal)

    def validate(self, prepared: PreparedESIngress, cohort_token: str) -> None:
        """Bind immutable snapshot rows to their original canonical publication."""
        if (
            type(prepared) is not PreparedESIngress
            or prepared.owner is not self
            or prepared._seal is not self._seal
            or prepared.cohort_token != cohort_token
            or prepared.encoded != tuple(row.encode() for row in prepared.rows)
            or not any(
                route._sorted_writer is prepared.sink for route in self.spool._writers.values()
            )
        ):
            raise StateError("ES ingress lost its exact canonical cohort and source journal")

    @property
    def event_count(self) -> int:
        """Return the number of admitted source snapshots."""
        return sum(route._sorted_writer.event_count for route in self.spool._writers.values())

    def cleanup(self) -> None:
        """Remove internal snapshots after successful native output finalization."""
        if self.finalized or not self.enabled:
            if self.root.exists():
                shutil.rmtree(self.root)

    def barrier_flush(self) -> None:
        """Seal immutable ingress runs without delivering future occurrences."""
        if self.enabled and not self.finalized:
            self.spool.barrier_flush()

    def assert_restored_count(self) -> None:
        """Reject a checkpoint that loses admitted source occurrences."""
        if self._expected_restored_count is not None:
            count = sum(route._sorted_writer.event_count for route in self.spool._writers.values())
            if count != self._expected_restored_count:
                raise StateError("ES ingress checkpoint occurrence count does not match its spool")
            self._expected_restored_count = None

    def finalize(self, dispatcher: EventDispatcher) -> None:
        """Sequence all committed occurrences through the strict collector API."""
        if not self.enabled or self.finalized:
            return
        self.assert_restored_count()
        # Close only this private spool. Native output remains owned by its normal
        # emitter and is exported only after all finalization stages succeed.
        self.spool.close()
        registry = ESCollectorRegistry()
        output = dispatcher.emitters.get("macos_endpoint_security")
        count = 0
        last_key: tuple[str, int, str] | None = None
        for route in sorted(self.spool._writers.values(), key=lambda item: str(item.output_path)):
            with route.output_path.open(encoding="utf-8") as stream:
                for line in iter(lambda: stream.readline(_MAX_INGRESS_BYTES + 1), ""):
                    if len(line.encode()) > _MAX_INGRESS_BYTES:
                        raise StateError("ES occurrence snapshot exceeds its modeled row bound")
                    row = ESProcessIngressRow.model_validate_json(line)
                    key = (row.initial.source_instance, row.initial.generation, row.occurrence_id)
                    if key == last_key:
                        raise StateError("ES occurrence ingress contains a duplicate delivery")
                    last_key = key
                    state = registry.connection(row.initial.source_instance)
                    if state is None or state.generation != row.initial.generation:
                        registry.open(row.initial)
                    elif (
                        state.source_profile != row.initial.source_profile
                        or state.process != row.initial.process
                    ):
                        raise StateError("ES occurrence ingress changed its owning source epoch")
                    state = registry.connection(row.initial.source_instance)
                    assert state is not None
                    delivery = registry.prepare(
                        source_instance=state.source_instance,
                        generation=state.generation,
                        delivery=state.next_delivery,
                        occurrence_id=row.occurrence_id,
                        event_type=row.event_type,
                        observed_at=row.observed_at,
                        decision=ObservationDecision(row.status, row.delay),
                    )
                    if count >= self._cursor:
                        if self._pending is None:
                            batch = self._authority.issue_batch()
                            if row.native_body is not None and row.status in {"visible", "delayed"}:
                                if output is None:
                                    raise StateError(
                                        "Visible ES ingress lost its native output owner"
                                    )
                                payload = json.loads(row.native_body)
                                record = EndpointSecurityRecord.model_validate_json(
                                    json.dumps(
                                        payload
                                        | {
                                            "seq_num": delivery.observation.seq_num,
                                            "global_seq_num": delivery.observation.global_seq_num,
                                        }
                                    )
                                )
                                sink = output.native_sink(row.host)
                                batch.reserve_participants((sink,))
                                batch.prepare(
                                    lambda sink=sink, record=record: sink.write(record.to_ndjson())
                                )
                            else:
                                batch.reserve_participants(())
                                batch.prepare(lambda: None)
                            self._pending = batch
                        if self._pending.state not in {"committed", "releasing", "released"}:
                            self._pending.commit()
                        self._pending.release_no_fail()
                        self._cursor = count + 1
                        self._pending = None
                    registry.commit(delivery)
                    count += 1
        expected = sum(route._sorted_writer.event_count for route in self.spool._writers.values())
        if count != expected or self._cursor != count:
            raise StateError("ES occurrence replay lost an admitted source snapshot")
        states = {state.source_instance: state for state in dispatcher.es_collectors.snapshot()}
        for state in registry.snapshot():
            current = states.get(state.source_instance)
            if current is None or current.generation != state.generation:
                raise StateError("ES replay lost its final source connection")
            states[state.source_instance] = state.model_copy(
                update={"closed_at": current.closed_at}
            )
        _, membership = dispatcher.es_collectors.snapshot_with_membership()
        completed = ESCollectorRegistry()
        completed.restore(tuple(states.values()), membership)
        dispatcher.es_collectors = completed
        self.finalized = True
