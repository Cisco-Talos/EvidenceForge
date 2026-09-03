"""Incremental checkpoint adapter for deferred Windows source journals."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "1"
_EVENT_COLUMNS = (
    "sequence",
    "sort_key",
    "phase",
    "payload",
    "payload_bytes",
    "ordinal",
    "route_kind",
    "route_key",
    "payload_digest",
)
_FINALIZATION_COLUMNS = (
    "singleton",
    "phase",
    "candidate_rows",
    "candidate_bytes",
    "final_rows",
    "final_bytes",
    "routes",
    "published_rows",
    "epoch",
    "high_water_rows",
    "high_water_bytes",
    "high_water_routes",
)
_COUNTER_ATTRIBUTES = (
    "_candidate_admitted_rows",
    "_candidate_admitted_bytes",
    "_candidate_high_water_rows",
    "_candidate_high_water_bytes",
    "_source_high_water_rows",
    "_source_high_water_bytes",
    "_source_high_water_routes",
    "_exact_candidate_high_water_rows",
    "_exact_candidate_high_water_bytes",
    "_exact_candidate_high_water_participants",
    "_checkpoint_pruned_exact_sequence",
)
_SYSMON_LIVE_ATTRIBUTES = (
    "_terminal_session_ids_by_logon",
    "_call_trace_cache",
    "_call_trace_counters",
    "_sysmon_thread_pools",
    "_sysmon_thread_counters",
    "_sysmon_last_thread_by_host",
    "_sysmon_pids",
    "_dns_client_pids",
)
_TRANSIENT_EMPTY_ATTRIBUTES = (
    "_event_dicts",
    "_record_id_sequences",
    "_last_time_created_by_computer",
    "_time_collision_count_by_computer",
    "_final_process_guids",
    "_last_record_time_created_by_computer",
    "_lock_lifecycle_shift_by_session",
    "_rendered_lock_time_by_session",
    "_exact_candidate_reservations",
    "_exact_candidate_participants",
    "_active_exact_publication_keys",
    "_source_finalization_routes",
    "_source_finalization_route_ids",
)


@dataclass(frozen=True)
class _PreparedState:
    sequence: int
    committed_sequence: int
    seal: ParticipantSeal


def _require_int(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CheckpointCorruptionError(f"deferred source checkpoint {label} is invalid")
    return value


def _require_row(value: object, *, width: int, label: str) -> list[object]:
    if type(value) is not list or len(value) != width:
        raise CheckpointCorruptionError(f"deferred source checkpoint {label} is invalid")
    return value


class DeferredSourceSpoolParticipant:
    """Seal only newly appended rows from one exact source-finalization journal."""

    checkpoint_restore_priority = 44
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("journal_tail", "immutable-incremental-segments"),
        OwnerStateField("journal_finalization_state", "bounded-live-head"),
        OwnerStateField("source_allocator_caches", "bounded-live-head"),
        OwnerStateField("journal_connection_and_protected_path", "deterministically-rebuilt"),
        OwnerStateField("renderer_and_exact_publication_state", "transient-empty-at-barrier"),
    )

    def __init__(self, *, format_name: str, emitter: object) -> None:
        if format_name not in {"windows_event_security", "windows_event_sysmon"}:
            raise ValueError(f"unsupported deferred source emitter: {format_name}")
        if not bool(getattr(emitter, "_source_finalization_bound", False)):
            raise ValueError(f"{format_name} does not own a deferred source journal")
        self.format_name = format_name
        self.emitter = emitter
        self.checkpoint_owner = f"deferred-source-spool.{format_name}"
        self._committed_sequence = 0
        self._prepared: _PreparedState | None = None
        self.last_rows_read = 0
        self.last_payload_bytes_read = 0

    def _prune_terminal_receipts(self) -> None:
        prune = getattr(self.emitter, "prune_checkpoint_terminal_receipts", None)
        if not callable(prune):
            raise RuntimeError(f"{self.format_name} lacks checkpoint receipt pruning")
        prune()

    def _validate_transients(self) -> None:
        for attribute in _TRANSIENT_EMPTY_ATTRIBUTES:
            value = getattr(self.emitter, attribute, None)
            if value:
                raise RuntimeError(
                    f"{self.format_name} checkpoint barrier retained transient {attribute}"
                )
        scalar_expectations = {
            "_queue_admissions": 0,
            "_exact_candidate_current_rows": 0,
            "_exact_candidate_current_bytes": 0,
            "_exact_candidate_current_participants": 0,
            "_exact_candidate_released_rows": 0,
            "_exact_candidate_released_bytes": 0,
            "_exact_candidate_completed_participants": 0,
            "_source_finalization_state": "open",
            "_source_finalization_owner": None,
            "_source_finalization_epoch": None,
        }
        for attribute, expected in scalar_expectations.items():
            if getattr(self.emitter, attribute, expected) != expected:
                raise RuntimeError(
                    f"{self.format_name} checkpoint barrier retained transient {attribute}"
                )

    def _live_state(self) -> object:
        if self.format_name != "windows_event_sysmon":
            return encode_state_value({})
        state: dict[str, object] = {}
        for attribute in _SYSMON_LIVE_ATTRIBUTES:
            present = hasattr(self.emitter, attribute)
            state[attribute] = {
                "present": present,
                "value": getattr(self.emitter, attribute) if present else None,
            }
        return encode_state_value(state)

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Seal the journal suffix and bounded source-native allocator state."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("deferred source participant already prepared another sequence")
            return self._prepared.seal
        self._prune_terminal_receipts()
        self._validate_transients()
        self.last_rows_read = 0
        self.last_payload_bytes_read = 0

        spool_sequence = _require_int(
            getattr(self.emitter, "_spool_sequence", None), label="spool sequence"
        )
        spooled_count = _require_int(
            getattr(self.emitter, "_spooled_count", None), label="spooled count"
        )
        if spool_sequence != spooled_count or spool_sequence < self._committed_sequence:
            raise RuntimeError(f"{self.format_name} journal sequence accounting changed")

        with self.emitter._file_lock:
            connection = getattr(self.emitter, "_spool_conn", None)
            if spool_sequence:
                if connection is None:
                    raise RuntimeError(f"{self.format_name} lost its deferred journal")
                self.emitter._validate_spool_file_unlocked()
                rows = connection.execute(
                    """SELECT sequence, sort_key, phase, payload, payload_bytes, ordinal,
                              route_kind, route_key, payload_digest
                       FROM events WHERE sequence >= ? ORDER BY sequence""",
                    (self._committed_sequence,),
                ).fetchall()
                finalization_state = connection.execute(
                    "SELECT * FROM finalization_state WHERE singleton = ?",
                    (1,),
                ).fetchone()
            else:
                rows = []
                finalization_state = (1, "candidate", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        expected_sequences = list(range(self._committed_sequence, spool_sequence))
        if [row[0] for row in rows] != expected_sequences:
            raise RuntimeError(f"{self.format_name} journal tail is not contiguous")
        if any(row[2] != "candidate" for row in rows):
            raise RuntimeError(f"{self.format_name} checkpoint encountered finalized rows")
        if finalization_state is None or len(finalization_state) != len(_FINALIZATION_COLUMNS):
            raise RuntimeError(f"{self.format_name} finalization state is malformed")
        self.last_rows_read = len(rows)
        self.last_payload_bytes_read = sum(int(row[4]) for row in rows)

        counters: dict[str, int] = {}
        for attribute in _COUNTER_ATTRIBUTES:
            value = getattr(self.emitter, attribute, None)
            if type(value) is not int or value < 0:
                raise RuntimeError(f"{self.format_name} counter {attribute} is malformed")
            counters[attribute] = value
        segments: tuple[SegmentDraft, ...] = ()
        if rows:
            segments = (
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps(
                        {
                            "format": self.format_name,
                            "rows": [list(row) for row in rows],
                            "schema_version": self.checkpoint_schema_version,
                            "start_sequence": self._committed_sequence,
                        }
                    ),
                    record_count=len(rows),
                ),
            )
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(
                    {
                        "counters": counters,
                        "finalization_state": list(finalization_state),
                        "format": self.format_name,
                        "live_state": self._live_state(),
                        "schema_version": self.checkpoint_schema_version,
                        "spool_sequence": spool_sequence,
                    }
                ),
            ),
            segments=segments,
        )
        self._prepared = _PreparedState(
            sequence=sequence,
            committed_sequence=spool_sequence,
            seal=seal,
        )
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the append watermark after manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("deferred source participant commit has no matching seal")
        self._committed_sequence = self._prepared.committed_sequence
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retain the old journal watermark when publication aborts."""

        if self._prepared is not None and self._prepared.sequence == sequence:
            self._prepared = None

    def _decode_head(self, head: bytes) -> dict[str, object]:
        decoded = loads(head)
        if type(decoded) is not dict:
            raise CheckpointCorruptionError("deferred source checkpoint head is invalid")
        if (
            decoded.get("schema_version") != self.checkpoint_schema_version
            or decoded.get("format") != self.format_name
        ):
            raise CheckpointCorruptionError("deferred source checkpoint schema is incompatible")
        return decoded

    def _decode_segments(self, segments: tuple[bytes, ...], total: int) -> list[list[object]]:
        restored: list[list[object]] = []
        next_sequence = 0
        for payload in segments:
            decoded = loads(payload)
            if type(decoded) is not dict or (
                decoded.get("schema_version") != self.checkpoint_schema_version
                or decoded.get("format") != self.format_name
                or decoded.get("start_sequence") != next_sequence
            ):
                raise CheckpointCorruptionError("deferred source checkpoint segment is invalid")
            rows = decoded.get("rows")
            if type(rows) is not list:
                raise CheckpointCorruptionError("deferred source checkpoint rows are invalid")
            for encoded in rows:
                row = _require_row(encoded, width=len(_EVENT_COLUMNS), label="event row")
                if row[0] != next_sequence or row[2] != "candidate":
                    raise CheckpointCorruptionError(
                        "deferred source checkpoint journal is not contiguous"
                    )
                if (
                    type(row[1]) is not str
                    or type(row[3]) is not str
                    or type(row[4]) is not int
                    or row[4] != len(row[3].encode("utf-8"))
                ):
                    raise CheckpointCorruptionError(
                        "deferred source checkpoint event row is malformed"
                    )
                restored.append(row)
                next_sequence += 1
        if next_sequence != total:
            raise CheckpointCorruptionError("deferred source checkpoint journal tail is missing")
        return restored

    def _restore_live_state(self, encoded: object) -> None:
        state = decode_state_value(encoded)
        if type(state) is not dict:
            raise CheckpointCorruptionError("deferred source checkpoint live state is invalid")
        if self.format_name == "windows_event_security":
            if state:
                raise CheckpointCorruptionError("Windows Security live state is unsupported")
            return
        if set(state) != set(_SYSMON_LIVE_ATTRIBUTES):
            raise CheckpointCorruptionError("Sysmon live-state field set changed")
        for attribute in _SYSMON_LIVE_ATTRIBUTES:
            document = state[attribute]
            if type(document) is not dict or set(document) != {"present", "value"}:
                raise CheckpointCorruptionError("Sysmon live-state entry is invalid")
            present = document["present"]
            value = document["value"]
            if type(present) is not bool or (present and type(value) is not dict):
                raise CheckpointCorruptionError("Sysmon live-state entry is invalid")
            if present:
                setattr(self.emitter, attribute, value)
            elif hasattr(self.emitter, attribute):
                delattr(self.emitter, attribute)

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Rebuild a fresh protected SQLite journal and restore bounded allocators."""

        decoded = self._decode_head(head)
        total = _require_int(decoded.get("spool_sequence"), label="spool sequence")
        rows = self._decode_segments(segments, total)
        finalization_state = _require_row(
            decoded.get("finalization_state"),
            width=len(_FINALIZATION_COLUMNS),
            label="finalization state",
        )
        if (
            finalization_state[0] != 1
            or finalization_state[1] != "candidate"
            or finalization_state[2] != total
            or finalization_state[4:9] != [0, 0, 0, 0, 0]
        ):
            raise CheckpointCorruptionError("deferred source finalization state is inconsistent")
        counters = decoded.get("counters")
        if type(counters) is not dict or set(counters) != set(_COUNTER_ATTRIBUTES):
            raise CheckpointCorruptionError("deferred source checkpoint counters changed")
        validated_counters = {
            attribute: _require_int(counters[attribute], label=attribute)
            for attribute in _COUNTER_ATTRIBUTES
        }
        if (
            validated_counters["_candidate_admitted_rows"] != total
            or validated_counters["_candidate_admitted_bytes"] != finalization_state[3]
        ):
            raise CheckpointCorruptionError("deferred source candidate accounting is inconsistent")

        self._validate_transients()
        with self.emitter._file_lock:
            if getattr(self.emitter, "_spool_conn", None) is not None:
                raise RuntimeError(f"{self.format_name} restore requires a fresh emitter journal")
            if rows:
                connection = self.emitter._get_spool_conn_unlocked()
                self.emitter._validate_spool_file_unlocked()
                connection.executemany(
                    """INSERT INTO events
                       (sequence, sort_key, phase, payload, payload_bytes, ordinal,
                        route_kind, route_key, payload_digest)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                connection.execute(
                    """UPDATE finalization_state SET
                       phase = ?, candidate_rows = ?, candidate_bytes = ?, final_rows = ?,
                       final_bytes = ?, routes = ?, published_rows = ?, epoch = ?,
                       high_water_rows = ?, high_water_bytes = ?, high_water_routes = ?
                       WHERE singleton = ?""",
                    tuple(finalization_state[1:]) + (1,),
                )
                self.emitter._commit_journal_unlocked()
        self.emitter._spool_sequence = total
        self.emitter._spooled_count = total
        for attribute, value in validated_counters.items():
            setattr(self.emitter, attribute, value)
        self._restore_live_state(decoded.get("live_state"))
        self._committed_sequence = total


__all__ = ["DeferredSourceSpoolParticipant"]
