"""Incremental checkpoint adapter for the Snort candidate journal."""

from __future__ import annotations

from dataclasses import dataclass

from evidenceforge.events.ids_evaluation import IdsDigest

from .errors import CheckpointCorruptionError, CheckpointError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "1"
_CANDIDATE_COLUMNS = (
    "sequence",
    "publication_key",
    "publication_digest",
    "row_kind",
    "sensor",
    "timestamp",
    "gid",
    "sid",
    "payload",
    "policy",
    "cluster_id",
    "occurrence_id",
    "observation_status",
    "origin",
    "final_line",
    "payload_bytes",
    "terminal_headroom_bytes",
    "detection_key",
    "detection_count",
    "detection_seconds",
    "event_key",
    "event_count",
    "event_seconds",
    "exported",
    "summarized",
    "admitted",
    "released",
    "epoch",
)
_SPOOL_STATE_COLUMNS = (
    "singleton",
    "pending_rows",
    "pending_bytes",
    "exported_rows",
    "exported_bytes",
    "admission_receipts",
    "admission_bytes",
    "export_slots",
    "export_slot_bytes",
    "export_receipts",
    "export_bytes",
    "summary_rows",
    "summary_bytes",
    "filter_rows",
    "filter_bytes",
    "terminal_headroom_bytes",
    "plan_rows",
    "plan_bytes",
    "total_events",
    "high_water_rows",
    "high_water_bytes",
    "filter_watermark",
)
_EMPTY_TABLES = (
    "admission_receipts",
    "export_plans",
    "export_receipts",
    "filter_checkpoints",
    "raw_sensor_state",
)
_TRANSIENT_EMPTY_ATTRIBUTES = (
    "_active_exact_publication_keys",
    "_consumed_plan_buffers",
    "_exact_buffer_plan_headroom",
    "_exact_candidate_receipts",
    "_exact_capacity_reservations",
    "_exact_prepared_policy_limits",
    "_exact_provisional_output_bytes",
    "_exact_provisional_output_owners",
    "_exact_provisional_output_states",
    "_summary_decisions",
    "_summary_filter_records",
)


@dataclass(frozen=True)
class _PreparedState:
    sequence: int
    committed_sequence: int
    seal: ParticipantSeal


def _require_int(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CheckpointCorruptionError(f"Snort checkpoint {label} is invalid")
    return value


def _require_row(value: object, *, width: int, label: str) -> list[object]:
    if type(value) is not list or len(value) != width:
        raise CheckpointCorruptionError(f"Snort checkpoint {label} is invalid")
    return value


def _encode_digest(digest: object) -> list[object]:
    if type(digest) is not IdsDigest:
        raise CheckpointError("Snort checkpoint evaluation summary has a foreign digest")
    version, words, byte_count, pending = digest.checkpoint_state()
    return [version, list(words), byte_count, pending]


def _decode_digest(value: object) -> IdsDigest:
    row = _require_row(value, width=4, label="digest state")
    if type(row[1]) is not list:
        raise CheckpointCorruptionError("Snort checkpoint digest words are invalid")
    try:
        return IdsDigest.from_checkpoint_state(
            (row[0], tuple(row[1]), row[2], row[3]),
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("Snort checkpoint digest state is invalid") from error


class SnortSpoolParticipant:
    """Seal only new candidate rows plus bounded filter-summary state."""

    checkpoint_owner = "snort-spool"
    checkpoint_restore_priority = 46
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("candidate_rows", "immutable-incremental-segments"),
        OwnerStateField("journal_census", "bounded-live-head"),
        OwnerStateField("evaluation_summaries", "bounded-live-head"),
        OwnerStateField("output_routes", "deterministically-rebuilt"),
        OwnerStateField("journal_connection_and_protected_path", "deterministically-rebuilt"),
        OwnerStateField("publication_and_export_state", "transient-empty-at-barrier"),
    )

    def __init__(self, emitter: object) -> None:
        self.emitter = emitter
        self._committed_sequence = 0
        self._prepared: _PreparedState | None = None
        self.last_rows_read = 0
        self.last_payload_bytes_read = 0

    def _validate_transients(self) -> None:
        for attribute in _TRANSIENT_EMPTY_ATTRIBUTES:
            if getattr(self.emitter, attribute, None):
                raise CheckpointError(f"Snort checkpoint barrier retained transient {attribute}")
        scalar_expectations = {
            "_exact_reserved_bytes": 0,
            "_exact_reserved_rows": 0,
            "_export_recovery_pending": False,
            "_pending_summary_snapshot": None,
            "_preparing_exact_policy_limits": None,
            "_preparing_exact_sensor": None,
            "_preparing_exact_terminal_headroom": None,
            "_queue_admissions": 0,
            "_summary_filter_watermark": "",
            "_summary_scope": "none",
            "_worker_publication_error": None,
        }
        for attribute, expected in scalar_expectations.items():
            if getattr(self.emitter, attribute, expected) != expected:
                raise CheckpointError(f"Snort checkpoint barrier retained transient {attribute}")
        if getattr(self.emitter, "_ids_alert_summary", None):
            raise CheckpointError("Snort checkpoint barrier finalized candidate summaries early")

    def _evaluation_rows(self) -> list[list[object]]:
        rows: list[list[object]] = []
        summaries = getattr(self.emitter, "_ids_evaluation_summary", None)
        if type(summaries) is not dict:
            raise CheckpointError("Snort checkpoint evaluation summary is malformed")
        for sensor, signatures in sorted(summaries.items()):
            if type(sensor) is not str or type(signatures) is not dict:
                raise CheckpointError("Snort checkpoint evaluation summary is malformed")
            for key, summary in sorted(signatures.items()):
                if type(key) is not str or type(summary) is not dict:
                    raise CheckpointError("Snort checkpoint evaluation signature is malformed")
                expected = {
                    "_digest",
                    "candidate",
                    "emitted",
                    "emitted_delayed",
                    "emitted_visible",
                    "gid",
                    "origins",
                    "policy_filtered",
                    "sid",
                }
                origins = summary.get("origins")
                if set(summary) != expected or type(origins) is not dict:
                    raise CheckpointError("Snort checkpoint evaluation signature is malformed")
                numeric = [
                    summary[name]
                    for name in (
                        "gid",
                        "sid",
                        "candidate",
                        "emitted",
                        "policy_filtered",
                        "emitted_visible",
                        "emitted_delayed",
                    )
                ]
                if any(type(value) is not int or value < 0 for value in numeric) or any(
                    type(origin) is not str or type(count) is not int or count < 0
                    for origin, count in origins.items()
                ):
                    raise CheckpointError("Snort checkpoint evaluation signature is malformed")
                rows.append(
                    [
                        sensor,
                        key,
                        *numeric,
                        dict(origins),
                        _encode_digest(summary["_digest"]),
                    ]
                )
        return rows

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Seal candidate rows admitted since the prior durable manifest."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("Snort participant already prepared another sequence")
            return self._prepared.seal
        self._validate_transients()
        self.last_rows_read = 0
        self.last_payload_bytes_read = 0
        with self.emitter._spool_lock:
            connection = self.emitter._spool_connection
            if connection is None:
                candidate_sequence = 0
                candidate_rows: list[tuple[object, ...]] = []
                spool_state = [1, *([0] * 20), ""]
            else:
                self.emitter._journal_owner.validate()
                sequence_row = connection.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = ?",
                    ("candidates",),
                ).fetchone()
                candidate_sequence = 0 if sequence_row is None else int(sequence_row[0])
                if candidate_sequence < self._committed_sequence:
                    raise CheckpointError("Snort candidate sequence moved backward")
                candidate_rows = connection.execute(
                    f"SELECT {', '.join(_CANDIDATE_COLUMNS)} FROM candidates "
                    "WHERE sequence > ? ORDER BY sequence",
                    (self._committed_sequence,),
                ).fetchall()
                state_row = connection.execute(
                    f"SELECT {', '.join(_SPOOL_STATE_COLUMNS)} FROM spool_state "
                    "WHERE singleton = ?",
                    (1,),
                ).fetchone()
                if state_row is None:
                    raise CheckpointError("Snort checkpoint journal lost its census")
                spool_state = list(state_row)
                for table in _EMPTY_TABLES:
                    if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                        raise CheckpointError(
                            f"Snort checkpoint barrier retained transient table {table}"
                        )
                summaries = connection.execute(
                    "SELECT summary_key, payload, retained_bytes FROM summaries "
                    "ORDER BY summary_key"
                ).fetchall()
                expected_summaries = self.emitter._summary_records(
                    {},
                    self.emitter._ids_evaluation_summary,
                )
                if summaries != expected_summaries:
                    raise CheckpointError("Snort checkpoint summary journal is inconsistent")
        self._validate_candidate_rows(
            [list(row) for row in candidate_rows],
            start_after=self._committed_sequence,
            end_sequence=candidate_sequence,
        )
        self._validate_spool_state(spool_state, candidate_sequence=candidate_sequence)
        self.last_rows_read = len(candidate_rows)
        self.last_payload_bytes_read = sum(int(row[15]) for row in candidate_rows)
        segments: tuple[SegmentDraft, ...] = ()
        if candidate_sequence > self._committed_sequence:
            segments = (
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps(
                        {
                            "end_sequence": candidate_sequence,
                            "rows": [list(row) for row in candidate_rows],
                            "schema_version": self.checkpoint_schema_version,
                            "start_after": self._committed_sequence,
                        }
                    ),
                    record_count=len(candidate_rows),
                ),
            )
        known_sensors = getattr(self.emitter, "_known_output_sensors", None)
        if type(known_sensors) is not set or any(
            type(sensor) is not str for sensor in known_sensors
        ):
            raise CheckpointError("Snort checkpoint output sensor set is malformed")
        next_epoch = getattr(self.emitter, "_next_epoch", None)
        if type(next_epoch) is not int or next_epoch <= 0:
            raise CheckpointError("Snort checkpoint export epoch is malformed")
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(
                    {
                        "candidate_sequence": candidate_sequence,
                        "evaluation": self._evaluation_rows(),
                        "known_sensors": sorted(known_sensors),
                        "next_epoch": next_epoch,
                        "schema_version": self.checkpoint_schema_version,
                        "spool_state": spool_state,
                    }
                ),
            ),
            segments=segments,
        )
        self._prepared = _PreparedState(
            sequence=sequence,
            committed_sequence=candidate_sequence,
            seal=seal,
        )
        return seal

    @staticmethod
    def _validate_candidate_rows(
        rows: list[list[object]],
        *,
        start_after: int,
        end_sequence: int,
    ) -> None:
        prior = start_after
        publication_keys: set[str] = set()
        for row in rows:
            if (
                len(row) != len(_CANDIDATE_COLUMNS)
                or type(row[0]) is not int
                or not prior < row[0] <= end_sequence
                or (row[1] is not None and type(row[1]) is not str)
                or (row[2] is not None and type(row[2]) is not str)
                or (row[1] is None) != (row[2] is None)
                or row[3] != "candidate"
                or any(type(row[index]) is not str for index in (4, 5, 8, 9, 10, 11, 12, 13))
                or any(type(row[index]) is not int for index in (6, 7, 15, 16))
                or row[15] < 0
                or row[16] < 0
                or row[23:28] != [0, 0, None, 1, None]
            ):
                raise CheckpointCorruptionError("Snort checkpoint candidate row is invalid")
            if row[1] is not None:
                if row[1] in publication_keys:
                    raise CheckpointCorruptionError(
                        "Snort checkpoint candidate publication key is duplicated"
                    )
                publication_keys.add(row[1])
            prior = row[0]

    @staticmethod
    def _validate_spool_state(state: list[object], *, candidate_sequence: int) -> None:
        if (
            len(state) != len(_SPOOL_STATE_COLUMNS)
            or state[0] != 1
            or any(type(value) is not int or value < 0 for value in state[1:21])
            or state[21] != ""
            or any(state[index] != 0 for index in (3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 16, 17))
            or state[1] > candidate_sequence
        ):
            raise CheckpointCorruptionError("Snort checkpoint journal census is invalid")

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the candidate watermark only after manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("Snort participant commit has no matching seal")
        self._committed_sequence = self._prepared.committed_sequence
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Keep the prior candidate watermark when publication aborts."""

        if self._prepared is not None and self._prepared.sequence == sequence:
            self._prepared = None

    @staticmethod
    def _decode_evaluation(rows: object) -> dict[str, dict[str, dict[str, object]]]:
        if type(rows) is not list:
            raise CheckpointCorruptionError("Snort checkpoint evaluation table is invalid")
        restored: dict[str, dict[str, dict[str, object]]] = {}
        for value in rows:
            row = _require_row(value, width=11, label="evaluation row")
            sensor, key = row[:2]
            numeric = row[2:9]
            origins = row[9]
            if (
                type(sensor) is not str
                or not sensor
                or type(key) is not str
                or not key
                or any(type(item) is not int or item < 0 for item in numeric)
                or type(origins) is not dict
                or any(
                    type(origin) is not str or type(count) is not int or count < 0
                    for origin, count in origins.items()
                )
                or key in restored.get(sensor, {})
            ):
                raise CheckpointCorruptionError("Snort checkpoint evaluation signature is invalid")
            restored.setdefault(sensor, {})[key] = {
                "gid": numeric[0],
                "sid": numeric[1],
                "candidate": numeric[2],
                "emitted": numeric[3],
                "policy_filtered": numeric[4],
                "emitted_visible": numeric[5],
                "emitted_delayed": numeric[6],
                "origins": dict(origins),
                "_digest": _decode_digest(row[10]),
            }
        return restored

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Recreate a fresh protected candidate journal and resumable summaries."""

        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
            or type(document.get("known_sensors")) is not list
        ):
            raise CheckpointCorruptionError("Snort checkpoint head schema is unsupported")
        candidate_sequence = _require_int(
            document.get("candidate_sequence"),
            label="candidate sequence",
        )
        next_epoch = _require_int(document.get("next_epoch"), label="next epoch")
        if next_epoch == 0:
            raise CheckpointCorruptionError("Snort checkpoint next epoch is invalid")
        known_sensors = document["known_sensors"]
        if any(type(sensor) is not str or not sensor for sensor in known_sensors) or len(
            known_sensors
        ) != len(set(known_sensors)):
            raise CheckpointCorruptionError("Snort checkpoint output sensor set is invalid")
        spool_state = _require_row(
            document.get("spool_state"),
            width=len(_SPOOL_STATE_COLUMNS),
            label="journal census",
        )
        self._validate_spool_state(spool_state, candidate_sequence=candidate_sequence)
        evaluation = self._decode_evaluation(document.get("evaluation"))

        candidate_rows: list[list[object]] = []
        expected_start = 0
        for payload in segments:
            decoded = loads(payload)
            if (
                type(decoded) is not dict
                or decoded.get("schema_version") != self.checkpoint_schema_version
                or decoded.get("start_after") != expected_start
            ):
                raise CheckpointCorruptionError("Snort checkpoint segment chain is invalid")
            end_sequence = _require_int(decoded.get("end_sequence"), label="segment end")
            if end_sequence <= expected_start:
                raise CheckpointCorruptionError("Snort checkpoint segment made no progress")
            raw_rows = decoded.get("rows")
            if type(raw_rows) is not list:
                raise CheckpointCorruptionError("Snort checkpoint candidate table is invalid")
            rows = [
                _require_row(row, width=len(_CANDIDATE_COLUMNS), label="candidate row")
                for row in raw_rows
            ]
            self._validate_candidate_rows(
                rows,
                start_after=expected_start,
                end_sequence=end_sequence,
            )
            candidate_rows.extend(rows)
            expected_start = end_sequence
        if expected_start != candidate_sequence:
            raise CheckpointCorruptionError("Snort checkpoint candidate segments are incomplete")
        if len({row[0] for row in candidate_rows}) != len(candidate_rows):
            raise CheckpointCorruptionError("Snort checkpoint candidate sequence is duplicated")
        if len({row[1] for row in candidate_rows if row[1] is not None}) != sum(
            row[1] is not None for row in candidate_rows
        ):
            raise CheckpointCorruptionError(
                "Snort checkpoint candidate publication key is duplicated"
            )
        if spool_state[1] != len(candidate_rows) or spool_state[2] != sum(
            int(row[15]) for row in candidate_rows
        ):
            raise CheckpointCorruptionError("Snort checkpoint candidate accounting is inconsistent")

        self._validate_transients()
        with self.emitter._spool_lock:
            if self.emitter._spool_connection is not None:
                raise RuntimeError("Snort checkpoint restore requires a fresh protected journal")
            self.emitter._ids_alert_summary = {}
            self.emitter._ids_evaluation_summary = evaluation
            self.emitter._known_output_sensors = set(known_sensors)
            self.emitter._output_routes_initialized = False
            self.emitter._output_route_states = {}
            self.emitter._output_owner_sensors = {}
            self.emitter._output_baseline_bytes = 0
            self.emitter._initialize_output_routes_unlocked()
            if candidate_sequence:
                connection = self.emitter._open_spool()
                if candidate_rows:
                    placeholders = ", ".join("?" for _ in _CANDIDATE_COLUMNS)
                    connection.executemany(
                        f"INSERT INTO candidates ({', '.join(_CANDIDATE_COLUMNS)}) "
                        f"VALUES ({placeholders})",
                        candidate_rows,
                    )
                connection.execute(
                    "UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
                    (candidate_sequence, "candidates"),
                )
                assignments = ", ".join(f"{column} = ?" for column in _SPOOL_STATE_COLUMNS[1:])
                connection.execute(
                    f"UPDATE spool_state SET {assignments} WHERE singleton = ?",
                    (*spool_state[1:], 1),
                )
                connection.commit()
            self.emitter._next_epoch = next_epoch
            self.emitter._emitted_event_count = sum(
                int(summary["emitted"])
                for signatures in evaluation.values()
                for summary in signatures.values()
            )
            self.emitter._retained_total_events = int(spool_state[18])
            self.emitter._retained_high_water_rows = int(spool_state[19])
            self.emitter._retained_high_water_bytes = int(spool_state[20])
        self._committed_sequence = candidate_sequence
        self._prepared = None


__all__ = ["SnortSpoolParticipant"]
