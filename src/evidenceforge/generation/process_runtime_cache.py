# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded exact caches for process-lifecycle-adjacent runtime state."""

from __future__ import annotations

import ast
import json
import sqlite3
import sys
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Generic, TypeVar, cast

from evidenceforge.generation.indexes import (
    CompactIndexedStore,
    ExpiringIndex,
    IndexMetrics,
    PackedHandleExpiryIndex,
)
from evidenceforge.utils.time import ensure_utc

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


@dataclass(frozen=True, slots=True)
class RuntimeProcessBinding:
    """Exact process instance retained by a tuple or PID compatibility key."""

    pid: int
    process_key: tuple[str, int, datetime | None]


@dataclass(frozen=True, slots=True)
class ProcessRuntimeCacheFamilySpec:
    """Public production shape for one bounded generator cache family."""

    name: str
    key_shape: str
    value_shape: str
    deadline_shape: str


class ActivityGeneratorRetentionDisposition(StrEnum):
    """Observed retention behavior for one direct mutable generator field."""

    BOUNDED = "bounded"
    SCENARIO_STATIC = "scenario_static"
    TRANSIENT = "transient"
    DEFINITE_GROWTH = "definite_growth"
    CONDITIONAL_GROWTH = "conditional_growth"
    DEAD = "dead"


@dataclass(frozen=True, slots=True)
class ActivityGeneratorMutableRetentionPolicy:
    """Checked ownership and horizon for one mutable generator field."""

    field_name: str
    owner: str
    horizon: str
    disposition: ActivityGeneratorRetentionDisposition = (
        ActivityGeneratorRetentionDisposition.CONDITIONAL_GROWTH
    )
    evidence: str = "legacy policy awaiting whole-class classification"


@dataclass(frozen=True, slots=True)
class ActivityGeneratorMutableFieldDiscovery:
    """Whole-class AST evidence for one directly retained mutable field."""

    field_name: str
    first_line: int
    methods: tuple[str, ...]
    mutation_kinds: tuple[str, ...]
    lazy: bool


@dataclass(frozen=True, slots=True)
class ActivityGeneratorMutableFieldSnapshot:
    """Whole-instance cardinality evidence for one materialized mutable field."""

    field_name: str
    value_type: str
    entries: int
    retained_bytes: int
    alias_owner: str
    policy_disposition: ActivityGeneratorRetentionDisposition


@dataclass(frozen=True, slots=True)
class ActivityGeneratorSessionRetentionRelease:
    """Exact retained rows released after one accepted session close."""

    bash_rows: int = 0
    local_session_rows: int = 0
    workstation_lock_rows: int = 0
    browser_target_rows: int = 0
    sudo_tty_rows: int = 0

    @property
    def total_rows(self) -> int:
        """Return all rows released by the idempotent close hook."""

        return (
            self.bash_rows
            + self.local_session_rows
            + self.workstation_lock_rows
            + self.browser_target_rows
            + self.sudo_tty_rows
        )


@dataclass(frozen=True, slots=True)
class EmailArtifactManifestSpoolCensus:
    """Constant-time census for a disk-backed artifact-manifest spool."""

    logical_rows: int
    backing_rows: int
    retained_rows: int
    database_bytes: int
    maximum_append_work: int


class EmailArtifactManifestSpool:
    """Disk-backed, deterministically ordered email artifact-manifest rows.

    SQLite owns the duration-sized payload. Python retains only the connection
    and scalar counters, and final JSON publication streams the ordered rows
    one at a time. The spool is an internal disposable build artifact.
    """

    def __init__(self, manifest_path: Path) -> None:
        self._manifest_path = manifest_path
        self._database_path = manifest_path.with_name(f".{manifest_path.name}.spool.sqlite3")
        self._connection: sqlite3.Connection | None = None
        self._logical_rows = 0
        self._maximum_append_work = 0

    def _connect(self) -> sqlite3.Connection:
        connection = self._connection
        if connection is not None:
            return connection
        self._manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._database_path.unlink(missing_ok=True)
        connection = sqlite3.connect(self._database_path, isolation_level=None)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA cache_size=-2048")
        connection.execute(
            """
            CREATE TABLE manifest_rows (
                ordinal INTEGER PRIMARY KEY,
                date_value TEXT NOT NULL,
                message_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._connection = connection
        return connection

    def append(self, row: Mapping[str, object]) -> None:
        """Spool one manifest row with constant retained Python state."""

        payload = json.dumps(dict(row), sort_keys=True, separators=(",", ":"))
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO manifest_rows (ordinal, date_value, message_id, sender, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                self._logical_rows,
                str(row.get("date") or ""),
                str(row.get("message_id") or ""),
                str(row.get("sender") or ""),
                payload,
            ),
        )
        self._logical_rows += 1
        self._maximum_append_work = max(self._maximum_append_work, 1)

    def census(self) -> EmailArtifactManifestSpoolCensus:
        """Return row and disk cardinality without loading any payload row."""

        database_bytes = self._database_path.stat().st_size if self._database_path.exists() else 0
        return EmailArtifactManifestSpoolCensus(
            logical_rows=self._logical_rows,
            backing_rows=self._logical_rows,
            retained_rows=0,
            database_bytes=database_bytes,
            maximum_append_work=self._maximum_append_work,
        )

    def write_manifest(self, *, schema_version: str) -> int:
        """Stream the final sorted manifest and dispose of the spool."""

        if self._logical_rows == 0:
            self.close()
            return 0
        connection = self._connect()
        temporary_path = self._manifest_path.with_name(f".{self._manifest_path.name}.tmp")
        with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
            output.write('{\n  "email": {\n    "messages": [')
            first = True
            cursor = connection.execute(
                """
                SELECT payload
                FROM manifest_rows
                ORDER BY date_value, message_id, sender, ordinal
                """
            )
            for (payload,) in cursor:
                output.write("\n      " if first else ",\n      ")
                rendered_row = json.dumps(
                    json.loads(str(payload)),
                    indent=2,
                    sort_keys=True,
                )
                output.write(rendered_row.replace("\n", "\n      "))
                first = False
            if not first:
                output.write("\n    ")
            output.write(']\n  },\n  "schema_version": ' + json.dumps(schema_version) + "\n}\n")
        temporary_path.replace(self._manifest_path)
        rows = self._logical_rows
        self.close()
        return rows

    def close(self) -> None:
        """Close and remove the disposable database idempotently."""

        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()
        self._database_path.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class ProcessRuntimeCacheFamilyCensus:
    """Constant-time structural census for one production cache family."""

    name: str
    live_entries: int
    backing_entries: int
    stale_entries: int
    high_water_mark: int
    estimated_bytes: int
    estimated_index_bytes: int
    lookup_candidates_inspected: int
    expiry_work: int


@dataclass(frozen=True, slots=True)
class ProcessRuntimeCacheLoadResult:
    """Describe whether one representative probe load inserted or replaced."""

    inserted: bool
    replaced: bool
    key: Hashable
    deadline: datetime


@dataclass(frozen=True, slots=True)
class ProcessRuntimeCacheExpiryPage:
    """One bounded cross-family expiry result."""

    expired_by_family: tuple[
        tuple[str, tuple[tuple[Hashable, object], ...]],
        ...,
    ]
    processed: int
    has_more: bool


def deadline_seconds(value: datetime | float | int) -> float:
    """Return a platform-independent sortable UTC deadline."""

    if isinstance(value, datetime):
        return (ensure_utc(value) - _EPOCH).total_seconds()
    return float(value)


def _retained_size(value: object, *, seen: set[int] | None = None) -> int:
    """Estimate retained payload bytes once at mutation time.

    Runtime cache keys and values are bounded tuples, frozen sets, dataclasses,
    timestamps, strings, and scalars. Tracking them on mutation keeps census
    constant-time without pretending structural index bytes include payloads.
    """

    visited = seen if seen is not None else set()
    identity = id(value)
    if identity in visited:
        return 0
    visited.add(identity)
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        return size + sum(
            _retained_size(key, seen=visited) + _retained_size(item, seen=visited)
            for key, item in value.items()
        )
    if isinstance(value, tuple | list | set | frozenset):
        return size + sum(_retained_size(item, seen=visited) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return size + sum(
            _retained_size(getattr(value, field.name), seen=visited) for field in fields(value)
        )
    return size


_DIRECT_MUTABLE_ANNOTATION_TOKENS = (
    "BoundedRuntimeCache[",
    "EmailArtifactManifestSpool",
    "ExpiringIndex[",
    "ProductionProcessRuntimeCaches",
    "dict[",
    "list[",
    "set[",
)
_DIRECT_MUTABLE_CONSTRUCTORS = {
    "BoundedRuntimeCache",
    "Counter",
    "EmailArtifactManifestSpool",
    "ExpiringIndex",
    "build_production_process_runtime_caches",
    "dict",
    "list",
    "set",
}
_DIRECT_MUTATOR_METHODS = {
    "__setitem__",
    "add",
    "append",
    "clear",
    "discard",
    "extend",
    "insert",
    "pop",
    "popitem",
    "redeadline",
    "remove",
    "reverse",
    "set",
    "setdefault",
    "sort",
    "update",
}


def _self_field_name(node: ast.expr) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return node.attr
    return None


def _self_subscript_field_name(node: ast.expr) -> str | None:
    if not isinstance(node, ast.Subscript):
        return None
    value = node.value
    while isinstance(value, ast.Subscript):
        value = value.value
    return _self_field_name(value)


def _self_dict_field_name(node: ast.expr) -> str | None:
    if not isinstance(node, ast.Subscript):
        return None
    if not (
        isinstance(node.value, ast.Attribute)
        and node.value.attr == "__dict__"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "self"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return None
    return node.slice.value


def _annotation_is_direct_mutable(annotation: ast.expr | None) -> bool:
    if annotation is None:
        return False
    rendered = ast.unparse(annotation)
    return any(token in rendered for token in _DIRECT_MUTABLE_ANNOTATION_TOKENS)


def _expression_is_direct_mutable(
    value: ast.expr | None,
    *,
    mutable_locals: set[str],
) -> bool:
    if value is None:
        return False
    if isinstance(value, ast.Name) and value.id in mutable_locals:
        return True
    for candidate in ast.walk(value):
        if isinstance(
            candidate, ast.Dict | ast.DictComp | ast.List | ast.ListComp | ast.Set | ast.SetComp
        ):
            return True
        if not isinstance(candidate, ast.Call):
            continue
        if (
            isinstance(candidate.func, ast.Name)
            and candidate.func.id in _DIRECT_MUTABLE_CONSTRUCTORS
        ):
            return True
        if (
            isinstance(candidate.func, ast.Name)
            and candidate.func.id == "getattr"
            and len(candidate.args) >= 3
            and isinstance(candidate.args[2], ast.Dict | ast.List | ast.Set)
        ):
            return True
    return False


def discover_activity_generator_mutable_fields(
    class_source: str,
) -> tuple[ActivityGeneratorMutableFieldDiscovery, ...]:
    """Discover direct mutable fields across the complete class body.

    The inventory is intentionally whole-class rather than ``__init__``-only.
    It follows simple local aliases used by lazy ``getattr`` initialization and
    records subscript/mutator writes even when creation happens elsewhere. It
    inventories direct retained containers and the explicit bounded cache
    wrappers; subsystem-owning managers expose their own independent censuses.
    """

    tree = ast.parse(class_source)
    class_nodes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    if len(class_nodes) != 1:
        raise ValueError("Expected source for exactly one ActivityGenerator class")
    class_node = class_nodes[0]
    if class_node.name != "ActivityGenerator":
        raise ValueError("Mutable-field inventory requires ActivityGenerator source")

    evidence: dict[str, list[tuple[int, str, str]]] = {}

    def record(field_name: str, node: ast.AST, method_name: str, kind: str) -> None:
        if field_name == "__dict__":
            return
        evidence.setdefault(field_name, []).append((node.lineno, method_name, kind))

    for method in (
        node for node in class_node.body if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ):
        mutable_locals: set[str] = set()
        # Resolve the small lazy-initialization alias patterns to a fixed point.
        changed = True
        while changed:
            changed = False
            for node in ast.walk(method):
                target: ast.expr | None = None
                annotation: ast.expr | None = None
                value: ast.expr | None = None
                if isinstance(node, ast.AnnAssign):
                    target = node.target
                    annotation = node.annotation
                    value = node.value
                elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                    value = node.value
                if not isinstance(target, ast.Name) or target.id in mutable_locals:
                    continue
                if _annotation_is_direct_mutable(annotation) or _expression_is_direct_mutable(
                    value,
                    mutable_locals=mutable_locals,
                ):
                    mutable_locals.add(target.id)
                    changed = True

        for node in ast.walk(method):
            if isinstance(node, ast.AnnAssign):
                field_name = _self_field_name(node.target)
                if field_name is not None and (
                    _annotation_is_direct_mutable(node.annotation)
                    or _expression_is_direct_mutable(node.value, mutable_locals=mutable_locals)
                ):
                    record(field_name, node, method.name, "assignment")
                subscript_field = _self_subscript_field_name(node.target)
                if subscript_field is not None:
                    record(subscript_field, node, method.name, "subscript_write")
                dict_field = _self_dict_field_name(node.target)
                if dict_field is not None and _expression_is_direct_mutable(
                    node.value,
                    mutable_locals=mutable_locals,
                ):
                    record(dict_field, node, method.name, "assignment")
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    field_name = _self_field_name(target)
                    if field_name is not None and _expression_is_direct_mutable(
                        node.value,
                        mutable_locals=mutable_locals,
                    ):
                        record(field_name, node, method.name, "assignment")
                    subscript_field = _self_subscript_field_name(target)
                    if subscript_field is not None:
                        record(subscript_field, node, method.name, "subscript_write")
                    dict_field = _self_dict_field_name(target)
                    if dict_field is not None and _expression_is_direct_mutable(
                        node.value,
                        mutable_locals=mutable_locals,
                    ):
                        record(dict_field, node, method.name, "assignment")
            elif isinstance(node, ast.AugAssign):
                field_name = _self_field_name(node.target) or _self_subscript_field_name(
                    node.target
                )
                if field_name is not None:
                    record(field_name, node, method.name, "augmented_write")
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    field_name = _self_subscript_field_name(target)
                    if field_name is not None:
                        record(field_name, node, method.name, "delete")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                field_name = _self_field_name(node.func.value)
                if field_name is not None and node.func.attr in _DIRECT_MUTATOR_METHODS:
                    record(field_name, node, method.name, node.func.attr)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "setattr"
                and len(node.args) == 3
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "self"
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and _expression_is_direct_mutable(
                    node.args[2],
                    mutable_locals=mutable_locals,
                )
            ):
                record(node.args[1].value, node, method.name, "assignment")

    discoveries: list[ActivityGeneratorMutableFieldDiscovery] = []
    for field_name, rows in sorted(evidence.items()):
        rows = sorted(set(rows))
        methods = tuple(sorted({method for _line, method, _kind in rows}))
        discoveries.append(
            ActivityGeneratorMutableFieldDiscovery(
                field_name=field_name,
                first_line=min(line for line, _method, _kind in rows),
                methods=methods,
                mutation_kinds=tuple(sorted({kind for _line, _method, kind in rows})),
                lazy="__init__" not in methods,
            )
        )
    return tuple(discoveries)


def snapshot_activity_generator_mutable_fields(
    generator: object,
) -> tuple[ActivityGeneratorMutableFieldSnapshot, ...]:
    """Snapshot every materialized direct mutable field on one generator.

    Aliases into ``ProductionProcessRuntimeCaches`` are grouped by a stable
    lexical owner so retained bytes are not mistaken for independent storage.
    The snapshot is diagnostic and never walks subsystem managers.
    """

    policies = {
        policy.field_name: policy for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
    }
    mutable_values: dict[str, object] = {
        name: value
        for name, value in vars(generator).items()
        if isinstance(
            value,
            dict
            | list
            | set
            | BoundedRuntimeCache
            | EmailArtifactManifestSpool
            | ExpiringIndex
            | ProductionProcessRuntimeCaches,
        )
    }
    aliases: dict[int, list[str]] = {}
    for name, value in mutable_values.items():
        aliases.setdefault(id(value), []).append(name)
    process_bundle = mutable_values.get("_production_process_runtime_caches")
    process_cache_ids = (
        {id(cache) for _name, cache in process_bundle.items()}
        if isinstance(process_bundle, ProductionProcessRuntimeCaches)
        else set()
    )

    snapshots: list[ActivityGeneratorMutableFieldSnapshot] = []
    for name, value in sorted(mutable_values.items()):
        policy = policies.get(name)
        if policy is None:
            raise ValueError(f"Mutable ActivityGenerator field has no retention policy: {name}")
        if isinstance(value, ProductionProcessRuntimeCaches):
            census = value.census(watermark=None, estimate_bytes=True)
            entries = census.physical_records
            retained_bytes = census.estimated_bytes
        elif isinstance(value, BoundedRuntimeCache):
            entries = len(value)
            metrics = value.metrics(estimate_bytes=True)
            retained_bytes = metrics.estimated_bytes + value.estimated_payload_bytes
        elif isinstance(value, ExpiringIndex):
            entries = len(value)
            retained_bytes = value.metrics(estimate_bytes=True).estimated_bytes
        elif isinstance(value, EmailArtifactManifestSpool):
            census = value.census()
            entries = census.retained_rows
            retained_bytes = 0
        else:
            entries = len(value)
            retained_bytes = _retained_size(value)
        snapshots.append(
            ActivityGeneratorMutableFieldSnapshot(
                field_name=name,
                value_type=type(value).__name__,
                entries=entries,
                retained_bytes=retained_bytes,
                alias_owner=(
                    "_production_process_runtime_caches"
                    if id(value) in process_cache_ids
                    else min(aliases[id(value)])
                ),
                policy_disposition=policy.disposition,
            )
        )
    return tuple(snapshots)


@dataclass(frozen=True, slots=True)
class _RuntimeCacheRecord(Generic[V]):
    value: V
    deadline_seconds: float
    retained_bytes: int


class BoundedRuntimeCache(Generic[K, V]):
    """Exact map with paged expiry and observationally eager watermarks.

    Physical reclamation is bounded. An entry left behind after one page is
    nevertheless invisible once its deadline is behind the logical watermark,
    making bounded reclamation observationally equivalent to eager expiry.
    Deliberately no iterator/items/values API is exposed: callers must use exact
    keys or bounded expiry pages.
    """

    def __init__(self, *, default_deadline: Callable[[V], datetime | float | int]) -> None:
        self._default_deadline = default_deadline
        self._records: CompactIndexedStore[K, _RuntimeCacheRecord[V]] = CompactIndexedStore()
        self._deadlines = PackedHandleExpiryIndex()
        self._watermark_seconds: float | None = None
        self._lookup_candidates_inspected = 0
        self._expiry_work = 0
        self._high_water_entries = 0
        self._estimated_payload_bytes = 0

    def __len__(self) -> int:
        """Return physically retained entries in constant time."""

        return len(self._records)

    def __bool__(self) -> bool:
        return bool(self._records)

    def __contains__(self, key: object) -> bool:
        return self.get(key) is not None  # type: ignore[arg-type]

    def __getitem__(self, key: K) -> V:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: K, value: V) -> None:
        self.set(key, value, deadline=self._default_deadline(value))

    def _visible(self, record: _RuntimeCacheRecord[V]) -> bool:
        watermark = self._watermark_seconds
        return watermark is None or record.deadline_seconds >= watermark

    def _record(self, key: K) -> _RuntimeCacheRecord[V] | None:
        try:
            return self._records[key]
        except KeyError:
            return None

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return one exact visible entry and account one candidate at most."""

        record = self._record(key)
        if record is None:
            return default
        self._lookup_candidates_inspected += 1
        return record.value if self._visible(record) else default

    def raw_get(self, key: K, default: V | None = None) -> V | None:
        """Return one physically retained entry for exact expiry bookkeeping."""

        record = self._record(key)
        return default if record is None else record.value

    def set(
        self,
        key: K,
        value: V,
        *,
        deadline: datetime | float | int,
    ) -> None:
        """Insert or replace one exact entry and versioned expiry deadline."""

        deadline_value = deadline_seconds(deadline)
        retained_bytes = _retained_size((key, value))
        record = _RuntimeCacheRecord(value, deadline_value, retained_bytes)
        prior = self._record(key)
        self._records[key] = record
        handle = self._records.handle_for(key)
        self._deadlines.set(handle, deadline_value)
        if prior is None:
            self._high_water_entries = max(self._high_water_entries, len(self._records))
        else:
            self._estimated_payload_bytes -= prior.retained_bytes
        self._estimated_payload_bytes += retained_bytes

    def redeadline(self, key: K, *, deadline: datetime | float | int) -> bool:
        """Move one exact retained entry to a new deadline without a scan."""

        record = self._record(key)
        if record is None:
            return False
        self.set(key, record.value, deadline=deadline)
        return True

    def pop(self, key: K, default: V | None = None) -> V | None:
        """Remove one exact entry."""

        record = self._record(key)
        if record is None:
            return default
        handle = self._records.handle_for(key)
        self._deadlines.pop(handle)
        del self._records[key]
        self._estimated_payload_bytes -= record.retained_bytes
        self._reset_empty_backing()
        return record.value

    def _reset_empty_backing(self) -> None:
        if self._records:
            return
        self._records = CompactIndexedStore()
        self._deadlines = PackedHandleExpiryIndex()
        self._estimated_payload_bytes = 0

    def advance_watermark(
        self,
        cutoff: datetime,
        *,
        limit: int,
    ) -> tuple[tuple[K, V], ...]:
        """Advance logical visibility and reclaim at most one bounded page."""

        if limit <= 0:
            raise ValueError("Runtime cache watermark page limit must be positive")
        cutoff_seconds = deadline_seconds(cutoff)
        if self._watermark_seconds is not None and cutoff_seconds < self._watermark_seconds:
            raise ValueError("Runtime cache watermark cannot move backward")
        self._watermark_seconds = cutoff_seconds
        expired_handles = self._deadlines.expire_before_page(
            cutoff_seconds,
            inclusive=False,
            limit=limit,
        )
        expired: list[tuple[K, V]] = []
        for handle, _deadline in expired_handles:
            try:
                key = self._records.key_by_handle(handle)
                record = self._records.get_by_handle(handle)
            except KeyError:  # pragma: no cover - synchronized handle/deadline invariant
                continue
            del self._records[key]
            self._estimated_payload_bytes -= record.retained_bytes
            expired.append((key, record.value))
        self._expiry_work += len(expired)
        self._deadlines.compact(max_slots=limit)
        self._records.compact_primary(max_slots=limit)
        self._reset_empty_backing()
        return tuple(expired)

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return structural index metrics without iterating retained entries."""

        records = self._records.metrics(estimate_bytes=estimate_bytes)
        deadlines = self._deadlines.metrics(estimate_bytes=estimate_bytes)
        return IndexMetrics(
            live_entries=len(self._records),
            backing_entries=deadlines.backing_entries,
            stale_entries=deadlines.stale_entries,
            allocated_slots=records.allocated_slots,
            high_water_mark=self._high_water_entries,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
            compaction_work=deadlines.compaction_work,
            compaction_seconds=deadlines.compaction_seconds,
            compaction_pending=deadlines.compaction_pending,
            estimated_bytes=records.estimated_bytes + deadlines.estimated_bytes,
            primary_map_entries=records.primary_map_entries,
            primary_map_backing_bytes=records.primary_map_backing_bytes,
            primary_compaction_pending=records.primary_compaction_pending,
            primary_compaction_rotations=records.primary_compaction_rotations,
            primary_compaction_work=records.primary_compaction_work,
            primary_compaction_seconds=records.primary_compaction_seconds,
        )

    @property
    def lookup_candidates_inspected(self) -> int:
        """Return cumulative exact lookup candidates."""

        return self._lookup_candidates_inspected

    @property
    def watermark_seconds(self) -> float | None:
        """Return the current logical watermark without scanning retained entries."""

        return self._watermark_seconds

    @property
    def expiry_work(self) -> int:
        """Return cumulative physically reclaimed entries."""

        return self._expiry_work

    @property
    def estimated_payload_bytes(self) -> int:
        """Return mutation-maintained retained key/value bytes."""

        return self._estimated_payload_bytes

    @property
    def watermark(self) -> datetime | None:
        """Return the current logical watermark."""

        if self._watermark_seconds is None:
            return None
        return _EPOCH + (datetime.fromtimestamp(self._watermark_seconds, tz=UTC) - _EPOCH)


@dataclass(frozen=True, slots=True)
class ProcessRuntimeCacheCensus:
    """Constant-time aggregate metrics for process-adjacent runtime caches."""

    cache_count: int
    physical_records: int
    live_entries: int
    backing_entries: int
    stale_entries: int
    high_water_entries: int
    maximum_cache_entries: int
    estimated_bytes: int
    estimated_index_bytes: int
    lookup_candidates_inspected: int
    expiry_work: int
    reverse_subjects: int
    reverse_bindings: int
    reverse_high_water: int
    reverse_backing_entries: int
    reverse_stale_entries: int
    reverse_estimated_bytes: int
    reverse_estimated_index_bytes: int
    reverse_lookup_candidates_inspected: int
    watermark: datetime | None
    families: tuple[ProcessRuntimeCacheFamilyCensus, ...]


def runtime_cache_census(
    caches: Iterable[BoundedRuntimeCache[object, object]],
    *,
    watermark: datetime | None,
    estimate_bytes: bool = False,
    reverse_subjects: int = 0,
    reverse_bindings: int = 0,
    reverse_high_water: int = 0,
    reverse_backing_entries: int = 0,
    reverse_stale_entries: int = 0,
    reverse_estimated_bytes: int = 0,
    reverse_estimated_index_bytes: int = 0,
    reverse_lookup_candidates_inspected: int = 0,
    names: Iterable[str] | None = None,
) -> ProcessRuntimeCacheCensus:
    """Aggregate a fixed cache collection without inspecting any entry."""

    cache_tuple = tuple(caches)
    metrics = tuple(cache.metrics(estimate_bytes=estimate_bytes) for cache in cache_tuple)
    name_tuple = (
        tuple(names)
        if names is not None
        else tuple(f"cache_{ordinal}" for ordinal in range(len(cache_tuple)))
    )
    if len(name_tuple) != len(cache_tuple):
        raise ValueError("Runtime cache census names must match the fixed cache collection")
    family_census = tuple(
        ProcessRuntimeCacheFamilyCensus(
            name=name,
            live_entries=metric.live_entries,
            backing_entries=metric.backing_entries,
            stale_entries=metric.stale_entries,
            high_water_mark=metric.high_water_mark,
            # IndexMetrics accounts the structural primary store and expiry
            # index. Payload referents are deliberately excluded so this stays
            # constant-time; workload probes pair it with measured RSS.
            estimated_bytes=metric.estimated_bytes + cache.estimated_payload_bytes,
            estimated_index_bytes=metric.estimated_bytes,
            lookup_candidates_inspected=cache.lookup_candidates_inspected,
            expiry_work=cache.expiry_work,
        )
        for name, cache, metric in zip(name_tuple, cache_tuple, metrics, strict=True)
    )
    live_entries = sum(metric.live_entries for metric in metrics)
    physical_records = live_entries + reverse_bindings
    return ProcessRuntimeCacheCensus(
        cache_count=len(cache_tuple),
        physical_records=physical_records,
        live_entries=live_entries,
        backing_entries=sum(metric.backing_entries for metric in metrics),
        stale_entries=sum(metric.stale_entries for metric in metrics),
        high_water_entries=sum(metric.high_water_mark for metric in metrics),
        maximum_cache_entries=max((metric.live_entries for metric in metrics), default=0),
        estimated_bytes=(
            sum(family.estimated_bytes for family in family_census) + reverse_estimated_bytes
        ),
        estimated_index_bytes=(
            sum(family.estimated_index_bytes for family in family_census)
            + reverse_estimated_index_bytes
        ),
        lookup_candidates_inspected=sum(cache.lookup_candidates_inspected for cache in cache_tuple),
        expiry_work=sum(cache.expiry_work for cache in cache_tuple),
        reverse_subjects=reverse_subjects,
        reverse_bindings=reverse_bindings,
        reverse_high_water=reverse_high_water,
        reverse_backing_entries=reverse_backing_entries,
        reverse_stale_entries=reverse_stale_entries,
        reverse_estimated_bytes=reverse_estimated_bytes,
        reverse_estimated_index_bytes=reverse_estimated_index_bytes,
        reverse_lookup_candidates_inspected=reverse_lookup_candidates_inspected,
        watermark=watermark,
        families=family_census,
    )


PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES: tuple[ProcessRuntimeCacheFamilySpec, ...] = (
    ProcessRuntimeCacheFamilySpec(
        "terminated",
        "(hostname, pid, process_start)",
        "terminated_at",
        "terminated_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "terminated_latest",
        "(hostname, pid)",
        "(process_start, terminated_at)",
        "terminated_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "source_create",
        "(hostname, pid, process_start)",
        "source_create_at",
        "source_create_at or process close",
    ),
    ProcessRuntimeCacheFamilySpec(
        "source_create_latest",
        "(hostname, pid)",
        "(process_start, source_create_at)",
        "source_create_at or process close",
    ),
    ProcessRuntimeCacheFamilySpec(
        "source_terminate",
        "(hostname, pid, process_start)",
        "source_terminate_at",
        "source_terminate_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "source_terminate_latest",
        "(hostname, pid)",
        "(process_start, source_terminate_at)",
        "source_terminate_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "session_source_terminate",
        "(session_object_id, format_name)",
        "latest_source_terminate_at",
        "latest_source_terminate_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "loaded_modules",
        "(hostname, pid, process_start)",
        "frozenset[module_path]",
        "process close or generation window end",
    ),
    ProcessRuntimeCacheFamilySpec(
        "ssh_responder",
        "transport_tuple_digest",
        "RuntimeProcessBinding",
        "process close or generation window end",
    ),
    ProcessRuntimeCacheFamilySpec(
        "smb_responder",
        "transport_tuple_digest",
        "RuntimeProcessBinding",
        "process close or generation window end",
    ),
    ProcessRuntimeCacheFamilySpec(
        "ssh_pid_alias",
        "(hostname, compatibility_pid)",
        "RuntimeProcessBinding",
        "process close or generation window end",
    ),
    ProcessRuntimeCacheFamilySpec(
        "ssh_ready",
        "session_object_id",
        "shell_ready_at",
        "shell_ready_at + 24h",
    ),
    ProcessRuntimeCacheFamilySpec(
        "apt_frontend",
        "hostname",
        "(pid, termination_at)",
        "termination_at",
    ),
    ProcessRuntimeCacheFamilySpec(
        "cli_exe",
        "(hostname, principal, logon_id, executable)",
        "last_launch_at",
        "last_launch_at + 9s",
    ),
    ProcessRuntimeCacheFamilySpec(
        "cli_command",
        "(hostname, principal, logon_id, executable, command)",
        "last_launch_at",
        "last_launch_at + 75s",
    ),
    ProcessRuntimeCacheFamilySpec(
        "preferred_browser_session",
        "(hostname, principal, logon_id)",
        "canonical_executable",
        "session close or bounded 24h fallback",
    ),
    ProcessRuntimeCacheFamilySpec(
        "browser_launch_session",
        "(hostname, principal, logon_id)",
        "last_launch_at",
        "last_launch_at + 18s",
    ),
)


_PROCESS_CACHE_FIELDS = (
    "_production_process_runtime_caches",
    "_terminated_process_times",
    "_terminated_process_latest",
    "_ssh_session_ready_times",
    "_ssh_responder_pids",
    "_smb_responder_pids",
    "_ssh_pid_aliases",
    "_linux_apt_frontends",
    "_loaded_modules_by_process",
    "_last_one_shot_cli_launch_by_exe",
    "_last_one_shot_cli_launch_by_command",
    "_preferred_browser_by_session",
    "_last_browser_launch_by_session",
    "_process_source_create_times",
    "_process_source_terminate_times",
    "_process_source_create_latest",
    "_process_source_terminate_latest",
    "_session_process_source_terminate_times",
)
_BOUNDED_TEMPORAL_FIELDS = (
    "_recent_connection_tuples",
    "_ssh_source_ports",
    "_dns_cache",
    "_bash_history_user_seconds",
    "_top_level_browser_launch_targets",
    "_privileged_auth_occurrences",
    "_failed_logon_attempt_times",
)
_SCENARIO_COMPILED_FIELDS = (
    "sid_registry",
    "_ip_to_system",
    "_systems_by_hostname",
    "_proxy_service_accounts",
    "_created_account_sids",
    "_email_corpus_cache",
    # Engine-injected direct collections. They do not appear in the
    # ActivityGenerator class AST, so whole-instance inventory is the guard.
    "_system_pids",
    "_all_system_ips",
    "_db_servers",
    "_dns_server_ips",
    "_dc_hostnames",
    "_dc_ips",
    "_dc_systems",
    "_users_by_username",
    "_proxy_routes",
)
_OCCURRENCE_OR_DRAIN_FIELDS = (
    "_process_close_in_progress",
    "_expanding_types",
    "_postfix_queue_states",
    "_failed_logon_attempt_pending",
)
_SESSION_SCOPED_FIELDS = (
    "_bash_history_next_time",
    "_bash_history_command_counts",
    "_bash_history_quick_streaks",
    "_linux_local_logon_syslog_sessions",
    "_linux_sudo_tty_assignments",
    "_linux_sudo_tty_owners",
    "_linux_sudo_tty_sessions",
    "_linux_sudo_tty_available",
    "_linux_sudo_tty_keys_by_logon_id",
    "_last_workstation_lock_time",
)
_EXTERNAL_SPOOL_FIELDS = ("_email_artifact_manifest_spool",)
_BOUNDED_LEGACY_FIELDS = (
    "_user_process_history",
    "_proxy_auth_session_deadlines",
    "_kerberos_source_port_reservations",
    "_kerberos_tgt_cache_until",
    "_visible_account_created_at",
    "_visible_account_kerberos_transport_emitted",
    "_next_icmp_observation_ts_us",
    "_ntp_association_profiles",
    "_ntp_server_response_profiles",
    "_ntp_last_parser_times",
    "_linux_shell_last_session_close",
    "_postfix_qmgr_pid_cache",
)
_DEFINITE_GROWING_FIELDS: tuple[str, ...] = ()
_CONDITIONAL_GROWING_FIELDS: tuple[str, ...] = ()
REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS = (
    "_dns_observation_cache",
    "_dns_resolver_rrset_cache",
    "_kerberos_cache",
    "_linux_local_logind_session_ids",
    "_tls_cert_validity",
    "_tls_intermediate_profiles",
    "_tls_ocsp_windows",
    "_tls_ocsp_response_sizes",
    "_tls_seen_client_server_pairs",
    "_tls_seen_server_names",
)
REMOVED_DURATION_SIZED_ACTIVITY_GENERATOR_FIELDS = ("_email_artifact_manifest",)

ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES: tuple[
    ActivityGeneratorMutableRetentionPolicy,
    ...,
] = (
    tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="production_process_runtime_bundle",
            horizon="exact entry deadline with paged watermark expiry",
            disposition=ActivityGeneratorRetentionDisposition.BOUNDED,
            evidence="packed exact cache with explicit deadline and bounded watermark page",
        )
        for field_name in _PROCESS_CACHE_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="bounded_temporal_index",
            horizon="explicit temporal cutoff",
            disposition=ActivityGeneratorRetentionDisposition.BOUNDED,
            evidence="expiry-index ownership or an enforced hard live-entry cap",
        )
        for field_name in _BOUNDED_TEMPORAL_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="scenario_compilation",
            horizon="immutable generation scenario",
            disposition=ActivityGeneratorRetentionDisposition.SCENARIO_STATIC,
            evidence="cardinality derives from compiled scenario entities or catalogs",
        )
        for field_name in _SCENARIO_COMPILED_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="occurrence_or_bounded_drain",
            horizon="one occurrence or active drain page",
            disposition=ActivityGeneratorRetentionDisposition.TRANSIENT,
            evidence="balanced add/remove recursion guard or one active close page",
        )
        for field_name in _OCCURRENCE_OR_DRAIN_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="session_close_retention_release",
            horizon="owning live session or scenario-static host/user fallback",
            disposition=ActivityGeneratorRetentionDisposition.BOUNDED,
            evidence="exact reverse-routed rows are deleted only after accepted session close",
        )
        for field_name in _SESSION_SCOPED_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="disk_backed_streaming_spool",
            horizon="one scalar/connection owner; payload rows are externalized",
            disposition=ActivityGeneratorRetentionDisposition.TRANSIENT,
            evidence="constant-time census reports zero Python-retained manifest rows",
        )
        for field_name in _EXTERNAL_SPOOL_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="legacy_direct_bounded_state",
            horizon="fixed entity domain, fixed per-key cap, or overwrite-only current value",
            disposition=ActivityGeneratorRetentionDisposition.BOUNDED,
            evidence="key domain is scenario-static and every per-key value is capped or replaced",
        )
        for field_name in _BOUNDED_LEGACY_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="duration_stability_migration_debt",
            horizon="none; grows with canonical occurrences, sessions, ports, messages, or hours",
            disposition=ActivityGeneratorRetentionDisposition.DEFINITE_GROWTH,
            evidence="production key contains an occurrence/session/hour identity and has no expiry",
        )
        for field_name in _DEFINITE_GROWING_FIELDS
    )
    + tuple(
        ActivityGeneratorMutableRetentionPolicy(
            field_name=field_name,
            owner="cardinality_retention_migration_debt",
            horizon="none; growth depends on unbounded source, hostname, URL, or stale-session keys",
            disposition=ActivityGeneratorRetentionDisposition.CONDITIONAL_GROWTH,
            evidence="per-key state is capped or singular but the retained key universe is not",
        )
        for field_name in _CONDITIONAL_GROWING_FIELDS
    )
)


@dataclass(frozen=True, slots=True)
class _ProcessRuntimeReverseRoute:
    process_key: tuple[str, int, datetime | None]
    cache_name: str
    cache_key: Hashable
    retained_bytes: int


class _ProcessRuntimeReverseIndex:
    """Exact compact process-to-cache route index with bounded subject pages."""

    def __init__(self) -> None:
        self._routes: CompactIndexedStore[
            tuple[tuple[str, int, datetime | None], str, Hashable],
            _ProcessRuntimeReverseRoute,
        ] = self._new_store()
        self._lookup_candidates_inspected = 0
        self._estimated_payload_bytes = 0

    @staticmethod
    def _new_store() -> CompactIndexedStore[
        tuple[tuple[str, int, datetime | None], str, Hashable],
        _ProcessRuntimeReverseRoute,
    ]:
        return CompactIndexedStore(process=lambda route: route.process_key)

    def _reset_empty_backing(self) -> None:
        if self._routes:
            return
        self._routes = self._new_store()
        self._estimated_payload_bytes = 0

    def bind(
        self,
        process_key: tuple[str, int, datetime | None],
        cache_name: str,
        cache_key: Hashable,
    ) -> bool:
        route_key = (process_key, cache_name, cache_key)
        if route_key in self._routes:
            return False
        record = _ProcessRuntimeReverseRoute(
            process_key=process_key,
            cache_name=cache_name,
            cache_key=cache_key,
            retained_bytes=0,
        )
        retained_bytes = _retained_size((route_key, record))
        record = _ProcessRuntimeReverseRoute(
            process_key=process_key,
            cache_name=cache_name,
            cache_key=cache_key,
            retained_bytes=retained_bytes,
        )
        self._routes[route_key] = record
        self._estimated_payload_bytes += retained_bytes
        return True

    def unbind(
        self,
        process_key: tuple[str, int, datetime | None],
        cache_name: str,
        cache_key: Hashable,
    ) -> bool:
        route_key = (process_key, cache_name, cache_key)
        if route_key not in self._routes:
            return False
        record = self._routes[route_key]
        del self._routes[route_key]
        self._estimated_payload_bytes -= record.retained_bytes
        self._reset_empty_backing()
        return True

    def pop_subject_page(
        self,
        process_key: tuple[str, int, datetime | None],
        *,
        limit: int,
    ) -> tuple[tuple[tuple[str, Hashable], ...], bool]:
        if limit <= 0:
            raise ValueError("Process-runtime reverse page limit must be positive")
        handles, _cursor = self._routes.find_handle_page(
            "process",
            process_key,
            limit=limit,
        )
        self._lookup_candidates_inspected += len(handles)
        routes: list[tuple[str, Hashable]] = []
        for handle in handles:
            route = self._routes.get_by_handle(handle)
            routes.append((route.cache_name, route.cache_key))
            del self._routes[(route.process_key, route.cache_name, route.cache_key)]
            self._estimated_payload_bytes -= route.retained_bytes
        self._routes.compact_primary(max_slots=limit)
        self._reset_empty_backing()
        return tuple(routes), self._routes.count("process", process_key) > 0

    def subject_count(self, process_key: tuple[str, int, datetime | None]) -> int:
        """Return one process route cardinality in constant time."""

        return self._routes.count("process", process_key)

    def metrics(self, *, estimate_bytes: bool) -> IndexMetrics:
        return self._routes.metrics(estimate_bytes=estimate_bytes)

    @property
    def lookup_candidates_inspected(self) -> int:
        return self._lookup_candidates_inspected

    @property
    def estimated_payload_bytes(self) -> int:
        return self._estimated_payload_bytes


class ProductionProcessRuntimeCaches:
    """Fixed production cache bundle shared by generation and scale probes.

    The bundle exposes no entry iterator. Its fixed family tuple, census, probe
    loader, and bounded watermark page are the only cross-family operations.
    """

    def __init__(
        self,
        caches: tuple[tuple[str, BoundedRuntimeCache[Hashable, object]], ...],
    ) -> None:
        expected = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)
        actual = tuple(name for name, _cache in caches)
        if actual != expected:
            raise ValueError(
                "Production process-runtime cache families do not match the canonical order"
            )
        self._items = caches
        self._by_name = dict(caches)
        self._reverse = _ProcessRuntimeReverseIndex()

    @property
    def family_specs(self) -> tuple[ProcessRuntimeCacheFamilySpec, ...]:
        """Return immutable public key/value/deadline shapes."""

        return PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES

    def items(self) -> tuple[tuple[str, BoundedRuntimeCache[Hashable, object]], ...]:
        """Return the fixed small family tuple, never retained cache entries."""

        return self._items

    def cache(self, name: str) -> BoundedRuntimeCache[Hashable, object]:
        """Return one exact named production cache family."""

        try:
            return self._by_name[name]
        except KeyError as exc:
            raise KeyError(f"Unknown process-runtime cache family: {name}") from exc

    def census(
        self,
        *,
        watermark: datetime | None,
        estimate_bytes: bool = False,
    ) -> ProcessRuntimeCacheCensus:
        """Return aggregate and per-family constant-time structural metrics."""

        reverse = self._reverse.metrics(estimate_bytes=estimate_bytes)
        return runtime_cache_census(
            (cast(BoundedRuntimeCache[object, object], cache) for _name, cache in self._items),
            names=(name for name, _cache in self._items),
            watermark=watermark,
            estimate_bytes=estimate_bytes,
            reverse_subjects=reverse.secondary_buckets,
            reverse_bindings=reverse.live_entries,
            reverse_high_water=reverse.high_water_mark,
            reverse_backing_entries=reverse.backing_entries,
            reverse_stale_entries=reverse.stale_entries,
            reverse_estimated_bytes=(
                reverse.estimated_bytes + self._reverse.estimated_payload_bytes
            ),
            reverse_estimated_index_bytes=reverse.estimated_bytes,
            reverse_lookup_candidates_inspected=self._reverse.lookup_candidates_inspected,
        )

    def bind_process_route(
        self,
        process_key: tuple[str, int, datetime | None],
        cache_name: str,
        cache_key: Hashable,
    ) -> bool:
        """Bind one exact process-owned cache route, idempotently."""

        if cache_name not in self._by_name:
            raise KeyError(f"Unknown process-runtime cache family: {cache_name}")
        return self._reverse.bind(process_key, cache_name, cache_key)

    def unbind_process_route(
        self,
        process_key: tuple[str, int, datetime | None],
        cache_name: str,
        cache_key: Hashable,
    ) -> bool:
        """Remove one exact process-owned cache route."""

        return self._reverse.unbind(process_key, cache_name, cache_key)

    def pop_process_routes_page(
        self,
        process_key: tuple[str, int, datetime | None],
        *,
        limit: int,
    ) -> tuple[tuple[tuple[str, Hashable], ...], bool]:
        """Pop one bounded page of exact routes for a closing process."""

        return self._reverse.pop_subject_page(process_key, limit=limit)

    def process_route_count(self, process_key: tuple[str, int, datetime | None]) -> int:
        """Return one exact process route cardinality without scanning routes."""

        return self._reverse.subject_count(process_key)

    def advance_watermark_page(
        self,
        cutoff: datetime,
        *,
        limit: int,
    ) -> ProcessRuntimeCacheExpiryPage:
        """Expire at most ``limit`` records across the fixed family set.

        ``has_more`` is conservative when a family fills its allotment. A drain
        may therefore perform one final empty page, but never misses due state.
        """

        cache_count = len(self._items)
        if limit < cache_count:
            raise ValueError("Production cache watermark limit must cover every fixed cache family")
        quotient, remainder = divmod(limit, cache_count)
        expired_by_family: list[tuple[str, tuple[tuple[Hashable, object], ...]]] = []
        processed = 0
        has_more = False
        for ordinal, (name, cache) in enumerate(self._items):
            family_limit = quotient + (1 if ordinal < remainder else 0)
            expired = cache.advance_watermark(cutoff, limit=family_limit)
            if name in {"ssh_responder", "smb_responder", "ssh_pid_alias"}:
                for key, value in expired:
                    if isinstance(value, RuntimeProcessBinding):
                        self._reverse.unbind(value.process_key, name, key)
            expired_by_family.append((name, expired))
            processed += len(expired)
            has_more = has_more or len(expired) == family_limit
        return ProcessRuntimeCacheExpiryPage(
            expired_by_family=tuple(expired_by_family),
            processed=processed,
            has_more=has_more,
        )

    def load_probe_entry(
        self,
        family: str,
        ordinal: int,
        at: datetime,
        *,
        owner: str = "probe-owner",
    ) -> ProcessRuntimeCacheLoadResult:
        """Load one representative production-shaped entry for a scale probe."""

        if ordinal < 0:
            raise ValueError("Process-runtime probe ordinal must be non-negative")
        timestamp = ensure_utc(at)
        process_start = timestamp - timedelta(seconds=1)
        binding = RuntimeProcessBinding(
            pid=10_000 + ordinal,
            process_key=(owner, 10_000 + ordinal, process_start),
        )
        key, value, deadline = self._probe_entry(
            family,
            ordinal,
            timestamp,
            owner=owner,
            binding=binding,
            process_start=process_start,
        )
        cache = self.cache(family)
        inserted = cache.raw_get(key) is None
        cache.set(key, value, deadline=deadline)
        if family in {"ssh_responder", "smb_responder", "ssh_pid_alias"}:
            self.bind_process_route(binding.process_key, family, key)
        return ProcessRuntimeCacheLoadResult(
            inserted=inserted,
            replaced=not inserted,
            key=key,
            deadline=deadline,
        )

    @staticmethod
    def _probe_entry(
        family: str,
        ordinal: int,
        timestamp: datetime,
        *,
        owner: str,
        binding: RuntimeProcessBinding,
        process_start: datetime,
    ) -> tuple[Hashable, object, datetime]:
        """Build one production-shaped probe entry without cross-family materialization."""

        process_key = (owner, binding.pid, process_start)
        latest_key = (owner, binding.pid)
        if family in {"terminated", "source_create", "source_terminate"}:
            return process_key, timestamp, timestamp
        if family in {
            "terminated_latest",
            "source_create_latest",
            "source_terminate_latest",
        }:
            return latest_key, (process_start, timestamp), timestamp
        if family == "session_source_terminate":
            return (f"session-{owner}-{ordinal}", "ecar"), timestamp, timestamp
        if family == "loaded_modules":
            return (
                process_key,
                frozenset({f"/module/{ordinal}.so"}),
                timestamp + timedelta(hours=1),
            )
        if family == "ssh_responder":
            return f"ssh:{owner}:{ordinal}", binding, timestamp
        if family == "smb_responder":
            return f"smb:{owner}:{ordinal}", binding, timestamp
        if family == "ssh_pid_alias":
            return (owner, ordinal), binding, timestamp
        if family == "ssh_ready":
            return (
                f"session-{owner}-{ordinal}",
                timestamp,
                timestamp + timedelta(days=1),
            )
        if family == "apt_frontend":
            return owner, (binding.pid, timestamp), timestamp
        if family == "cli_exe":
            return (
                (owner, "principal", f"0x{ordinal:x}", "powershell.exe"),
                timestamp,
                timestamp + timedelta(seconds=9),
            )
        if family == "cli_command":
            return (
                (
                    owner,
                    "principal",
                    f"0x{ordinal:x}",
                    "powershell.exe",
                    f"get-process -id {ordinal}",
                ),
                timestamp,
                timestamp + timedelta(seconds=75),
            )
        if family == "preferred_browser_session":
            return (
                (owner, "principal", f"0x{ordinal:x}"),
                "msedge.exe",
                timestamp + timedelta(hours=12),
            )
        if family == "browser_launch_session":
            return (
                (owner, "principal", f"0x{ordinal:x}"),
                timestamp,
                timestamp + timedelta(seconds=18),
            )
        raise KeyError(f"Unknown process-runtime cache family: {family}")


def build_production_process_runtime_caches(
    window_end: datetime,
) -> ProductionProcessRuntimeCaches:
    """Build the exact fixed cache family used by ``ActivityGenerator``."""

    canonical_end = ensure_utc(window_end)
    caches: tuple[tuple[str, BoundedRuntimeCache[Hashable, object]], ...] = (
        ("terminated", BoundedRuntimeCache(default_deadline=lambda value: cast(datetime, value))),
        (
            "terminated_latest",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(tuple[datetime | None, datetime], value)[1]
            ),
        ),
        (
            "source_create",
            BoundedRuntimeCache(default_deadline=lambda value: cast(datetime, value)),
        ),
        (
            "source_create_latest",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(tuple[datetime | None, datetime], value)[1]
            ),
        ),
        (
            "source_terminate",
            BoundedRuntimeCache(default_deadline=lambda value: cast(datetime, value)),
        ),
        (
            "source_terminate_latest",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(tuple[datetime | None, datetime], value)[1]
            ),
        ),
        (
            "session_source_terminate",
            BoundedRuntimeCache(default_deadline=lambda value: cast(datetime, value)),
        ),
        ("loaded_modules", BoundedRuntimeCache(default_deadline=lambda _value: canonical_end)),
        ("ssh_responder", BoundedRuntimeCache(default_deadline=lambda _value: canonical_end)),
        ("smb_responder", BoundedRuntimeCache(default_deadline=lambda _value: canonical_end)),
        ("ssh_pid_alias", BoundedRuntimeCache(default_deadline=lambda _value: canonical_end)),
        (
            "ssh_ready",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(datetime, value) + timedelta(days=1)
            ),
        ),
        (
            "apt_frontend",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(tuple[int, datetime], value)[1]
            ),
        ),
        (
            "cli_exe",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(datetime, value) + timedelta(seconds=9)
            ),
        ),
        (
            "cli_command",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(datetime, value) + timedelta(seconds=75)
            ),
        ),
        (
            "preferred_browser_session",
            BoundedRuntimeCache(default_deadline=lambda _value: canonical_end),
        ),
        (
            "browser_launch_session",
            BoundedRuntimeCache(
                default_deadline=lambda value: cast(datetime, value) + timedelta(seconds=18)
            ),
        ),
    )
    return ProductionProcessRuntimeCaches(caches)
