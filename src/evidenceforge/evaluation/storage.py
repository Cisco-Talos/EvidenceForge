"""Run-local hybrid collections for exact evaluation with bounded retained state.

Only data serialized by this process is deserialized. The disposable database lives in a private
TemporaryDirectory; it is never accepted as an input or reused as a persistent cache.
"""

from __future__ import annotations

import pickle
import sqlite3
import struct
import sys
import tempfile
import weakref
from bisect import bisect_left, bisect_right
from collections import OrderedDict, defaultdict
from collections.abc import (
    Callable,
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSet,
    Sequence,
)
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, overload

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.exceptions import EvaluationError

T = TypeVar("T")
K = TypeVar("K")
_ACTIVE: ContextVar[EvaluationWorkspace | None] = ContextVar("evaluation_workspace", default=None)


def record_identity(record: ParsedRecord) -> int:
    """Return the stable workspace identity, or object identity for standalone scorer callers."""
    return record.evaluation_id if record.evaluation_id is not None else id(record)


def _key_bytes(value: Any) -> bytes:
    """Preserve Python's equality for numeric and aware-datetime mapping keys."""
    hash(value)  # Keep the ordinary mapping rejection of unhashable input.

    def canonical(item: Any) -> Any:
        if isinstance(item, bool):
            return int(item)
        if isinstance(item, float) and item.is_integer():
            return int(item)
        if isinstance(item, datetime) and item.tzinfo is not None:
            return item.astimezone(UTC)
        if isinstance(item, tuple):
            return tuple(canonical(part) for part in item)
        return item

    return pickle.dumps(canonical(value), protocol=5)


def _size(value: object, seen: set[int] | None = None) -> int:
    if isinstance(value, ParsedRecord) and value.evaluation_size is not None:
        return value.evaluation_size
    seen = seen if seen is not None else set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    total = sys.getsizeof(value)
    if isinstance(value, ParsedRecord):
        total += _size(value.__dict__, seen)
    elif isinstance(value, dict):
        total += sum(_size(key, seen) + _size(item, seen) for key, item in value.items())
    elif isinstance(value, list | tuple | set | frozenset):
        total += sum(_size(item, seen) for item in value)
    return total


def _token(value: Any) -> bytes:
    """Encode the primitive sort keys used by evaluation, preserving Python ordering."""
    if isinstance(value, datetime):
        normalized = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        delta = normalized - datetime(1970, 1, 1, tzinfo=UTC)
        return b"d" + _token(
            delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
        )
    if isinstance(value, int):
        # Sign/magnitude encoding also supports seed integers larger than SQLite's int64.
        magnitude = abs(value).to_bytes(max(1, (abs(value).bit_length() + 7) // 8), "big")
        body = len(magnitude).to_bytes(4, "big") + magnitude
        return b"i" + (b"1" + body if value >= 0 else b"0" + bytes(255 - x for x in body))
    if isinstance(value, float):
        value = 0.0 if value == 0 else value
        bits = struct.unpack(">Q", struct.pack(">d", value))[0]
        bits = ~bits & ((1 << 64) - 1) if bits >> 63 else bits ^ (1 << 63)
        return b"f" + bits.to_bytes(8, "big")
    if isinstance(value, str):
        return (
            b"s" + value.encode("utf-8", errors="surrogatepass").replace(b"\0", b"\0\xff") + b"\0\0"
        )
    if isinstance(value, bytes):
        return b"b" + value.replace(b"\0", b"\0\xff") + b"\0\0"
    if isinstance(value, tuple):
        return b"t" + b"".join(_token(item) for item in value) + b"\0"
    raise TypeError(f"Unsupported evaluation sort key: {type(value).__name__}")


class EvaluationWorkspace:
    """Own shared memory accounting, canonical records and disposable spill storage."""

    def __init__(
        self, memory_bytes: int = 256 * 1024 * 1024, scratch_dir: Path | None = None
    ) -> None:
        if memory_bytes <= 0:
            raise ValueError("Evaluation working-memory budget must be positive")
        self.memory_bytes = memory_bytes
        self.scratch_dir = scratch_dir
        self.retained_bytes = 0
        self.peak_retained_bytes = 0
        self.spilled = False
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.db: sqlite3.Connection | None = None
        self._records: dict[int, ParsedRecord] = {}
        self._groups: dict[int, dict[bytes, list[tuple[int, Any, bytes]]]] = {}
        self._charges: dict[int, int] = {}
        self._ordered: dict[int, dict[bytes, list]] = {}
        self._next: dict[int, int] = {}
        self._record_cache: OrderedDict[int, tuple[ParsedRecord, int]] = OrderedDict()
        self._record_cache_bytes = 0
        self._record_cache_limit = min(32 * 1024 * 1024, memory_bytes // 8)
        self._record_id = 0
        self._namespace_id = 0
        self.shared: dict[object, Any] = {}
        self._closed = False
        self._spillables: list[weakref.ReferenceType] = []

    def register_spillable(self, value: Any) -> None:
        self._spillables.append(weakref.ref(value))

    def namespace(self) -> int:
        self._namespace_id += 1
        number = self._namespace_id
        self._next[number] = 0
        self._groups[number] = {}
        self._charges[number] = 0
        return number

    def release(self, ns: int) -> None:
        if self._closed:
            return
        self._next.pop(ns, None)
        self._ordered.pop(ns, None)
        self.retained_bytes -= self._charges.pop(ns, 0)
        if ns in self._groups:
            self._groups.pop(ns, None)
        elif self.spilled:
            assert self.db is not None
            self.db.execute("DELETE FROM entries WHERE ns=?", (ns,))
            self.db.execute("DELETE FROM groups WHERE ns=?", (ns,))

    def charge(self, size: int, namespace: int | None = None) -> None:
        self.retained_bytes += size
        if namespace is not None:
            self._charges[namespace] += size
        self.peak_retained_bytes = max(self.peak_retained_bytes, self.retained_bytes)
        if self.retained_bytes > self.memory_bytes:
            if not self.spilled:
                self._spill()
            else:
                for ns in tuple(self._groups):
                    self._spill_namespace(ns)

    def _spill_namespace(self, ns: int) -> None:
        assert self.db is not None
        groups = self._groups.pop(ns)
        self._ordered.pop(ns, None)
        for key, rows in groups.items():
            self.db.execute(
                "INSERT INTO groups VALUES (?,?,?,?)",
                (ns, key, rows[0][0] if rows else 0, len(rows)),
            )
            self.db.executemany(
                "INSERT INTO entries VALUES (?,?,?,?,?,?)",
                ((ns, key, order, *self._encode_value(value), sort) for order, value, sort in rows),
            )
        self.retained_bytes -= self._charges.get(ns, 0)
        self._charges[ns] = 0

    def _spill(self) -> None:
        try:
            self._temporary = tempfile.TemporaryDirectory(
                prefix="eforge-eval-", dir=self.scratch_dir
            )
            self.db = sqlite3.connect(Path(self._temporary.name) / "evaluation.sqlite")
            # Disposable scratch needs no recovery journal. Bound SQLite's page cache too.
            self.db.executescript(
                "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE;"
                f"PRAGMA cache_size=-{max(64, min(8192, self.memory_bytes // 8192))};"
                "CREATE TABLE records (id INTEGER PRIMARY KEY, payload BLOB NOT NULL);"
                "CREATE TABLE groups (ns INTEGER, k BLOB, first_ord INTEGER, n INTEGER,"
                " PRIMARY KEY(ns,k)) WITHOUT ROWID;"
                "CREATE INDEX group_order ON groups(ns,first_ord);"
                "CREATE TABLE entries (ns INTEGER, k BLOB, ord INTEGER, rid INTEGER,"
                " payload BLOB, sort BLOB, PRIMARY KEY(ns,k,ord)) WITHOUT ROWID;"
                "CREATE INDEX entry_sort ON entries(ns,k,sort,ord);"
            )
            self.db.executemany(
                "INSERT INTO records VALUES (?,?)",
                (
                    (identity, self._encode_record(record))
                    for identity, record in self._records.items()
                ),
            )
            for ns in tuple(self._groups):
                self._spill_namespace(ns)
            self._records.clear()
            self.retained_bytes = 0
            self.spilled = True
            for reference in self._spillables:
                value = reference()
                if value is not None:
                    value.spill()
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise EvaluationError(
                "Unable to create evaluation scratch storage; choose a writable scratch directory with free space"
            ) from exc

    @staticmethod
    def _encode_record(record: ParsedRecord) -> bytes:
        return pickle.dumps(record.__dict__, protocol=5)

    @staticmethod
    def _encode_value(value: Any) -> tuple[int | None, bytes | None]:
        if isinstance(value, ParsedRecord):
            return record_identity(value), None
        return None, pickle.dumps(value, protocol=5)

    def add_record(self, record: ParsedRecord) -> ParsedRecord:
        """Register one parsed record, preserving its raw evidence exactly once."""
        if record.evaluation_owner == id(self) and record.evaluation_id is not None:
            cached = self._record_cache.pop(record.evaluation_id, None)
            if cached is not None:
                self._record_cache_bytes -= cached[1]
                self.retained_bytes -= cached[1]
            if self.spilled:
                assert self.db is not None
                self.db.execute(
                    "UPDATE records SET payload=? WHERE id=?",
                    (self._encode_record(record), record.evaluation_id),
                )
            return record
        self._record_id += 1
        record.evaluation_id = self._record_id
        record.evaluation_owner = id(self)
        record.evaluation_size = _size(record)
        if self.spilled:
            assert self.db is not None
            self.db.execute(
                "INSERT INTO records VALUES (?,?)", (self._record_id, self._encode_record(record))
            )
        else:
            self._records[self._record_id] = record
            self.charge(_size(record) + 96)
        return record

    def decode(self, rid: int | None, payload: bytes | None) -> Any:
        if rid is not None:
            if not self.spilled:
                return self._records[rid]
            cached = self._record_cache.get(rid)
            if cached is not None:
                self._record_cache.move_to_end(rid)
                return cached[0]
            assert payload is not None
            record = ParsedRecord.model_validate(pickle.loads(payload))
            size = _size(record) + 128
            if size <= self._record_cache_limit:
                while self._record_cache_bytes + size > self._record_cache_limit:
                    _, (_, previous_size) = self._record_cache.popitem(last=False)
                    self._record_cache_bytes -= previous_size
                    self.retained_bytes -= previous_size
                self._record_cache[rid] = (record, size)
                self._record_cache_bytes += size
                self.charge(size)
            return record
        assert payload is not None
        return pickle.loads(payload)

    def append(self, ns: int, key: bytes, value: Any, sort: bytes = b"") -> None:
        if isinstance(value, ParsedRecord) and value.evaluation_owner != id(self):
            self.add_record(value)
        order = self._next[ns]
        self._next[ns] += 1
        if ns not in self._groups:
            assert self.db is not None
            rid, payload = self._encode_value(value)
            self.db.execute(
                "INSERT INTO groups VALUES (?,?,?,1) ON CONFLICT(ns,k) DO UPDATE SET n=n+1",
                (ns, key, order),
            )
            self.db.execute(
                "INSERT INTO entries VALUES (?,?,?,?,?,?)", (ns, key, order, rid, payload, sort)
            )
        else:
            groups = self._groups[ns]
            if key not in groups:
                groups[key] = []
                self.retained_bytes += len(key) + 192
                self._charges[ns] += len(key) + 192
            groups[key].append((order, value, sort))
            self.forget_order(ns, key)
            # After the corpus spills, newly hydrated records in small working sets are charged.
            value_bytes = (
                0 if isinstance(value, ParsedRecord) and not self.spilled else _size(value)
            )
            self.charge(160 + len(sort) + value_bytes, ns)

    def length(self, ns: int, key: bytes) -> int:
        if ns in self._groups:
            return len(self._groups[ns].get(key, ()))
        assert self.db is not None
        row = self.db.execute("SELECT n FROM groups WHERE ns=? AND k=?", (ns, key)).fetchone()
        return row[0] if row else 0

    def keys(self, ns: int) -> Iterator[Any]:
        if ns in self._groups:
            for key in self._groups[ns]:
                yield pickle.loads(key)
        else:
            assert self.db is not None
            for row in self.db.execute("SELECT k FROM groups WHERE ns=? ORDER BY first_ord", (ns,)):
                yield pickle.loads(row[0])

    def forget_order(self, ns: int, key: bytes) -> None:
        cached = self._ordered.get(ns, {}).pop(key, None)
        if cached is not None:
            size = 96 + len(cached) * 8
            self.retained_bytes -= size
            self._charges[ns] -= size

    def memory_rows(
        self, ns: int, key: bytes, ordered: bool = False
    ) -> Sequence[tuple[int, Any, bytes]]:
        rows = self._groups[ns].get(key, ())
        if not ordered or not rows:
            return rows
        cached = self._ordered.setdefault(ns, {})
        if key not in cached:
            result = sorted(rows, key=lambda item: (item[2], item[0]))
            cached[key] = result
            self.charge(96 + len(result) * 8, ns)
            return result
        return cached[key]

    def rows(self, ns: int, key: bytes, ordered: bool = False) -> Iterator[Any]:
        if ns in self._groups:
            rows = self.memory_rows(ns, key, ordered)
            for _, value, _ in rows:
                yield value
        else:
            assert self.db is not None
            ordering = "e.sort,e.ord" if ordered else "e.ord"
            cursor = self.db.execute(
                "SELECT e.rid, CASE WHEN e.rid IS NULL THEN e.payload ELSE r.payload END "
                "FROM entries e LEFT JOIN records r ON r.id=e.rid "
                f"WHERE e.ns=? AND e.k=? ORDER BY {ordering}",
                (ns, key),
            )
            for rid, payload in cursor:
                yield self.decode(rid, payload)

    def discard(self, ns: int, key: bytes) -> None:
        if ns in self._groups:
            self._groups[ns].pop(key, None)
        else:
            assert self.db is not None
            self.db.execute("DELETE FROM entries WHERE ns=? AND k=?", (ns, key))
            self.db.execute("DELETE FROM groups WHERE ns=? AND k=?", (ns, key))

    def close(self) -> None:
        """Release only this run's private scratch, including after interruption/failure."""
        if self._closed:
            return
        self._closed = True
        self.shared.clear()
        self._records.clear()
        self._record_cache.clear()
        self._record_cache_bytes = 0
        self._groups.clear()
        self._charges.clear()
        self._ordered.clear()
        self._next.clear()
        self._spillables.clear()
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._temporary is not None:
            self._temporary.cleanup()


class SpillSequence(Sequence[T]):
    """A repeatable sequence whose entries share the workspace's spill budget."""

    def __init__(
        self,
        workspace: EvaluationWorkspace,
        ns: int | None = None,
        key: Any = None,
        ordered: bool = False,
    ) -> None:
        self.workspace = workspace
        self._owns_namespace = ns is None
        self._owner: object | None = None
        self.ns = ns if ns is not None else workspace.namespace()
        self.key = _key_bytes(key)
        self.ordered = ordered
        self.bounds: tuple[bytes, bytes, bool] | None = None

    def __del__(self) -> None:
        if self._owns_namespace:
            self.workspace.release(self.ns)

    def append(self, value: T, *, sort: bytes = b"") -> None:
        self.workspace.append(self.ns, self.key, value, sort)

    def extend(self, values: Iterable[T]) -> None:
        for value in values:
            self.append(value)

    def pop(self, index: int = -1) -> T:
        if self.bounds is not None:
            raise TypeError("Cannot remove records through a time-range view")
        value = self[index]
        if index < 0:
            index += len(self)
        if self.ns in self.workspace._groups:
            selected = self.workspace.memory_rows(self.ns, self.key, self.ordered)[index][0]
            self.workspace.forget_order(self.ns, self.key)
            rows = self.workspace._groups[self.ns][self.key]
            for position, row in enumerate(rows):
                if row[0] == selected:
                    rows.pop(position)
                    break
        else:
            assert self.workspace.db is not None
            ordering = "sort,ord" if self.ordered else "ord"
            row = self.workspace.db.execute(
                f"SELECT ord FROM entries WHERE ns=? AND k=? ORDER BY {ordering} LIMIT 1 OFFSET ?",
                (self.ns, self.key, index),
            ).fetchone()
            self.workspace.db.execute(
                "DELETE FROM entries WHERE ns=? AND k=? AND ord=?", (self.ns, self.key, row[0])
            )
            self.workspace.db.execute(
                "UPDATE groups SET n=n-1 WHERE ns=? AND k=?", (self.ns, self.key)
            )
        return value

    def __len__(self) -> int:
        if self.bounds is not None:
            if self.ns in self.workspace._groups:
                rows = self.workspace.memory_rows(self.ns, self.key, True)
                lower, upper, exclusive = self.bounds
                start = bisect_left(rows, lower, key=lambda row: row[2])
                end = (bisect_left if exclusive else bisect_right)(
                    rows, upper, key=lambda row: row[2]
                )
                return end - start
            assert self.workspace.db is not None
            lower, upper, exclusive = self.bounds
            comparator = "<" if exclusive else "<="
            return self.workspace.db.execute(
                f"SELECT count(*) FROM entries WHERE ns=? AND k=? AND sort>=? AND sort{comparator}?",
                (self.ns, self.key, lower, upper),
            ).fetchone()[0]
        return self.workspace.length(self.ns, self.key)

    def in_range(
        self, lower: Any, upper: Any, *, exclusive_upper: bool = False
    ) -> SpillSequence[T]:
        result: SpillSequence[T] = SpillSequence(
            self.workspace, self.ns, pickle.loads(self.key), True
        )
        result._owner = self
        result.bounds = (_token(lower), _token(upper), exclusive_upper)
        return result

    def __iter__(self) -> Iterator[T]:
        if self.bounds is None:
            yield from self.workspace.rows(self.ns, self.key, self.ordered)
            return
        lower, upper, exclusive = self.bounds
        if self.ns in self.workspace._groups:
            from itertools import islice

            rows = self.workspace.memory_rows(self.ns, self.key, True)
            start = bisect_left(rows, lower, key=lambda row: row[2])
            end = (bisect_left if exclusive else bisect_right)(rows, upper, key=lambda row: row[2])
            for _, value, _ in islice(rows, start, end):
                yield value
            return
        assert self.workspace.db is not None
        comparator = "<" if exclusive else "<="
        for rid, payload in self.workspace.db.execute(
            "SELECT e.rid, CASE WHEN e.rid IS NULL THEN e.payload ELSE r.payload END "
            "FROM entries e LEFT JOIN records r ON r.id=e.rid "
            f"WHERE e.ns=? AND e.k=? AND e.sort>=? AND e.sort{comparator}? ORDER BY e.sort,e.ord",
            (self.ns, self.key, lower, upper),
        ):
            yield self.workspace.decode(rid, payload)

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[T]: ...

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        if isinstance(index, slice):
            return SequenceSlice(self, index)
        original = index
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        if self.ns in self.workspace._groups:
            rows = self.workspace.memory_rows(self.ns, self.key, self.ordered)
            start = 0
            if self.bounds is not None:
                lower, _, _ = self.bounds
                start = bisect_left(rows, lower, key=lambda row: row[2])
            return rows[start + index][1]
        assert self.workspace.db is not None
        descending = original < 0
        direction = " DESC" if descending else ""
        ordering = f"e.sort{direction},e.ord{direction}" if self.ordered else f"e.ord{direction}"
        where = "e.ns=? AND e.k=?"
        arguments = [self.ns, self.key]
        if self.bounds is not None:
            lower, upper, exclusive = self.bounds
            where += f" AND e.sort>=? AND e.sort{'<' if exclusive else '<='}?"
            arguments.extend((lower, upper))
        arguments.append(-original - 1 if descending else index)
        row = self.workspace.db.execute(
            "SELECT e.rid, CASE WHEN e.rid IS NULL THEN e.payload ELSE r.payload END "
            "FROM entries e LEFT JOIN records r ON r.id=e.rid "
            f"WHERE {where} ORDER BY {ordering} LIMIT 1 OFFSET ?",
            arguments,
        ).fetchone()
        assert row is not None
        return self.workspace.decode(*row)

    def latest_before(self, upper: Any, *, strict: bool = False) -> T | None:
        token = _token(upper)
        if self.ns in self.workspace._groups:
            rows = self.workspace.memory_rows(self.ns, self.key, True)
            index = (bisect_left if strict else bisect_right)(rows, token, key=lambda row: row[2])
            return rows[index - 1][1] if index else None
        assert self.workspace.db is not None
        row = self.workspace.db.execute(
            "SELECT e.rid, CASE WHEN e.rid IS NULL THEN e.payload ELSE r.payload END "
            "FROM entries e LEFT JOIN records r ON r.id=e.rid "
            f"WHERE e.ns=? AND e.k=? AND e.sort{'<' if strict else '<='}? ORDER BY e.sort DESC,e.ord DESC LIMIT 1",
            (self.ns, self.key, token),
        ).fetchone()
        return self.workspace.decode(*row) if row else None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sequence):
            return False
        return len(self) == len(other) and all(a == b for a, b in zip(self, other, strict=True))


class SequenceSlice(Sequence[T]):
    """A lazy slice, avoiding materialization of large candidate time windows."""

    def __init__(self, source: Sequence[T], selection: slice) -> None:
        self.source = source
        self.indices = range(*selection.indices(len(source)))

    def __len__(self) -> int:
        return len(self.indices)

    def __iter__(self) -> Iterator[T]:
        from itertools import islice

        if self.indices.step > 0:
            yield from islice(self.source, self.indices.start, self.indices.stop, self.indices.step)
        else:
            for index in self.indices:
                yield self.source[index]

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            selected = self.indices[index]
            return SequenceSlice(self.source, slice(selected.start, selected.stop, selected.step))
        return self.source[self.indices[index]]


class SpillGroups(Mapping[K, SpillSequence[T]]):
    """Insertion-ordered multimap with no retained Python object per disk-backed key."""

    def __init__(self, workspace: EvaluationWorkspace, ordered: bool = False) -> None:
        self.workspace = workspace
        self.ns = workspace.namespace()
        self.ordered = ordered

    def __del__(self) -> None:
        self.workspace.release(self.ns)

    def __getitem__(self, key: K) -> SpillSequence[T]:
        result: SpillSequence[T] = SpillSequence(self.workspace, self.ns, key, self.ordered)
        result._owner = self
        return result

    def get(self, key: K, default: Any = None) -> Any:
        return self[key] if key in self else default

    def __contains__(self, key: object) -> bool:
        return self.workspace.length(self.ns, _key_bytes(key)) > 0

    def __iter__(self) -> Iterator[K]:
        return self.workspace.keys(self.ns)

    def __len__(self) -> int:
        if self.ns in self.workspace._groups:
            return len(self.workspace._groups[self.ns])
        assert self.workspace.db is not None
        return self.workspace.db.execute(
            "SELECT count(*) FROM groups WHERE ns=?", (self.ns,)
        ).fetchone()[0]


class SpillMap(MutableMapping[K, T]):
    """A spillable insertion-ordered mapping of immutable/replaced values."""

    def __init__(self, workspace: EvaluationWorkspace) -> None:
        self.groups: SpillGroups[K, T] = SpillGroups(workspace)

    def __getitem__(self, key: K) -> T:
        return self._lookup(key)

    def _lookup(self, key: K) -> T:
        workspace = self.groups.workspace
        encoded = _key_bytes(key)
        if self.groups.ns in workspace._groups:
            rows = workspace._groups[self.groups.ns].get(encoded)
            if rows:
                return rows[0][1]
        else:
            assert workspace.db is not None
            row = workspace.db.execute(
                "SELECT e.rid, CASE WHEN e.rid IS NULL THEN e.payload ELSE r.payload END "
                "FROM entries e LEFT JOIN records r ON r.id=e.rid WHERE e.ns=? AND e.k=?",
                (self.groups.ns, encoded),
            ).fetchone()
            if row is not None:
                return workspace.decode(*row)
        raise KeyError(key)

    def __setitem__(self, key: K, value: T) -> None:
        encoded = _key_bytes(key)
        workspace = self.groups.workspace
        if isinstance(value, ParsedRecord) and value.evaluation_owner != id(workspace):
            workspace.add_record(value)
        if key in self.groups:
            # Preserve dict insertion order on replacement.
            if self.groups.ns in workspace._groups:
                rows = workspace._groups[self.groups.ns][encoded]
                previous = rows[0][1]
                workspace.forget_order(self.groups.ns, encoded)
                rows[0] = (rows[0][0], value, b"")
                previous_bytes = (
                    0
                    if isinstance(previous, ParsedRecord) and not workspace.spilled
                    else _size(previous)
                )
                value_bytes = (
                    0 if isinstance(value, ParsedRecord) and not workspace.spilled else _size(value)
                )
                workspace.charge(value_bytes - previous_bytes, self.groups.ns)
                return
            assert workspace.db is not None
            rid, payload = workspace._encode_value(value)
            workspace.db.execute(
                "UPDATE entries SET rid=?,payload=? WHERE ns=? AND k=?",
                (rid, payload, self.groups.ns, encoded),
            )
        else:
            self.groups[key].append(value)

    def __delitem__(self, key: K) -> None:
        if key not in self.groups:
            raise KeyError(key)
        self.groups.workspace.discard(self.groups.ns, _key_bytes(key))

    def __contains__(self, key: object) -> bool:
        return key in self.groups

    def get(self, key: K, default: Any = None) -> Any:
        try:
            return self._lookup(key)
        except KeyError:
            return default

    def __iter__(self) -> Iterator[K]:
        return iter(self.groups)

    def __len__(self) -> int:
        return len(self.groups)


class SpillSet(MutableSet[T]):
    """A spillable exact membership set."""

    def __init__(self, workspace: EvaluationWorkspace) -> None:
        self.values: SpillMap[T, bool] = SpillMap(workspace)

    def __contains__(self, value: object) -> bool:
        return value in self.values.groups

    def __iter__(self) -> Iterator[T]:
        return iter(self.values)

    def __len__(self) -> int:
        return len(self.values)

    def add(self, value: T) -> None:
        if value not in self:
            self.values[value] = True

    def discard(self, value: T) -> None:
        if value in self:
            del self.values[value]


@contextmanager
def evaluation_workspace(workspace: EvaluationWorkspace) -> Iterator[None]:
    """Scope run-local storage without changing independent scorer/test entry points."""
    token = _ACTIVE.set(workspace)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def current_workspace() -> EvaluationWorkspace | None:
    """Return the active evaluator workspace, if called inside a complete evaluation."""
    return _ACTIVE.get()


def bounded_list[T](values: Iterable[T] = ()) -> list[T] | SpillSequence[T]:
    """Collect exact values, spilling with the rest of this run's working state."""
    workspace = current_workspace()
    if workspace is None:
        return list(values)
    result: SpillSequence[T] = SpillSequence(workspace)
    result.extend(values)
    return result


def bounded_groups(*, ordered: bool = False) -> Any:
    """Create an exact multimap, with ordinary defaultdict behavior outside evaluation."""
    workspace = current_workspace()
    return SpillGroups(workspace, ordered=ordered) if workspace else defaultdict(list)


def bounded_map[K, T](values: Iterable[tuple[K, T]] = ()) -> MutableMapping[K, T]:
    """Create an exact mapping of replaced values."""
    workspace = current_workspace()
    result: MutableMapping[K, T] = SpillMap(workspace) if workspace else {}
    result.update(values)
    return result


def bounded_set[T](values: Iterable[T] = ()) -> MutableSet[T]:
    """Create an exact membership set."""
    workspace = current_workspace()
    result: MutableSet[T] = SpillSet(workspace) if workspace else set()
    for value in values:
        result.add(value)
    return result


def bounded_sorted[T](values: Iterable[T], *, key: Callable[[T], Any] | None = None) -> Sequence[T]:
    """Sort exactly, with stable ties and external ordering after spill."""
    if isinstance(values, SpillSequence) and values.ordered and key is None:
        return values
    workspace = current_workspace()
    if workspace is None:
        return sorted(values, key=key)
    sort_key = key or (lambda value: value)
    result: SpillSequence[T] = SpillSequence(workspace, ordered=True)
    for value in values:
        result.append(value, sort=_token(sort_key(value)))
    return result


class SpillCounter(SpillMap[K, int]):
    """Exact spillable frequency counters."""

    def __getitem__(self, key: K) -> int:
        try:
            return super().__getitem__(key)
        except KeyError:
            return 0


def bounded_counter() -> Any:
    workspace = current_workspace()
    if workspace is None:
        from collections import Counter

        return Counter()
    return SpillCounter(workspace)


def append_group(groups: Any, key: Any, value: Any, *, sort: Any = None) -> None:
    """Append to either the compatibility multimap or a hybrid ordered index."""
    bucket = groups[key]
    if isinstance(bucket, SpillSequence) and sort is not None:
        bucket.append(value, sort=_token(sort))
    else:
        bucket.append(value)


class CounterGroups(Mapping[K, MutableMapping[Any, int]]):
    """Grouped counters, including unknown users/types, sharing the run budget."""

    def __init__(self, workspace: EvaluationWorkspace) -> None:
        self.counts: SpillCounter[tuple[K, Any]] = SpillCounter(workspace)
        self.keys_by_group: SpillGroups[K, Any] = SpillGroups(workspace)

    def __getitem__(self, key: K) -> MutableMapping[Any, int]:
        return CounterGroup(self, key)

    def __iter__(self) -> Iterator[K]:
        return iter(self.keys_by_group)

    def __len__(self) -> int:
        return len(self.keys_by_group)


class CounterGroup(MutableMapping[Any, int]):
    """A view of one grouped counter."""

    def __init__(self, owner: CounterGroups, key: Any) -> None:
        self.owner = owner
        self.key = key

    def __getitem__(self, key: Any) -> int:
        return self.owner.counts[(self.key, key)]

    def __setitem__(self, key: Any, value: int) -> None:
        pair = (self.key, key)
        if pair not in self.owner.counts:
            self.owner.keys_by_group[self.key].append(key)
        self.owner.counts[pair] = value

    def __delitem__(self, key: Any) -> None:
        raise TypeError("Evaluation counter groups support accumulation only")

    def __contains__(self, key: object) -> bool:
        return (self.key, key) in self.owner.counts

    def get(self, key: Any, default: Any = None) -> Any:
        return self[key] if key in self else default

    def __iter__(self) -> Iterator[Any]:
        return iter(self.owner.keys_by_group.get(self.key, ()))

    def __len__(self) -> int:
        return len(self.owner.keys_by_group.get(self.key, ()))


def bounded_counter_groups() -> Any:
    workspace = current_workspace()
    if workspace is None:
        from collections import Counter

        return defaultdict(Counter)
    return CounterGroups(workspace)


class PayloadSearch:
    """Match known payloads against a joined text stream with bounded overlap."""

    def __init__(self, parts: Iterable[str], patterns: Iterable[str]) -> None:
        remaining = set(patterns)
        self.matches: set[str] = set()
        overlap = max((len(value) - 1 for value in remaining), default=0)
        tail = ""
        pending = ""
        first = True
        for part in parts:
            chunk = pending + ("" if first else "\n") + part
            first = False
            pending = "\r" if chunk.endswith("\r") else ""
            if pending:
                chunk = chunk[:-1]
            chunk = chunk.replace("\r\n", "\n").replace("\r", "\n")
            text = tail + chunk
            found = {value for value in remaining if value in text}
            self.matches.update(found)
            remaining.difference_update(found)
            if not remaining:
                return
            tail = text[-overlap:] if overlap else ""
        if pending:
            self.matches.update(value for value in remaining if value in tail + "\n")

    def __contains__(self, value: str) -> bool:
        return value in self.matches


def bounded_nsmallest[T](
    limit: int, values: Iterable[T], *, key: Callable[[T], Any]
) -> Sequence[T]:
    """Preserve existing deterministic statistical samples with bounded top-k work."""
    from heapq import nsmallest

    workspace = current_workspace()
    if workspace is None:
        return nsmallest(limit, values, key=key)
    if not workspace.spilled:
        return bounded_list(nsmallest(limit, values, key=key))
    result: SpillSequence[T] = SpillSequence(workspace, ordered=True)
    workspace._spill_namespace(result.ns)
    largest: bytes | None = None
    count = 0
    for value in values:
        sort = _token(key(value))
        if count == limit and largest is not None and sort >= largest:
            continue
        result.append(value, sort=sort)
        count += 1
        assert workspace.db is not None
        if count > limit:
            row = workspace.db.execute(
                "SELECT ord FROM entries WHERE ns=? AND k=? ORDER BY sort DESC,ord DESC LIMIT 1",
                (result.ns, result.key),
            ).fetchone()
            workspace.db.execute(
                "DELETE FROM entries WHERE ns=? AND k=? AND ord=?", (result.ns, result.key, row[0])
            )
            workspace.db.execute(
                "UPDATE groups SET n=n-1 WHERE ns=? AND k=?", (result.ns, result.key)
            )
            count -= 1
        if count == limit:
            largest = workspace.db.execute(
                "SELECT sort FROM entries WHERE ns=? AND k=? ORDER BY sort DESC,ord DESC LIMIT 1",
                (result.ns, result.key),
            ).fetchone()[0]
    return result
