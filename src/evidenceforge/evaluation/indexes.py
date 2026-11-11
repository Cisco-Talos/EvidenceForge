"""Specialized shared indexes for high-volume evaluator correlation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.storage import EvaluationWorkspace, SequenceSlice, record_identity


class _HostRecords(Sequence[ParsedRecord]):
    def __init__(self, owner: HostTimeIndex, key: str, format_name: str) -> None:
        self.owner = owner
        self.key = key
        self.format_name = format_name

    def __len__(self) -> int:
        db = self.owner.workspace.db
        assert db is not None
        return db.execute(
            "SELECT count(*) FROM host_time WHERE ns=? AND k=? AND fmt=?",
            (self.owner.ns, self.key, self.format_name),
        ).fetchone()[0]

    def __iter__(self) -> Iterator[ParsedRecord]:
        workspace = self.owner.workspace
        assert workspace.db is not None
        with workspace.query(
            "SELECT r.id,r.payload FROM host_time h JOIN records r ON r.id=h.rid "
            "WHERE h.ns=? AND h.k=? AND h.fmt=? ORDER BY h.ord",
            (self.owner.ns, self.key, self.format_name),
        ) as cursor:
            for rid, payload in cursor:
                yield workspace.decode(rid, payload)

    def __getitem__(self, index: int | slice) -> Any:
        from itertools import islice

        if isinstance(index, slice):
            return SequenceSlice(self, index)
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        return next(islice(self, index, index + 1))


class HostTimeIndex(Mapping[str, Mapping[str, Sequence[ParsedRecord]]]):
    """Store each host/time alias with one batched/native reference-index operation."""

    def __init__(self, workspace: EvaluationWorkspace) -> None:
        self.workspace = workspace
        self.ns = workspace.namespace()
        self.memory: dict[str, dict[str, list[ParsedRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.ordinal = 0
        self.formats: dict[str, int] = {}
        self._request = 0
        self.ready = False
        workspace.register_spillable(self)
        if workspace.spilled:
            self.spill()

    def spill(self) -> None:
        if self.ready:
            return
        db = self.workspace.db
        assert db is not None
        db.executescript(
            "CREATE TABLE IF NOT EXISTS host_time (ns INTEGER,k TEXT,fmt TEXT,rid INTEGER,ord INTEGER,fmt_ord INTEGER,PRIMARY KEY(ns,k,fmt,rid)) WITHOUT ROWID;"
            "CREATE INDEX IF NOT EXISTS host_time_order ON host_time(ns,k,fmt,ord);"
        )
        db.executemany(
            "INSERT OR IGNORE INTO host_time VALUES (?,?,?,?,?,?)",
            (
                (self.ns, key, fmt, record_identity(record), order, self.formats[fmt])
                for key, formats in self.memory.items()
                for fmt, records in formats.items()
                for order, record in enumerate(records)
            ),
        )
        self.memory.clear()
        self.ready = True

    def append(self, key: str, format_name: str, record: ParsedRecord) -> None:
        format_order = self.formats.setdefault(format_name, len(self.formats))
        if not self.workspace.spilled:
            new_group = key not in self.memory or format_name not in self.memory[key]
            self.memory[key][format_name].append(record)
            self.workspace.charge(48 + (len(key) * 2 + 256 if new_group else 0), self.ns)
        else:
            assert self.workspace.db is not None
            self.workspace.db.execute(
                "INSERT OR IGNORE INTO host_time VALUES (?,?,?,?,?,?)",
                (self.ns, key, format_name, record_identity(record), self.ordinal, format_order),
            )
        self.ordinal += 1

    def __contains__(self, key: object) -> bool:
        if not self.workspace.spilled:
            return key in self.memory
        assert self.workspace.db is not None
        return (
            self.workspace.db.execute(
                "SELECT 1 FROM host_time WHERE ns=? AND k=? LIMIT 1", (self.ns, key)
            ).fetchone()
            is not None
        )

    def __getitem__(self, key: str) -> Mapping[str, Sequence[ParsedRecord]]:
        if key not in self:
            raise KeyError(key)
        if not self.workspace.spilled:
            return self.memory[key]
        assert self.workspace.db is not None
        with self.workspace.query(
            "SELECT fmt FROM host_time WHERE ns=? AND k=? GROUP BY fmt ORDER BY min(fmt_ord)",
            (self.ns, key),
        ) as cursor:
            return {row[0]: _HostRecords(self, key, row[0]) for row in cursor}

    def __iter__(self) -> Iterator[str]:
        if not self.workspace.spilled:
            yield from self.memory
        else:
            assert self.workspace.db is not None
            with self.workspace.query(
                "SELECT DISTINCT k FROM host_time WHERE ns=? ORDER BY k", (self.ns,)
            ) as cursor:
                for row in cursor:
                    yield row[0]

    def __len__(self) -> int:
        if not self.workspace.spilled:
            return len(self.memory)
        assert self.workspace.db is not None
        return self.workspace.db.execute(
            "SELECT count(DISTINCT k) FROM host_time WHERE ns=?", (self.ns,)
        ).fetchone()[0]

    def candidates(self, keys: list[str]) -> Iterator[tuple[str, ParsedRecord]]:
        """Read each candidate once, preserving its first legacy lookup position."""
        if not keys:
            return
        workspace = self.workspace
        seen = None
        if not workspace.spilled:
            from evidenceforge.evaluation.storage import bounded_set

            seen = bounded_set()
            for key in keys:
                if workspace.spilled:
                    break
                for format_name, records in self.memory.get(key, {}).items():
                    if workspace.spilled:
                        break
                    for record in records:
                        if workspace.spilled:
                            break
                        identity = record_identity(record)
                        if identity not in seen:
                            seen.add(identity)
                            yield format_name, record
            if not workspace.spilled:
                return
        db = workspace.db
        assert db is not None
        db.execute(
            "CREATE TABLE IF NOT EXISTS host_wanted (ns INTEGER,request INTEGER,ord INTEGER,k TEXT,PRIMARY KEY(ns,request,ord)) WITHOUT ROWID"
        )
        self._request += 1
        request = self._request
        db.executemany(
            "INSERT INTO host_wanted VALUES (?,?,?,?)",
            ((self.ns, request, order, key) for order, key in enumerate(keys)),
        )
        try:
            with workspace.query(
                "SELECT hits.fmt,r.id,r.payload FROM ("
                " SELECT h.fmt,h.rid,h.fmt_ord,w.ord AS query_ord,h.ord AS source_ord,"
                " row_number() OVER (PARTITION BY h.rid ORDER BY w.ord,h.fmt_ord,h.ord) AS rank"
                " FROM host_wanted w JOIN host_time h ON h.ns=w.ns AND h.k=w.k"
                " WHERE w.ns=? AND w.request=?"
                ") hits JOIN records r ON r.id=hits.rid WHERE hits.rank=1"
                " ORDER BY hits.query_ord,hits.fmt_ord,hits.source_ord",
                (self.ns, request),
            ) as cursor:
                for format_name, identity, payload in cursor:
                    if seen is None or identity not in seen:
                        yield format_name, workspace.decode(identity, payload)
        finally:
            if not workspace._closed:
                db.execute("DELETE FROM host_wanted WHERE ns=? AND request=?", (self.ns, request))
