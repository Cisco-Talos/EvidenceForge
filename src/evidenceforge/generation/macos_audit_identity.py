# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical chronological projection of immutable Mac audit identity reservations.

Planning handles participate in canonical proofs and never change. Native generations
are resolved from committed fork/exec allocation facts, independently of source selection.
History lives in a private SQLite ledger; only the current admission buffer is resident.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import weakref
from collections.abc import Callable, Iterator, MutableMapping
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

type AuditKey = tuple[str, int]
type AuditFact = tuple[datetime, str]


def _cleanup_ledger(db: sqlite3.Connection, directory: tempfile.TemporaryDirectory[str]) -> None:
    """Release native handles before removing the private canonical ledger."""
    db.close()
    directory.cleanup()


class MacosAuditIdentityLedger(MutableMapping[AuditKey, AuditFact]):
    """Own durable allocation facts and one sealed host-wide native generation map."""

    def __init__(self, record: Callable[[AuditKey, AuditFact | None], None]) -> None:
        self._record = record
        self._pending: dict[AuditKey, AuditFact | None] = {}
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._db: sqlite3.Connection | None = None
        self._sealed = False
        self._cleanup: weakref.finalize | None = None

    def _connection(self) -> sqlite3.Connection:
        if self._db is None:
            self._directory = tempfile.TemporaryDirectory(prefix="eforge-audit-identity-")
            path = Path(self._directory.name) / "allocations.sqlite"
            self._db = sqlite3.connect(path, check_same_thread=False)
            self._cleanup = weakref.finalize(self, _cleanup_ledger, self._db, self._directory)
            self._db.execute("PRAGMA cache_size=-1024")
            self._db.execute("PRAGMA temp_store=FILE")
            self._db.execute(
                "CREATE TABLE identities (host TEXT, handle INTEGER, at TEXT, execution TEXT, "
                "PRIMARY KEY(host, handle))"
            )
        return self._db

    @staticmethod
    def validate(key: object, value: object) -> None:
        """Validate typed canonical facts and incremental checkpoint tombstones."""
        if (
            type(key) is not tuple
            or len(key) != 2
            or type(key[0]) is not str
            or not key[0]
            or type(key[1]) is not int
            or not 0 < key[1] < 2**32
            or (
                value is not None
                and (
                    type(value) is not tuple
                    or len(value) != 2
                    or type(value[0]) is not datetime
                    or value[0].utcoffset() is None
                    or type(value[1]) is not str
                    or not value[1]
                )
            )
        ):
            raise ValueError("Invalid canonical Mac audit identity allocation")

    def __getitem__(self, key: AuditKey) -> AuditFact:
        if key in self._pending:
            value = self._pending[key]
            if value is None:
                raise KeyError(key)
            return value
        if self._db is not None:
            row = self._db.execute(
                "SELECT at, execution FROM identities WHERE host=? AND handle=?", key
            ).fetchone()
            if row is not None:
                return datetime.fromisoformat(row[0]), row[1]
        raise KeyError(key)

    def __setitem__(self, key: AuditKey, value: AuditFact) -> None:
        # This primitive tail performs no disk I/O. Admission validates facts;
        # planning/checkpoint/finalization drains the bounded in-flight buffer.
        if self._sealed:
            raise StateError("Mac audit identities are sealed for native publication")
        self._pending[key] = value
        self._record(key, value)

    def __delitem__(self, key: AuditKey) -> None:
        if key not in self:
            raise KeyError(key)
        if self._sealed:
            raise StateError("Mac audit identities are sealed for native publication")
        self._pending[key] = None
        self._record(key, None)

    def __iter__(self) -> Iterator[AuditKey]:
        self.flush()
        if self._db is None:
            return
        cursor = self._db.execute("SELECT host, handle FROM identities ORDER BY host, handle")
        for row in cursor:
            yield row[0], row[1]

    def __len__(self) -> int:
        self.flush()
        if self._db is None:
            return 0
        return self._db.execute("SELECT count(*) FROM identities").fetchone()[0]

    def flush(self) -> None:
        """Persist committed admission buffers outside the certified primitive tail."""
        if not self._pending:
            return
        db = self._connection()
        with db:
            for (host, handle), value in self._pending.items():
                if value is None:
                    db.execute("DELETE FROM identities WHERE host=? AND handle=?", (host, handle))
                else:
                    at, execution = value
                    db.execute(
                        "INSERT INTO identities VALUES (?, ?, ?, ?) ON CONFLICT(host, handle) "
                        "DO UPDATE SET at=excluded.at, execution=excluded.execution",
                        (
                            host,
                            handle,
                            ensure_utc(at).isoformat(timespec="microseconds"),
                            execution,
                        ),
                    )
        self._pending.clear()

    def drain_before_planning(self) -> None:
        """Bound resident committed history by a buffer plus the current action cohort."""
        if len(self._pending) >= 1024:
            self.flush()

    def canonical_snapshot(self) -> tuple[tuple[AuditKey, AuditFact], ...]:
        """Return logical facts for expensive offline atomicity diagnostics only."""
        return tuple(sorted(self.items()))

    def seal(self) -> None:
        """Assign generations from all committed canonical facts exactly once."""
        if self._sealed:
            return
        self.flush()
        if self._db is not None:
            with self._db:
                self._db.execute("BEGIN")
                self._db.execute(
                    "CREATE TABLE resolved AS SELECT host, handle, "
                    "row_number() OVER (PARTITION BY host ORDER BY at, handle) AS version "
                    "FROM identities"
                )
                self._db.execute("CREATE UNIQUE INDEX resolved_key ON resolved(host, handle)")
        self._sealed = True

    def resolve(self, host: str, handle: int) -> int:
        """Resolve one canonical reservation; unknown positive references fail closed."""
        if not self._sealed:
            raise StateError("Mac audit identities must be sealed before native publication")
        if handle == 0:
            return 0
        row = (
            self._db.execute(
                "SELECT version FROM resolved WHERE host=? AND handle=?", (host, handle)
            ).fetchone()
            if self._db is not None
            else None
        )
        if row is None:
            raise StateError(f"Mac audit reference has no canonical allocation on {host}")
        return row[0]

    def project_native(self, host: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Render all native token references through the same canonical mapping."""

        def visit(value: Any) -> Any:
            if isinstance(value, dict):
                result = {}
                for key, item in value.items():
                    if key == "pidversion":
                        result[key] = self.resolve(host, item)
                    elif key in {
                        "audit_token",
                        "parent_audit_token",
                        "responsible_audit_token",
                    } and isinstance(item, list):
                        if len(item) != 8:
                            raise StateError("Native audit-token array must have eight words")
                        result[key] = [*item[:7], self.resolve(host, item[7])]
                    else:
                        result[key] = visit(item)
                return result
            if isinstance(value, list):
                return [visit(item) for item in value]
            return value

        return visit(payload)

    def project_ecar(self, line: str) -> str:
        """Render eCAR's native generation properties without changing its journal."""
        payload = json.loads(line)
        properties = payload.get("properties", {})
        keys = [key for key in ("pid_version", "previous_pid_version") if key in properties]
        if not keys:
            return line
        for key in keys:
            original = properties[key]
            resolved = self.resolve(payload["hostname"], int(original))
            properties[key] = str(resolved) if isinstance(original, str) else resolved
        return json.dumps(payload, separators=(",", ":"))
