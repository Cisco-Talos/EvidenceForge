# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact-publication durability gates for Bash history and Snort output."""

from __future__ import annotations

import ast
import inspect
import json
import os
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread, get_ident
from urllib.parse import unquote, urlsplit

import pytest

import evidenceforge.generation.emitters.bash_history as bash_history_module
from evidenceforge.events.ids_evaluation import new_ids_digest, update_ids_digest
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import snort as snort_module
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    ExactPublicationKey,
)
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
from evidenceforge.generation.emitters.snort import SnortEmitter

T0 = datetime(2026, 1, 1, tzinfo=UTC)


class _CommitLostReturnConnection:
    """Delegate SQLite operations but fail after one selected real commit."""

    def __init__(self, connection: sqlite3.Connection, *, fail_on_commit: int = 1) -> None:
        self._connection = connection
        self.commit_calls = 0
        self._fail_on_commit = fail_on_commit

    def commit(self) -> None:
        self.commit_calls += 1
        self._connection.commit()
        if self.commit_calls == self._fail_on_commit:
            raise RuntimeError("SQLite commit returned late")

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)


def _bash_event(command: str, *, second: int = 0) -> dict[str, object]:
    return {
        "timestamp": T0 + timedelta(seconds=second),
        "username": "alice",
        "hostname": "linux-01",
        "host_fqdn": "linux-01.example.test",
        "command": command,
    }


def _bash_path(root: Path) -> Path:
    return root / "linux-01.example.test" / "bash_history" / "alice.bash_history"


def _snort_event(message: str, *, second: int = 0, candidate: bool = True) -> dict[str, object]:
    event: dict[str, object] = {
        "timestamp": T0 + timedelta(seconds=second),
        "gid": 1,
        "sid": 1001,
        "rev": 1,
        "message": message,
        "classification": "misc-activity",
        "priority": 2,
        "protocol": "TCP",
        "src_ip": "10.0.0.1",
        "src_port": 50_000 + second,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "_cluster_id": "cluster-1",
        "_occurrence_id": f"occurrence-{second}",
        "_ids_origin": "built_in" if candidate else "raw",
    }
    if candidate:
        event["_ids_candidate"] = True
    return event


def _publish_exact(emitter: object, event: dict[str, object]) -> None:
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(event))
    batch.release_no_fail()


def _upgrade_pending_bash_ordinary_route(emitter: BashHistoryEmitter) -> None:
    """Enter exact journal mode without admitting the staged placeholder row."""

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_bash_event("cancelled exact upgrade")))
    batch.cancel()


def test_bash_ordinary_flush_boundaries_keep_legacy_clear_and_order_bytes(
    tmp_path: Path,
) -> None:
    """Ordinary history remains sorted and cleared per flush, never globally."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("later", second=20))
    emitter.flush()

    emitter.emit_event(_bash_event("history -c", second=15))
    emitter.emit_event(_bash_event("survivor", second=30))
    emitter.flush()
    emitter.emit_event(_bash_event("stale-next-flush", second=10))
    emitter.flush()

    expected = (
        f"#{int((T0 + timedelta(seconds=30)).timestamp())}\nsurvivor\n"
        f"#{int((T0 + timedelta(seconds=10)).timestamp())}\nstale-next-flush\n"
    ).encode()
    assert _bash_path(tmp_path).read_bytes() == expected
    emitter.close()
    assert _bash_path(tmp_path).read_bytes() == expected


def test_snort_ordinary_raw_flush_visibility_and_bytes_are_unchanged(tmp_path: Path) -> None:
    """An ordinary raw alert is physically visible at flush, before close."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    emitter.emit_raw(_snort_event("ordinary raw", candidate=False))
    emitter.flush()

    flushed = output.read_bytes()
    assert flushed.count(b"ordinary raw") == 1
    assert flushed.endswith(b"\n")
    emitter.close()
    assert output.read_bytes() == flushed


def test_bash_exact_admission_freezes_final_row_and_reconciles_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable insert followed by an exception retries without rerendering."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _bash_event("frozen")
    original = emitter._commit_exact_history
    fail_after = True

    def commit_then_raise(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal fail_after
        original(key, digest, frozen)
        if fail_after:
            fail_after = False
            raise RuntimeError("Bash admission returned late")

    monkeypatch.setattr(emitter, "_commit_exact_history", commit_then_raise)
    with pytest.raises(RuntimeError, match="returned late"):
        batch.publish(lambda: emitter.emit_event(event))
    event["command"] = "mutated"
    batch.publish(lambda: emitter.emit_event(event))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("\nfrozen\n") == 1
    assert "mutated" not in rendered


def test_bash_sqlite_admission_commit_lost_return_reconstructs_exact_census(
    tmp_path: Path,
) -> None:
    """A durable SQLite commit is adopted on retry without accounting underflow."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("ordinary journal opener"))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_bash_event("reconciled exact", second=1)))
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection)
    writer._connection = proxy  # type: ignore[assignment]

    prepared = emitter.journal_census()
    with pytest.raises(RuntimeError, match="commit returned late"):
        batch.commit()

    failed = emitter.journal_census()
    assert failed.pending_operations == prepared.pending_operations == 1
    assert failed.reserved_rows == prepared.reserved_rows
    assert failed.reserved_bytes == prepared.reserved_bytes
    assert failed.admission_receipts == failed.export_receipts == 0
    assert writer._pending_rows == 1

    batch.commit()
    admitted = emitter.journal_census()
    assert proxy.commit_calls == 1
    assert admitted.pending_operations == 2
    assert admitted.reserved_rows == admitted.reserved_bytes == 0
    assert admitted.admission_receipts == 1
    assert writer._pending_rows == 2
    assert writer._receipt_rows == writer._admission_receipts == 1

    emitter.flush()
    exported = emitter.journal_census()
    assert exported.pending_operations == 0
    assert exported.admission_receipts == exported.export_receipts == 1
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("ordinary journal opener") == 1
    assert rendered.count("reconciled exact") == 1
    terminal = emitter.journal_census()
    assert terminal.retained_rows == terminal.retained_bytes == 0
    assert emitter.event_count == 2


def test_bash_duplicate_writer_retry_is_exactly_once_and_census_neutral(tmp_path: Path) -> None:
    """A duplicate adapter retry cannot charge or retain the same exact row twice."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("ordinary control"))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_bash_event("duplicate control", second=1)))
    batch.commit()

    writer = next(iter(emitter._writers.values()))
    prepared_rows = batch._prepared_rows
    assert prepared_rows is not None and len(prepared_rows) == 1
    row = prepared_rows[0]
    assert type(row.frozen_content) is str
    envelope = json.loads(row.frozen_content)
    before = emitter.journal_census()
    writer_state = (
        writer._pending_rows,
        writer._pending_bytes,
        writer._receipt_rows,
        writer._admission_receipts,
        writer._retained_event_count,
    )

    writer.commit_exact(
        batch._row_key(0),
        row.content_digest,
        envelope["rendered"],
        row.retained_bytes,
    )

    assert emitter.journal_census() == before
    assert (
        writer._pending_rows,
        writer._pending_bytes,
        writer._receipt_rows,
        writer._admission_receipts,
        writer._retained_event_count,
    ) == writer_state

    emitter.flush()
    batch.release_no_fail()
    emitter.close()
    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("ordinary control") == 1
    assert rendered.count("duplicate control") == 1


@pytest.mark.parametrize("exported", [False, True], ids=["unexported-update", "exported-delete"])
def test_bash_release_commit_lost_return_reconciles_once_and_reuses_route(
    tmp_path: Path,
    exported: bool,
) -> None:
    """Durable release state owns retry accounting for both UPDATE and DELETE."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("release first")))
    writer = next(iter(emitter._writers.values()))
    if exported:
        emitter.flush()
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection)
    writer._connection = proxy  # type: ignore[assignment]
    before = emitter.journal_census()

    with pytest.raises(RuntimeError, match="commit returned late"):
        batch.release_no_fail()

    assert emitter.journal_census() == before
    assert writer._exact_release_receipts
    assert writer._exact_receipts
    with pytest.raises(ExactPublicationError, match="releases to reconcile"):
        emitter.flush()
    batch.release_no_fail()
    batch.release_no_fail()
    assert proxy.commit_calls == 1
    assert writer._exact_release_receipts == {}
    assert writer._exact_receipts == {}

    if not exported:
        emitter.flush()
    assert emitter._writers == {}
    released = emitter.journal_census()
    assert released.retained_rows == released.retained_bytes == 0

    emitter.emit_event(_bash_event("release later ordinary", second=1))
    _publish_exact(emitter, _bash_event("release later exact", second=2))
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("release first") == 1
    assert rendered.count("release later ordinary") == 1
    assert rendered.count("release later exact") == 1
    assert emitter.event_count == 3
    _assert_bash_terminal_state(emitter)


def test_bash_ordinary_insert_commit_lost_return_is_adopted_exactly_once(
    tmp_path: Path,
) -> None:
    """An anonymous durable row is identified by sequence and charged only once."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("ordinary opener"))
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection)
    writer._connection = proxy  # type: ignore[assignment]

    emitter.emit_event(_bash_event("ordinary reconciled", second=1))
    assert proxy.commit_calls == 1
    assert writer._pending_rows == 2
    emitter.flush()
    emitter.flush()
    assert emitter._writers == {}
    assert emitter.journal_census().retained_rows == 0

    emitter.emit_event(_bash_event("ordinary later epoch", second=2))
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("ordinary opener") == 1
    assert rendered.count("ordinary reconciled") == 1
    assert rendered.count("ordinary later epoch") == 1
    assert emitter.event_count == 3
    _assert_bash_terminal_state(emitter)


def test_bash_export_plan_commit_lost_return_retains_and_adopts_sealed_owner(
    tmp_path: Path,
) -> None:
    """A durable plan keeps its temp and budget until retry adopts it once."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("plan first"))
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection)
    writer._connection = proxy  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="commit returned late"):
        emitter.flush()

    pending_plan = writer._unreconciled_export_plan
    assert pending_plan is not None
    assert writer._plan_rows == writer._plan_bytes == 0
    assert (writer.output_path.parent / pending_plan.temporary_name).exists()
    retained = emitter._budget.snapshot()
    assert retained.plan_rows == 1
    assert retained.plan_bytes == pending_plan.working_bytes

    emitter.flush()
    emitter.flush()
    assert proxy.commit_calls == 2
    assert writer._unreconciled_export_plan is None
    assert emitter._writers == {}
    assert emitter.journal_census().retained_rows == 0

    emitter.emit_event(_bash_event("plan later epoch", second=1))
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("plan first") == 1
    assert rendered.count("plan later epoch") == 1
    assert emitter.event_count == 2
    _assert_bash_terminal_state(emitter)


def test_bash_export_completion_commit_lost_return_reconciles_deleted_epoch_once(
    tmp_path: Path,
) -> None:
    """Durable plan deletion retains a local completion owner until retry."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("completion first"))
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection, fail_on_commit=2)
    writer._connection = proxy  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="commit returned late"):
        emitter.flush()

    assert proxy.commit_calls == 2
    assert writer._export_completion is not None
    assert writer._plan_rows == 1
    assert writer._pending_rows == 1
    assert proxy.execute("SELECT singleton FROM export_plan WHERE singleton = 1").fetchone() is None
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("completion first") == 1

    emitter.flush()
    emitter.flush()
    assert proxy.commit_calls == 2
    assert writer._export_completion is None
    assert emitter._writers == {}
    assert emitter.journal_census().retained_rows == 0

    emitter.emit_event(_bash_event("completion later epoch", second=1))
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("completion first") == 1
    assert rendered.count("completion later epoch") == 1
    assert emitter.event_count == 2
    _assert_bash_terminal_state(emitter)


def test_bash_export_completion_lost_return_allows_immediate_exact_release(
    tmp_path: Path,
) -> None:
    """Release first reconciles a committed export owner before deleting its receipt."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("completion active first")))
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    proxy = _CommitLostReturnConnection(connection, fail_on_commit=2)
    writer._connection = proxy  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="commit returned late"):
        emitter.flush()

    assert writer._export_completion is not None
    assert writer._export_completion.active_exact == 1
    assert emitter.journal_census().export_receipts == 0
    batch.release_no_fail()
    batch.release_no_fail()

    assert proxy.commit_calls == 3
    assert writer._export_completion is None
    assert emitter._writers == {}
    assert emitter.journal_census().retained_rows == 0
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("completion active first") == 1

    emitter.emit_event(_bash_event("later route epoch", second=1))
    emitter.close()
    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("completion active first") == 1
    assert rendered.count("later route epoch") == 1
    assert emitter.event_count == 2
    _assert_bash_terminal_state(emitter)


def test_bash_exact_clear_is_an_ordered_operation_not_a_global_resort(tmp_path: Path) -> None:
    """Exact clear order is frozen while later ordinary flushes remain independent."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    emitter.emit_event(_bash_event("ordinary-before", second=20))
    emitter.flush()

    batch = ExactPublicationAuthority(capacity=1).issue_batch()

    def render() -> None:
        emitter.emit_event(_bash_event("history -c", second=15))
        emitter.emit_event(_bash_event("exact-survivor", second=30))

    batch.prepare(render)
    assert _bash_path(tmp_path).read_text(encoding="utf-8") == (
        f"#{int((T0 + timedelta(seconds=20)).timestamp())}\nordinary-before\n"
    )
    batch.commit()
    batch.release_no_fail()
    emitter.flush()
    emitter.emit_event(_bash_event("ordinary-next-epoch", second=10))
    emitter.close()

    commands = _bash_path(tmp_path).read_text(encoding="utf-8").splitlines()[1::2]
    assert commands == ["exact-survivor", "ordinary-next-epoch"]


def test_bash_threaded_exact_drain_keeps_the_current_logical_flush_epoch(
    tmp_path: Path,
) -> None:
    """The exact FIFO drain must not physically flush preceding ordinary work."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    emitter.emit_event(_bash_event("later", second=20))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_bash_event("history -c", second=15)))
    assert not _bash_path(tmp_path).exists()
    batch.commit()
    batch.release_no_fail()
    emitter.close()

    assert _bash_path(tmp_path).read_text(encoding="utf-8") == (
        f"#{int((T0 + timedelta(seconds=20)).timestamp())}\nlater\n"
    )


def test_bash_direct_reserve_drains_prior_fifo_without_physical_flush(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct participant reservation fences only after prior ordinary dispatch."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    ordinary_entered = Event()
    release_ordinary = Event()
    original_dispatch = emitter._dispatch
    block_once = True

    def block_prior_ordinary(event_data: dict[str, object]) -> None:
        nonlocal block_once
        if block_once and "prior ordinary" in str(event_data.get("rendered")):
            block_once = False
            ordinary_entered.set()
            assert release_ordinary.wait(timeout=2)
        original_dispatch(event_data)

    monkeypatch.setattr(emitter, "_dispatch", block_prior_ordinary)
    emitter.emit_event(_bash_event("prior ordinary"))
    assert ordinary_entered.wait(timeout=2)

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    reserved = Event()
    failures: list[BaseException] = []
    reserver = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.reserve_participants((emitter,))),
            reserved.set(),
        )
    )
    reserver.start()
    assert not reserved.wait(timeout=0.1)
    assert not _bash_path(tmp_path).exists()

    release_ordinary.set()
    assert reserved.wait(timeout=2)
    reserver.join(timeout=2)
    assert failures == []
    assert not _bash_path(tmp_path).exists()

    batch.prepare(lambda: emitter.emit_event(_bash_event("reserved exact", second=1)))
    batch.commit()
    batch.release_no_fail()
    emitter.close()

    commands = _bash_path(tmp_path).read_text(encoding="utf-8").splitlines()[1::2]
    assert commands == ["prior ordinary", "reserved exact"]
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_public_barrier_retains_legacy_physical_flush(tmp_path: Path) -> None:
    """A public barrier is still a real boundary even though exact drain is not."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    emitter.emit_event(_bash_event("prior flush", second=20))
    emitter.barrier_flush()
    assert b"prior flush" in _bash_path(tmp_path).read_bytes()

    _publish_exact(emitter, _bash_event("history -c", second=15))
    emitter.close()
    assert _bash_path(tmp_path).read_bytes() == b""


def test_bash_threaded_drain_baseexception_is_acknowledged_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drain-control BaseException wakes the producer without killing the worker."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    original = emitter._process_exact_drain
    fail_once = True

    def interrupt_once() -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise KeyboardInterrupt("drain interrupted")
        original()

    monkeypatch.setattr(emitter, "_process_exact_drain", interrupt_once)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(KeyboardInterrupt, match="drain interrupted"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("retry me")))
    batch.prepare(lambda: emitter.emit_event(_bash_event("retry me")))
    batch.commit()
    batch.release_no_fail()
    assert emitter._thread is not None and emitter._thread.is_alive()
    emitter.close()
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("retry me") == 1


def test_bash_close_racing_exact_drain_waits_for_terminal_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close cannot overtake drain, participant registration, or exact enqueue."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    entered = Event()
    release = Event()
    original = emitter._drain_threaded_before_exact

    def blocked_drain() -> None:
        entered.set()
        assert release.wait(timeout=2)
        original()

    monkeypatch.setattr(emitter, "_drain_threaded_before_exact", blocked_drain)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    failures: list[BaseException] = []
    prepared = Event()
    producer = Thread(
        target=lambda: (
            _capture_failure(
                failures,
                lambda: batch.prepare(lambda: emitter.emit_event(_bash_event("exact"))),
            ),
            prepared.set(),
        )
    )
    producer.start()
    assert entered.wait(timeout=2)
    closed = Event()
    closer = Thread(target=lambda: (_capture_failure(failures, emitter.close), closed.set()))
    closer.start()
    assert not closed.wait(timeout=0.1)
    release.set()
    assert prepared.wait(timeout=2)
    assert not closed.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    producer.join(timeout=2)
    closer.join(timeout=2)
    assert failures == []
    assert closed.is_set()
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_bash_event("late"))


def test_bash_failed_close_plan_keeps_rows_from_the_next_admission_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rows admitted after a failed close are exported by the following epoch."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    _publish_exact(emitter, _bash_event("first epoch", second=1))
    writer = next(iter(emitter._writers.values()))
    original = writer._replace_output
    fail_after = True

    def replace_then_raise(payload: bytes) -> None:
        nonlocal fail_after
        original(payload)
        if fail_after:
            fail_after = False
            raise RuntimeError("Bash replace returned late")

    monkeypatch.setattr(writer, "_replace_output", replace_then_raise)
    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    assert emitter._close_state == "open"

    _publish_exact(emitter, _bash_event("second epoch", second=2))
    emitter.close()
    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("first epoch") == 1
    assert rendered.count("second epoch") == 1


@pytest.mark.parametrize("operation", ["replace", "unlink", "fsync"])
def test_bash_threaded_failed_close_keeps_worker_live_for_later_ordinary_and_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """A lost close return cannot reopen admission with a stopped worker."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    emitter.emit_event(_bash_event("initial ordinary"))
    emitter._drain_threaded_before_exact()
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    fail_once = True

    if operation == "replace":
        original_replace = writer._replace_output

        def replace_then_raise(payload: object) -> None:
            nonlocal fail_once
            original_replace(payload)
            if fail_once:
                fail_once = False
                raise RuntimeError("threaded replace returned late")

        monkeypatch.setattr(writer, "_replace_output", replace_then_raise)
    elif operation == "unlink":
        original_unlink = writer._unlink_cleanup_journal

        def unlink_then_raise(directory_descriptor: int, journal_name: str) -> None:
            nonlocal fail_once
            original_unlink(directory_descriptor, journal_name)
            if fail_once:
                fail_once = False
                raise RuntimeError("threaded unlink returned late")

        monkeypatch.setattr(writer, "_unlink_cleanup_journal", unlink_then_raise)
    else:
        original_fsync = writer._fsync_cleanup_directory

        def fsync_then_raise(directory_descriptor: int) -> None:
            nonlocal fail_once
            original_fsync(directory_descriptor)
            if fail_once:
                fail_once = False
                raise RuntimeError("threaded fsync returned late")

        monkeypatch.setattr(writer, "_fsync_cleanup_directory", fsync_then_raise)

    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    assert emitter._close_state == "open"
    assert emitter._thread is not None and emitter._thread.is_alive()

    emitter.emit_event(_bash_event("later ordinary", second=1))
    _publish_exact(emitter, _bash_event("later exact", second=2))
    emitter.close()

    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("initial ordinary") == 1
    assert rendered.count("later ordinary") == 1
    assert rendered.count("later exact") == 1
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("operation", ["rmdir", "parent-fsync"])
def test_bash_threaded_private_cleanup_failed_close_allows_later_epochs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """A private-root lost return is reconciled before threaded admission reopens."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root, threaded=True)
    emitter.emit_event(_bash_event("private-close initial ordinary"))
    emitter._drain_threaded_before_exact()
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    journal_directory = writer._journal_directory
    assert journal_directory is not None
    original_close = journal_directory.close
    close_calls = 0
    operation_calls = 0
    fail_once = True

    def counted_close() -> None:
        nonlocal close_calls
        close_calls += 1
        original_close()

    monkeypatch.setattr(journal_directory, "close", counted_close)
    if operation == "rmdir":
        original_remove = journal_directory._remove_directory

        def remove_then_raise(
            parent_descriptor: int,
            directory_name: str,
            path: Path,
        ) -> None:
            nonlocal fail_once, operation_calls
            operation_calls += 1
            original_remove(parent_descriptor, directory_name, path)
            if fail_once:
                fail_once = False
                raise RuntimeError("threaded private rmdir returned late")

        monkeypatch.setattr(journal_directory, "_remove_directory", remove_then_raise)
    else:
        original_fsync = journal_directory._fsync_parent

        def fsync_then_raise(parent_descriptor: int) -> None:
            nonlocal fail_once, operation_calls
            operation_calls += 1
            original_fsync(parent_descriptor)
            if fail_once:
                fail_once = False
                raise RuntimeError("threaded private parent fsync returned late")

        monkeypatch.setattr(journal_directory, "_fsync_parent", fsync_then_raise)

    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    assert close_calls >= 2
    assert operation_calls == (1 if operation == "rmdir" else 2)
    assert emitter._close_state == "open"
    assert emitter._thread is not None and emitter._thread.is_alive()

    emitter.emit_event(_bash_event("private-close later ordinary", second=1))
    _publish_exact(emitter, _bash_event("private-close later exact", second=2))
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("private-close initial ordinary") == 1
    assert rendered.count("private-close later ordinary") == 1
    assert rendered.count("private-close later exact") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_capacity_charges_reservation_admission_export_and_terminal_gc(
    tmp_path: Path,
) -> None:
    """Every retained exact object is visible in the constant-time census."""

    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path,
        journal_row_capacity=16,
        journal_byte_capacity=64 * 1024,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_bash_event("charged")))
    prepared = emitter.journal_census()
    assert prepared.reserved_rows >= 2
    assert prepared.retained_rows == 1

    batch.commit()
    admitted = emitter.journal_census()
    assert admitted.pending_operations == 1
    assert admitted.admission_receipts == 1
    assert admitted.retained_rows >= 2
    emitter.flush()
    exported = emitter.journal_census()
    assert exported.pending_operations == 0
    assert exported.export_receipts == 1
    assert exported.admission_receipts == 1

    batch.release_no_fail()
    terminal = emitter.journal_census()
    assert terminal.retained_rows == terminal.retained_bytes == 0
    emitter.close()


def test_bash_private_journal_and_close_fence_cover_whole_ordinary_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close claims admission before waiting and private SQLite stays mode 0600."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    _publish_exact(emitter, _bash_event("journal"))
    writer = next(iter(emitter._writers.values()))
    journal_path = writer._journal_path
    assert journal_path is not None
    assert not journal_path.is_relative_to(tmp_path)
    assert stat.S_IMODE(journal_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600

    entered = Event()
    release = Event()
    original_dispatch = emitter._dispatch

    def blocked_dispatch(event_data: dict[str, object]) -> None:
        entered.set()
        assert release.wait(timeout=2)
        original_dispatch(event_data)

    monkeypatch.setattr(emitter, "_dispatch", blocked_dispatch)
    failures: list[BaseException] = []
    ordinary = Thread(
        target=lambda: _capture_failure(
            failures,
            lambda: emitter.emit_event(_bash_event("ordinary in flight", second=2)),
        )
    )
    ordinary.start()
    assert entered.wait(timeout=2)
    closed = Event()
    closer = Thread(target=lambda: (_capture_failure(failures, emitter.close), closed.set()))
    closer.start()
    assert _wait_for_state(emitter, "closing")
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_bash_event("late", second=3))
    assert not closed.wait(timeout=0.1)
    release.set()
    ordinary.join(timeout=2)
    closer.join(timeout=2)
    assert failures == []
    assert not journal_path.parent.exists()


def test_bash_threaded_two_row_batch_does_not_deadlock_interleaved_ordinary(
    tmp_path: Path,
) -> None:
    """Ordinary admission cannot occupy the FIFO between rows of one exact batch."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    first_staged = Event()
    allow_second = Event()
    prepared = Event()
    ordinary_done = Event()
    failures: list[BaseException] = []

    def render() -> None:
        emitter.emit_event(_bash_event("exact first", second=10))
        first_staged.set()
        assert allow_second.wait(timeout=2)
        emitter.emit_event(_bash_event("exact second", second=30))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)
    ordinary = Thread(
        target=lambda: (
            _capture_failure(
                failures,
                lambda: emitter.emit_event(_bash_event("ordinary middle", second=20)),
            ),
            ordinary_done.set(),
        ),
        daemon=True,
    )
    ordinary.start()
    assert not ordinary_done.wait(timeout=0.1)
    allow_second.set()
    assert prepared.wait(timeout=2)
    assert not ordinary_done.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    assert ordinary_done.wait(timeout=2)
    producer.join(timeout=2)
    ordinary.join(timeout=2)
    emitter.close()

    assert failures == []
    assert _bash_path(tmp_path).read_text(encoding="utf-8").splitlines()[1::2] == [
        "exact first",
        "ordinary middle",
        "exact second",
    ]
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_barrier_between_exact_rows_waits_outside_admission_lock(
    tmp_path: Path,
) -> None:
    """A public barrier waits without preventing the registered batch continuing."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    first_staged = Event()
    allow_second = Event()
    prepared = Event()
    barrier_done = Event()
    failures: list[BaseException] = []

    def render() -> None:
        emitter.emit_event(_bash_event("exact first", second=10))
        first_staged.set()
        assert allow_second.wait(timeout=2)
        emitter.emit_event(_bash_event("exact second", second=20))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)
    barrier = Thread(
        target=lambda: (
            _capture_failure(failures, emitter.barrier_flush),
            barrier_done.set(),
        ),
        daemon=True,
    )
    barrier.start()
    assert not barrier_done.wait(timeout=0.1)
    allow_second.set()
    assert prepared.wait(timeout=2)
    batch.commit()
    batch.release_no_fail()
    assert barrier_done.wait(timeout=2)
    producer.join(timeout=2)
    barrier.join(timeout=2)
    emitter.close()

    assert failures == []
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("exact") == 2
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_close_between_exact_rows_allows_registered_continuation(
    tmp_path: Path,
) -> None:
    """Close claims new admission while the already-fenced batch finishes rendering."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    first_staged = Event()
    allow_second = Event()
    prepared = Event()
    closed = Event()
    failures: list[BaseException] = []

    def render() -> None:
        emitter.emit_event(_bash_event("exact first", second=10))
        first_staged.set()
        assert allow_second.wait(timeout=2)
        emitter.emit_event(_bash_event("exact second", second=20))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)
    closer = Thread(
        target=lambda: (_capture_failure(failures, emitter.close), closed.set()),
        daemon=True,
    )
    closer.start()
    assert _wait_for_state(emitter, "closing")
    allow_second.set()
    assert prepared.wait(timeout=2)
    assert not closed.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    producer.join(timeout=2)
    closer.join(timeout=2)

    assert failures == []
    assert closed.is_set()
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("exact") == 2
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_foreign_batch_waits_without_blocking_current_render(
    tmp_path: Path,
) -> None:
    """A foreign exact producer never holds admission while waiting for the owner."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    first_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    second_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    first_staged = Event()
    finish_first = Event()
    first_prepared = Event()
    second_started = Event()
    second_prepared = Event()
    failures: list[BaseException] = []

    def first_render() -> None:
        emitter.emit_event(_bash_event("first batch", second=10))
        first_staged.set()
        assert finish_first.wait(timeout=2)
        emitter.emit_event(_bash_event("first continuation", second=20))

    first = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: first_batch.prepare(first_render)),
            first_prepared.set(),
        ),
        daemon=True,
    )
    first.start()
    assert first_staged.wait(timeout=2)

    def prepare_second() -> None:
        second_started.set()
        _capture_failure(
            failures,
            lambda: second_batch.prepare(
                lambda: emitter.emit_event(_bash_event("second batch", second=30))
            ),
        )
        second_prepared.set()

    second = Thread(target=prepare_second, daemon=True)
    second.start()
    assert second_started.wait(timeout=2)
    assert not second_prepared.wait(timeout=0.1)
    finish_first.set()
    assert first_prepared.wait(timeout=2)
    first_batch.commit()
    first_batch.release_no_fail()
    assert second_prepared.wait(timeout=2)
    second_batch.commit()
    second_batch.release_no_fail()
    first.join(timeout=2)
    second.join(timeout=2)
    emitter.close()

    assert failures == []
    rendered = _bash_path(tmp_path).read_text(encoding="utf-8")
    assert rendered.count("first batch") == 1
    assert rendered.count("first continuation") == 1
    assert rendered.count("second batch") == 1
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_worker_death_before_registration_cleans_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worker death during the drain fails promptly without retaining authority."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)

    def kill_worker(_queue_item: object) -> bool:
        raise SystemExit("worker died before registration")

    monkeypatch.setattr(emitter, "_handle_exact_drain_request", kill_worker)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("never admitted")))
    batch.cancel()
    assert emitter._active_exact_publication_keys == set()
    assert emitter._event_queue is not None and emitter._event_queue.unfinished_tasks == 0
    assert emitter.journal_census().retained_rows == 0
    assert emitter._stop_event is not None
    emitter._thread_error = None
    emitter._stop_event.set()
    emitter.close()
    assert not _bash_path(tmp_path).exists()
    _assert_bash_terminal_state(emitter)


def test_bash_threaded_worker_death_after_enqueue_releases_participant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A death after exact enqueue cannot strand the participant or publish later."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    original = bash_history_module.exact_publication_queue_payload

    def kill_on_exact(queue_item: object) -> tuple[object, object | None]:
        if type(queue_item).__name__ == "_ExactQueuedPublication":
            raise SystemExit("worker died after enqueue")
        return original(queue_item)

    monkeypatch.setattr(bash_history_module, "exact_publication_queue_payload", kill_on_exact)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("never staged")))
    batch.cancel()
    assert emitter._active_exact_publication_keys == set()
    assert emitter._event_queue is not None and emitter._event_queue.unfinished_tasks == 0
    assert emitter.journal_census().retained_rows == 0
    assert emitter._stop_event is not None
    emitter._thread_error = None
    emitter._stop_event.set()
    emitter.close()
    assert not _bash_path(tmp_path).exists()
    _assert_bash_terminal_state(emitter)


def test_bash_close_after_registration_cannot_overtake_exact_enqueue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registration and queue handoff form one close-serialized admission."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=True)
    entered = Event()
    release = Event()
    prepared = Event()
    closed = Event()
    failures: list[BaseException] = []
    original = emitter._handoff_exact_event

    def blocked_handoff(event_data: dict[str, object], attempt: object) -> object:
        entered.set()
        assert release.wait(timeout=2)
        return original(event_data, attempt)

    monkeypatch.setattr(emitter, "_handoff_exact_event", blocked_handoff)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    producer = Thread(
        target=lambda: (
            _capture_failure(
                failures,
                lambda: batch.prepare(lambda: emitter.emit_event(_bash_event("exact"))),
            ),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert entered.wait(timeout=2)
    assert emitter._active_exact_publication_keys
    closer = Thread(
        target=lambda: (_capture_failure(failures, emitter.close), closed.set()),
        daemon=True,
    )
    closer.start()
    assert not closed.wait(timeout=0.1)
    assert emitter._close_state == "open"
    release.set()
    assert prepared.wait(timeout=2)
    assert not closed.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    producer.join(timeout=2)
    closer.join(timeout=2)

    assert failures == []
    assert closed.is_set()
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("exact") == 1
    _assert_bash_terminal_state(emitter)


def test_bash_caller_callbacks_and_reentry_run_outside_admission_lock(
    tmp_path: Path,
) -> None:
    """Caller deepcopy/string hooks may re-enter public APIs without owning admission."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    observed_lock_states: list[bool] = []
    observed_hooks: list[str] = []
    failures: list[BaseException] = []
    completed = Event()

    class DetachedCommand:
        def __str__(self) -> str:
            observed_hooks.append("string")
            observed_lock_states.append(emitter._admission_lock._is_owned())
            emitter.flush()
            return "callback-safe"

        def __del__(self) -> None:
            observed_hooks.append("finalizer")
            observed_lock_states.append(emitter._admission_lock._is_owned())
            emitter.flush()

    class ReentrantCommand:
        def __deepcopy__(self, _memo: object) -> DetachedCommand:
            observed_hooks.append("deepcopy")
            observed_lock_states.append(emitter._admission_lock._is_owned())
            emitter.flush()
            return DetachedCommand()

    event = _bash_event("placeholder")
    event["command"] = ReentrantCommand()
    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: emitter.emit_event(event)),
            completed.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert completed.wait(timeout=2)
    producer.join(timeout=2)
    assert failures == []
    assert set(observed_hooks) == {"deepcopy", "string", "finalizer"}
    assert observed_lock_states and not any(observed_lock_states)
    emitter.close()
    assert "callback-safe" in _bash_path(tmp_path).read_text(encoding="utf-8")


@pytest.mark.parametrize("operation", ["flush", "close"])
def test_bash_exact_reentrant_callback_fails_promptly_without_deadlock(
    tmp_path: Path,
    operation: str,
) -> None:
    """A callback in a continuation cannot wait on the participant it currently owns."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    completed = Event()
    failures: list[BaseException] = []

    class ReentrantContinuation:
        def __deepcopy__(self, _memo: object) -> ReentrantContinuation:
            return self

        def __str__(self) -> str:
            getattr(emitter, operation)()
            return "never staged"

    def render() -> None:
        emitter.emit_event(_bash_event("first staged"))
        second = _bash_event("placeholder", second=1)
        second["command"] = ReentrantContinuation()
        emitter.emit_event(second)

    producer = Thread(
        target=lambda: (_capture_failure(failures, lambda: batch.prepare(render)), completed.set()),
        daemon=True,
    )
    producer.start()
    assert completed.wait(timeout=2)
    producer.join(timeout=2)
    assert len(failures) == 1
    assert isinstance(failures[0], ExactPublicationError)
    assert "cannot re-enter" in str(failures[0])
    assert emitter._active_exact_publication_keys == set()
    assert emitter.journal_census().retained_rows == emitter.journal_census().reserved_rows == 0
    batch.cancel()
    emitter.close()


def test_bash_global_route_cap_rejects_before_second_route_allocation(tmp_path: Path) -> None:
    """The exact route cap does not constrain legacy ordinary-only writers."""

    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path,
        journal_route_capacity=1,
        journal_row_capacity=32,
        journal_byte_capacity=64 * 1024,
    )
    emitter.emit_event(_bash_event("first route"))
    second = _bash_event("second route")
    second["username"] = "bob"
    second["host_fqdn"] = "linux-02.example.test"
    emitter.emit_event(second)

    census = emitter.journal_census()
    assert census.routes == census.writers == 0
    assert census.retained_rows == census.retained_bytes == 0
    assert census.high_water_rows <= census.row_capacity
    assert census.high_water_bytes <= census.byte_capacity
    assert not (tmp_path / "linux-02.example.test").exists()
    emitter.close()
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("first route") == 1
    second_output = tmp_path / "linux-02.example.test" / "bash_history" / "bob.bash_history"
    assert second_output.read_text(encoding="utf-8").count("second route") == 1

    exact_root = tmp_path / "exact"
    exact = BashHistoryEmitter(
        load_format("bash_history"),
        exact_root,
        journal_route_capacity=1,
        journal_row_capacity=16,
        journal_byte_capacity=64 * 1024,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()

    def render_two_routes() -> None:
        exact.emit_event(_bash_event("first exact route"))
        exact.emit_event(second)

    with pytest.raises(ExactPublicationError, match="route capacity"):
        batch.prepare(render_two_routes)
    batch.cancel()
    assert exact.journal_census().routes == exact.journal_census().reserved_rows == 0
    assert not exact_root.exists()
    exact.close()


@pytest.mark.parametrize(
    "capacity_name",
    ["journal_route_capacity", "journal_row_capacity", "journal_byte_capacity"],
)
@pytest.mark.parametrize("invalid", [0, -1, True])
def test_bash_global_caps_require_positive_exact_ints(
    tmp_path: Path,
    capacity_name: str,
    invalid: object,
) -> None:
    """Booleans, zero, and negative values cannot disable any global ceiling."""

    with pytest.raises(ValueError, match="positive exact int"):
        BashHistoryEmitter(
            load_format("bash_history"),
            tmp_path,
            **{capacity_name: invalid},
        )


def test_bash_exact_global_row_and_byte_caps_have_hard_boundaries(tmp_path: Path) -> None:
    """Exact route plus row reservations fit at equality and fail one unit below."""

    probe = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path / "probe",
        journal_route_capacity=1,
        journal_row_capacity=4,
        journal_byte_capacity=64 * 1024,
    )
    probe_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    probe_batch.prepare(lambda: probe.emit_event(_bash_event("boundary")))
    required_bytes = probe.journal_census().high_water_bytes
    assert probe.journal_census().high_water_rows == 4
    probe_batch.cancel()
    assert probe.journal_census().retained_rows == probe.journal_census().reserved_rows == 0
    probe.close()

    exact = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path / "exact",
        journal_route_capacity=1,
        journal_row_capacity=4,
        journal_byte_capacity=required_bytes,
    )
    exact_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    exact_batch.prepare(lambda: exact.emit_event(_bash_event("boundary")))
    exact_census = exact.journal_census()
    assert exact_census.high_water_rows == exact_census.row_capacity == 4
    assert exact_census.high_water_bytes == exact_census.byte_capacity == required_bytes
    exact_batch.cancel()
    exact.close()

    rejected = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path / "rejected",
        journal_route_capacity=1,
        journal_row_capacity=4,
        journal_byte_capacity=required_bytes - 1,
    )
    rejected_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="byte capacity"):
        rejected_batch.prepare(lambda: rejected.emit_event(_bash_event("boundary")))
    rejected_batch.cancel()
    rejected_census = rejected.journal_census()
    assert rejected_census.retained_rows == rejected_census.reserved_rows == 0
    assert rejected_census.high_water_bytes <= rejected_census.byte_capacity
    assert not (tmp_path / "rejected" / "linux-01.example.test").exists()
    rejected.close()


def test_bash_ordinary_rows_bypass_exact_journal_caps_and_private_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy ordinary rows neither consume exact capacity nor allocate a spool."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path / "root",
        journal_route_capacity=1,
        journal_row_capacity=1,
        journal_byte_capacity=1,
    )
    emitter.emit_event(_bash_event("ordinary ignores exact cap"))
    census = emitter.journal_census()
    assert census.writers == census.routes == 0
    assert census.retained_rows == census.retained_bytes == 0
    assert census.high_water_rows <= census.row_capacity
    assert not spool_root.exists()
    emitter.flush()
    assert (
        _bash_path(tmp_path / "root")
        .read_text(encoding="utf-8")
        .count("ordinary ignores exact cap")
        == 1
    )
    emitter.close()
    assert not spool_root.exists()


@pytest.mark.parametrize("capacity_kind", ["row", "byte"])
@pytest.mark.parametrize("delta", [-1, 0, 1], ids=["one-under", "exact", "plus-one"])
def test_bash_exact_upgrade_preflights_complete_ordinary_buffer_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capacity_kind: str,
    delta: int,
) -> None:
    """A complete migration fits at its direct boundary or rejects without a trace."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    ordinary_events = (
        _bash_event("migration ordinary first"),
        _bash_event("migration ordinary second", second=1),
    )
    exact_event = _bash_event("migration exact", second=3)
    sizing = BashHistoryEmitter(load_format("bash_history"), tmp_path / "sizing")
    for event in ordinary_events:
        sizing.emit_event(event)
    sizing_writer = next(iter(sizing._writers.values()))
    migration_rows, migration_bytes = sizing_writer.ordinary_migration_requirements()
    prepared = sizing._prepare_event(exact_event)
    exact_bytes = len(prepared["envelope"].encode("utf-8"))
    required_rows = migration_rows + bash_history_module._EXACT_RESERVATION_ROWS + 1
    required_bytes = (
        migration_bytes + exact_bytes + required_rows * bash_history_module._EXACT_METADATA_BYTES
    )
    sizing.close()

    row_capacity = required_rows + (delta if capacity_kind == "row" else 8)
    byte_capacity = required_bytes + (delta if capacity_kind == "byte" else 64 * 1024)
    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        root,
        journal_route_capacity=1,
        journal_row_capacity=row_capacity,
        journal_byte_capacity=byte_capacity,
    )
    for event in ordinary_events:
        emitter.emit_event(event)
    writer = next(iter(emitter._writers.values()))
    buffered = tuple(writer._ordinary_buffer)
    before = emitter.journal_census()
    token_calls = 0
    batch = ExactPublicationAuthority(capacity=1).issue_batch()

    def deterministic_token_hex(_byte_count: int) -> str:
        nonlocal token_calls
        token_calls += 1
        return f"{token_calls:032x}"

    monkeypatch.setattr(bash_history_module.secrets, "token_hex", deterministic_token_hex)
    if delta < 0:
        with pytest.raises(ExactPublicationError, match=f"{capacity_kind} capacity"):
            batch.prepare(lambda: emitter.emit_event(exact_event))
        assert batch.state == "issued"
        assert emitter.journal_census() == before
        assert emitter.event_count == len(ordinary_events)
        assert tuple(writer._ordinary_buffer) == buffered
        assert not writer._journal_mode
        assert not writer.exact_route_active
        assert writer._journal_directory is None
        assert writer._connection is None
        assert token_calls == 0
        assert not spool_root.exists()
        assert not _bash_path(root).exists()

        emitter.emit_event(_bash_event("migration ordinary after rejection", second=2))
        emitter.flush()
        emitter._budget.row_capacity = 128
        emitter._budget.byte_capacity = 128 * 1024
        batch.publish(lambda: emitter.emit_event(exact_event))
    else:
        batch.prepare(lambda: emitter.emit_event(exact_event))
        admitted_boundary = emitter.journal_census()
        if capacity_kind == "row":
            assert admitted_boundary.high_water_rows == required_rows
            assert admitted_boundary.row_capacity == required_rows + delta
        else:
            assert admitted_boundary.high_water_bytes == required_bytes
            assert admitted_boundary.byte_capacity == required_bytes + delta
        assert token_calls == 1
        emitter._budget.row_capacity = 128
        emitter._budget.byte_capacity = 128 * 1024
        batch.commit()

    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    commands = ["migration ordinary first", "migration ordinary second"]
    if delta < 0:
        commands.append("migration ordinary after rejection")
    commands.append("migration exact")
    positions = [rendered.index(f"\n{command}\n") for command in commands]
    assert positions == sorted(positions)
    for command in commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_mid_migration_failure_rolls_back_whole_buffer_and_private_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second-row failure leaves no durable prefix and retries the FIFO exactly once."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    emitter.emit_event(_bash_event("migration rollback first"))
    emitter.emit_event(_bash_event("migration rollback second", second=1))
    writer = next(iter(emitter._writers.values()))
    buffered = tuple(writer._ordinary_buffer)
    before = emitter.journal_census()
    original_insert = writer._insert_ordinary_migration_row_unlocked
    insert_calls = 0

    def fail_second_insert(
        connection: sqlite3.Connection,
        *,
        epoch: int,
        rendered: str,
        encoded_bytes: int,
    ) -> int:
        nonlocal insert_calls
        insert_calls += 1
        if insert_calls == 2:
            raise RuntimeError("ordinary migration failed mid-transaction")
        return original_insert(
            connection,
            epoch=epoch,
            rendered=rendered,
            encoded_bytes=encoded_bytes,
        )

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with monkeypatch.context() as patch:
        patch.setattr(writer, "_insert_ordinary_migration_row_unlocked", fail_second_insert)
        with pytest.raises(RuntimeError, match="mid-transaction"):
            batch.prepare(
                lambda: emitter.emit_event(_bash_event("migration rollback exact", second=2))
            )

    assert insert_calls == 2
    assert batch.state == "issued"
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert not writer.exact_route_active
    assert writer._ordinary_migration is None
    assert writer._ordinary_migration_reservation is None
    assert writer._journal_directory is None
    assert writer._connection is None
    rolled_back = emitter.journal_census()
    assert rolled_back.retained_rows == before.retained_rows == 0
    assert rolled_back.retained_bytes == before.retained_bytes == 0
    assert not spool_root.exists() or list(spool_root.iterdir()) == []
    assert not _bash_path(root).exists()

    batch.publish(lambda: emitter.emit_event(_bash_event("migration rollback exact", second=2)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    commands = [
        "migration rollback first",
        "migration rollback second",
        "migration rollback exact",
    ]
    positions = [rendered.index(f"\n{command}\n") for command in commands]
    assert positions == sorted(positions)
    for command in commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def _retain_unresolved_bash_migration_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    threaded: bool = False,
) -> tuple[
    BashHistoryEmitter,
    bash_history_module._SingleHistoryWriter,
    ExactPublicationBatch,
    _CommitLostReturnConnection,
    list[bool],
    list[int],
    tuple[str, ...],
]:
    """Leave one durable migration commit behind an unavailable reconciliation seam."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root, threaded=threaded)
    emitter.emit_event(_bash_event("migration owner first"))
    emitter.emit_event(_bash_event("migration owner second", second=1))
    if threaded:
        emitter._drain_threaded_before_exact()
    writer = next(iter(emitter._writers.values()))
    buffered = tuple(writer._ordinary_buffer)
    original_connect = bash_history_module._connect_existing_journal
    original_load = writer._load_ordinary_migration_unlocked
    proxies: list[_CommitLostReturnConnection] = []
    allow_reconciliation = [False]
    reconciliation_calls = [0]

    def lost_return_connect(
        journal_path: Path,
    ) -> sqlite3.Connection | _CommitLostReturnConnection:
        connection = original_connect(journal_path)
        if proxies:
            return connection
        proxy = _CommitLostReturnConnection(connection, fail_on_commit=2)
        proxies.append(proxy)
        return proxy

    def unavailable_reconciliation(
        owner: bash_history_module._OrdinaryMigration,
    ) -> tuple[tuple[int, str, int], ...]:
        reconciliation_calls[0] += 1
        if not allow_reconciliation[0]:
            raise RuntimeError("ordinary migration reconciliation unavailable")
        return original_load(owner)

    monkeypatch.setattr(bash_history_module, "_connect_existing_journal", lost_return_connect)
    monkeypatch.setattr(
        writer,
        "_load_ordinary_migration_unlocked",
        unavailable_reconciliation,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("migration owner exact", second=3)))

    assert len(proxies) == 1
    assert proxies[0].commit_calls == 2
    assert reconciliation_calls == [1]
    assert batch.state == "issued"
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert not _bash_path(root).exists()
    return (
        emitter,
        writer,
        batch,
        proxies[0],
        allow_reconciliation,
        reconciliation_calls,
        buffered,
    )


def _retain_unresolved_rolled_back_bash_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    BashHistoryEmitter,
    bash_history_module._SingleHistoryWriter,
    ExactPublicationBatch,
    list[bool],
    list[int],
    list[int],
    tuple[str, ...],
    Path,
    Path,
]:
    """Retain an owner after rollback succeeds and its first durable read is unavailable."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    emitter.emit_event(_bash_event("rolled back migration first"))
    emitter.emit_event(_bash_event("rolled back migration second", second=1))
    writer = next(iter(emitter._writers.values()))
    buffered = tuple(writer._ordinary_buffer)
    original_commit = writer._commit_ordinary_migration_unlocked
    original_load = writer._load_ordinary_migration_unlocked
    allow_reconciliation = [False]
    commit_calls = [0]
    reconciliation_calls = [0]

    def fail_first_commit(connection: sqlite3.Connection) -> None:
        commit_calls[0] += 1
        if commit_calls[0] == 1:
            raise RuntimeError("ordinary migration commit failed")
        original_commit(connection)

    def unavailable_reconciliation(
        owner: bash_history_module._OrdinaryMigration,
    ) -> tuple[tuple[int, str, int], ...]:
        reconciliation_calls[0] += 1
        if not allow_reconciliation[0]:
            raise RuntimeError("ordinary migration reconciliation unavailable")
        return original_load(owner)

    monkeypatch.setattr(writer, "_commit_ordinary_migration_unlocked", fail_first_commit)
    monkeypatch.setattr(
        writer,
        "_load_ordinary_migration_unlocked",
        unavailable_reconciliation,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        batch.prepare(
            lambda: emitter.emit_event(_bash_event("rolled back migration exact", second=3))
        )

    journal_directory = writer._journal_directory
    journal_path = writer._journal_path
    assert journal_directory is not None and journal_directory.path is not None
    assert journal_path is not None
    assert commit_calls == [1]
    assert reconciliation_calls == [1]
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert not writer._ordinary_migration_rollback_proved
    assert writer.exact_route_active
    return (
        emitter,
        writer,
        batch,
        allow_reconciliation,
        commit_calls,
        reconciliation_calls,
        buffered,
        journal_directory.path,
        journal_path,
    )


def test_bash_migration_commit_lost_return_retains_owner_and_retry_adopts_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable whole-buffer commit survives unavailable first reconciliation."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        proxy,
        allow_reconciliation,
        reconciliation_calls,
        buffered,
    ) = _retain_unresolved_bash_migration_owner(
        tmp_path,
        monkeypatch,
    )

    assert writer.exact_route_active
    retained_owner = emitter.journal_census()
    assert retained_owner.pending_operations == 0
    assert retained_owner.reserved_rows == len(buffered)
    assert writer._connection is proxy

    allow_reconciliation[0] = True
    batch.publish(lambda: emitter.emit_event(_bash_event("migration owner exact", second=3)))
    assert reconciliation_calls == [2]
    assert proxy.commit_calls == 3
    assert writer._ordinary_buffer == []
    assert writer._ordinary_migration is None
    assert writer._ordinary_migration_reservation is None
    assert writer._journal_mode
    assert writer._pending_rows == len(buffered) + 1
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    commands = [
        "migration owner first",
        "migration owner second",
        "migration owner exact",
    ]
    positions = [rendered.index(f"\n{command}\n") for command in commands]
    assert positions == sorted(positions)
    for command in commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("threaded", [False, True], ids=["direct", "threaded"])
def test_bash_unresolved_migration_fences_later_ordinary_suffix_until_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    threaded: bool,
) -> None:
    """A later ordinary row is not admitted until the durable prefix is adopted."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        proxy,
        allow_reconciliation,
        reconciliation_calls,
        buffered,
    ) = _retain_unresolved_bash_migration_owner(
        tmp_path,
        monkeypatch,
        threaded=threaded,
    )
    before = emitter.journal_census()
    before_event_count = emitter.event_count
    before_queue_tasks = emitter._event_queue.unfinished_tasks if threaded else 0

    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        emitter.emit_event(_bash_event("migration owner suffix", second=2))

    assert reconciliation_calls == [2]
    assert proxy.commit_calls == 2
    assert emitter.journal_census() == before
    assert emitter.event_count == before_event_count == len(buffered)
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert not _bash_path(root).exists()
    if threaded:
        assert emitter._event_queue.unfinished_tasks == before_queue_tasks == 0
        assert emitter._thread_error is None
        assert emitter._thread is not None and emitter._thread.is_alive()

    allow_reconciliation[0] = True
    emitter.emit_event(_bash_event("migration owner suffix", second=2))
    if threaded:
        emitter._drain_threaded_before_exact()
    assert writer._ordinary_buffer == []
    assert writer._ordinary_migration is None
    assert writer._ordinary_migration_reservation is None
    assert writer._journal_mode
    batch.publish(lambda: emitter.emit_event(_bash_event("migration owner exact", second=3)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    commands = [
        "migration owner first",
        "migration owner second",
        "migration owner suffix",
        "migration owner exact",
    ]
    positions = [rendered.index(f"\n{command}\n") for command in commands]
    assert positions == sorted(positions)
    for command in commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize(
    ("operation_name", "threaded"),
    [("flush", False), ("barrier_flush", False), ("barrier_flush", True)],
    ids=["flush", "barrier", "threaded-barrier"],
)
def test_bash_unresolved_migration_fences_flush_and_barrier_until_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation_name: str,
    threaded: bool,
) -> None:
    """Flush boundaries remain output-neutral while migration state is unknowable."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        proxy,
        allow_reconciliation,
        reconciliation_calls,
        buffered,
    ) = _retain_unresolved_bash_migration_owner(
        tmp_path,
        monkeypatch,
        threaded=threaded,
    )
    operation = getattr(emitter, operation_name)
    before = emitter.journal_census()

    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        operation()

    assert reconciliation_calls == [2]
    assert proxy.commit_calls == 2
    assert emitter.journal_census() == before
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert not _bash_path(root).exists()
    if threaded:
        assert emitter._thread_error is None
        assert emitter._thread is not None and emitter._thread.is_alive()

    allow_reconciliation[0] = True
    operation()
    batch.publish(lambda: emitter.emit_event(_bash_event("migration owner exact", second=3)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    for command in ["migration owner first", "migration owner second", "migration owner exact"]:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("threaded", [False, True], ids=["direct", "threaded"])
def test_bash_unresolved_migration_keeps_close_retryable_until_adoption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    threaded: bool,
) -> None:
    """Close cannot publish closed or clean a migration whose commit is unknowable."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        proxy,
        allow_reconciliation,
        reconciliation_calls,
        buffered,
    ) = _retain_unresolved_bash_migration_owner(
        tmp_path,
        monkeypatch,
        threaded=threaded,
    )
    before = emitter.journal_census()

    with pytest.raises(RuntimeError, match="reconciliation unavailable"):
        emitter.close()

    assert reconciliation_calls == [2]
    assert proxy.commit_calls == 2
    assert emitter._close_state == "open"
    assert emitter.journal_census() == before
    assert tuple(writer._ordinary_buffer) == buffered
    assert not writer._journal_mode
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert not _bash_path(root).exists()
    if threaded:
        assert emitter._thread_error is None
        assert emitter._thread is not None and emitter._thread.is_alive()

    batch.cancel()
    allow_reconciliation[0] = True
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("\nmigration owner first\n") == 1
    assert rendered.count("\nmigration owner second\n") == 1
    assert "migration owner exact" not in rendered
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("reconciliation_path", ["ordinary", "flush", "close", "exact"])
def test_bash_proved_absent_migration_rolls_back_atomically_for_later_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_path: str,
) -> None:
    """An empty durable read restores legacy state before the caller may continue."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        allow_reconciliation,
        commit_calls,
        reconciliation_calls,
        buffered,
        old_private_path,
        _old_journal_path,
    ) = _retain_unresolved_rolled_back_bash_migration(tmp_path, monkeypatch)
    allow_reconciliation[0] = True
    expected_commands = ["rolled back migration first", "rolled back migration second"]

    if reconciliation_path == "ordinary":
        emitter.emit_event(_bash_event("rolled back migration suffix", second=2))
        expected_commands.append("rolled back migration suffix")
        assert not writer._journal_mode
        assert not writer.exact_route_active
        assert writer._ordinary_migration is None
        assert writer._ordinary_migration_reservation is None
        assert writer._journal_directory is None
    elif reconciliation_path == "flush":
        emitter.flush()
        emitter.emit_event(_bash_event("rolled back migration suffix", second=2))
        expected_commands.append("rolled back migration suffix")
        assert not writer.exact_route_active
        assert writer._ordinary_migration is None
        assert writer._ordinary_migration_reservation is None
    elif reconciliation_path == "close":
        batch.cancel()
        emitter.close()
        assert not old_private_path.exists()
        assert list(spool_root.iterdir()) == []
        _assert_bash_terminal_state(emitter)

        emitter = BashHistoryEmitter(load_format("bash_history"), root)
        later_batch = ExactPublicationAuthority(capacity=1).issue_batch()
        later_batch.publish(
            lambda: emitter.emit_event(_bash_event("rolled back migration later exact", second=4))
        )
        later_batch.release_no_fail()
        emitter.close()
        expected_commands.append("rolled back migration later exact")
        rendered = _bash_path(root).read_text(encoding="utf-8")
        positions = [rendered.index(f"\n{command}\n") for command in expected_commands]
        assert positions == sorted(positions)
        for command in expected_commands:
            assert rendered.count(f"\n{command}\n") == 1
        assert list(spool_root.iterdir()) == []
        _assert_bash_terminal_state(emitter)
        return
    else:
        batch.publish(
            lambda: emitter.emit_event(_bash_event("rolled back migration exact", second=3))
        )

    assert reconciliation_calls == [2]
    assert commit_calls[0] >= 1
    assert not old_private_path.exists()
    if reconciliation_path != "exact":
        batch.publish(
            lambda: emitter.emit_event(_bash_event("rolled back migration exact", second=3))
        )
    expected_commands.append("rolled back migration exact")
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    positions = [rendered.index(f"\n{command}\n") for command in expected_commands]
    assert positions == sorted(positions)
    for command in expected_commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_proved_absent_migration_cleanup_lost_return_retains_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost unlink return keeps the absent owner until cleanup is reconciled."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    (
        emitter,
        writer,
        batch,
        allow_reconciliation,
        _commit_calls,
        reconciliation_calls,
        buffered,
        old_private_path,
        old_journal_path,
    ) = _retain_unresolved_rolled_back_bash_migration(tmp_path, monkeypatch)
    original_unlink = writer._unlink_cleanup_journal
    unlink_calls = 0

    def unlink_then_raise(directory_descriptor: int, journal_name: str) -> None:
        nonlocal unlink_calls
        unlink_calls += 1
        original_unlink(directory_descriptor, journal_name)
        if unlink_calls == 1:
            raise RuntimeError("absent migration cleanup returned late")

    monkeypatch.setattr(writer, "_unlink_cleanup_journal", unlink_then_raise)
    allow_reconciliation[0] = True
    before = emitter.journal_census()
    with pytest.raises(RuntimeError, match="cleanup returned late"):
        emitter.emit_event(_bash_event("rolled back migration suffix", second=2))

    assert unlink_calls == 1
    assert reconciliation_calls == [2]
    assert emitter.journal_census() == before
    assert tuple(writer._ordinary_buffer) == buffered
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert writer._ordinary_migration_rollback_proved
    assert writer.exact_route_active
    assert not old_journal_path.exists()
    assert old_private_path.exists()
    assert not _bash_path(root).exists()

    emitter.emit_event(_bash_event("rolled back migration suffix", second=2))
    assert unlink_calls == 1
    assert reconciliation_calls == [2]
    assert not old_private_path.exists()
    assert not writer.exact_route_active
    assert writer._ordinary_migration is None
    assert writer._ordinary_migration_reservation is None
    batch.publish(lambda: emitter.emit_event(_bash_event("rolled back migration exact", second=3)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    commands = [
        "rolled back migration first",
        "rolled back migration second",
        "rolled back migration suffix",
        "rolled back migration exact",
    ]
    positions = [rendered.index(f"\n{command}\n") for command in commands]
    assert positions == sorted(positions)
    for command in commands:
        assert rendered.count(f"\n{command}\n") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("conflict_kind", ["row", "receipt"])
def test_bash_proved_absent_migration_rejects_conflicting_durable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict_kind: str,
) -> None:
    """Any nonempty suffix or receipt keeps an unresolved migration fail closed."""

    root = tmp_path / "root"
    (
        emitter,
        writer,
        batch,
        allow_reconciliation,
        _commit_calls,
        reconciliation_calls,
        buffered,
        _old_private_path,
        _old_journal_path,
    ) = _retain_unresolved_rolled_back_bash_migration(tmp_path, monkeypatch)
    connection = writer._connection
    assert connection is not None
    if conflict_kind == "row":
        rendered_conflict = f"#{int(T0.timestamp())}\nforeign migration row"
        connection.execute(
            """INSERT INTO entries
            (publication_key, publication_digest, epoch, rendered, payload_bytes)
            VALUES (NULL, NULL, ?, ?, ?)""",
            (int(T0.timestamp()), rendered_conflict, len(rendered_conflict.encode("utf-8"))),
        )
    else:
        connection.execute(
            """INSERT INTO publication_receipts
            (publication_key, publication_digest, admission_active, exported)
            VALUES (?, ?, 1, 0)""",
            ("foreign:receipt:0", "foreign-digest"),
        )
    connection.commit()
    allow_reconciliation[0] = True
    before = emitter.journal_census()

    with pytest.raises(ExactPublicationError, match="conflicting|durable transaction"):
        emitter.emit_event(_bash_event("rejected migration suffix", second=2))

    assert reconciliation_calls == [2]
    assert emitter.journal_census() == before
    assert tuple(writer._ordinary_buffer) == buffered
    assert writer._ordinary_migration is not None
    assert writer._ordinary_migration_reservation is not None
    assert writer.exact_route_active
    assert not _bash_path(root).exists()

    connection.execute("DELETE FROM entries")
    connection.execute("DELETE FROM publication_receipts")
    connection.commit()
    batch.cancel()
    emitter.close()
    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("\nrolled back migration first\n") == 1
    assert rendered.count("\nrolled back migration second\n") == 1
    assert "rejected migration suffix" not in rendered
    _assert_bash_terminal_state(emitter)


def test_bash_export_charges_full_baseline_and_expected_before_temp_allocation(
    tmp_path: Path,
) -> None:
    """A working-set cap failure leaves baseline, plan, and temporary namespace untouched."""

    output = _bash_path(tmp_path)
    output.parent.mkdir(parents=True)
    baseline = b"baseline-history\n" * 128
    output.write_bytes(baseline)
    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path,
        journal_route_capacity=1,
        journal_row_capacity=32,
        journal_byte_capacity=4096,
    )
    emitter.emit_event(_bash_event("pending append"))
    _upgrade_pending_bash_ordinary_route(emitter)
    with pytest.raises(ExactPublicationError, match="byte capacity"):
        emitter.flush()

    census = emitter.journal_census()
    writer = next(iter(emitter._writers.values()))
    assert output.read_bytes() == baseline
    assert census.pending_operations == 1
    assert census.high_water_bytes <= census.byte_capacity
    assert writer._plan_rows == writer._plan_bytes == 0
    assert list(output.parent.glob(".*.export-*.tmp")) == []

    emitter._budget.byte_capacity = 64 * 1024
    emitter.close()


@pytest.mark.parametrize("mutation", ["append", "replace"])
def test_bash_sealed_baseline_copy_is_bounded_under_concurrent_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """A changed baseline cannot make export copy beyond its precharged snapshot."""

    output = _bash_path(tmp_path)
    output.parent.mkdir(parents=True)
    baseline = b"sealed-baseline\n" * 32
    output.write_bytes(baseline)
    emitter = BashHistoryEmitter(
        load_format("bash_history"),
        tmp_path,
        journal_route_capacity=1,
        journal_row_capacity=32,
        journal_byte_capacity=4096,
    )
    emitter.emit_event(_bash_event("pending after mutation"))
    _upgrade_pending_bash_ordinary_route(emitter)
    original_copy = bash_history_module._copy_descriptor
    observed_temporary_sizes: list[int] = []
    attacked = False
    attack_bytes = b"attacker-growth\n" * 1024

    def mutate_then_copy(
        source: int,
        destination: int,
        digest: object,
        *,
        expected_size: int,
        expected_digest: str,
    ) -> int:
        nonlocal attacked
        if not attacked:
            attacked = True
            if mutation == "append":
                with output.open("ab") as stream:
                    stream.write(attack_bytes)
            else:
                replacement = output.with_name("replacement-history")
                replacement.write_bytes(attack_bytes)
                os.replace(replacement, output)
        try:
            return original_copy(
                source,
                destination,
                digest,
                expected_size=expected_size,
                expected_digest=expected_digest,
            )
        finally:
            observed_temporary_sizes.append(os.fstat(destination).st_size)

    with monkeypatch.context() as patch:
        patch.setattr(bash_history_module, "_copy_descriptor", mutate_then_copy)
        with pytest.raises(ExactPublicationError, match="output"):
            emitter.flush()

    attacked_output = baseline + attack_bytes if mutation == "append" else attack_bytes
    assert output.read_bytes() == attacked_output
    assert observed_temporary_sizes and max(observed_temporary_sizes) <= len(baseline)
    assert list(output.parent.glob(".*.export-*.tmp")) == []
    writer = next(iter(emitter._writers.values()))
    assert writer._plan_rows == writer._plan_bytes == 0
    assert writer._pending_rows == 1
    census = emitter.journal_census()
    assert census.high_water_bytes <= census.byte_capacity

    emitter._budget.byte_capacity = 128 * 1024
    emitter.close()


@pytest.mark.parametrize(
    "route_case",
    ["username-210", "username-boundary", "host-boundary"],
)
def test_bash_long_public_route_uses_bounded_private_names_and_publishes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route_case: str,
) -> None:
    """Valid public boundary names use fixed-size private route identifiers."""

    name_max = int(os.pathconf(tmp_path, "PC_NAME_MAX"))
    username = "alice"
    host = "linux-01.example.test"
    if route_case == "username-210":
        username = "u" * 210
    elif route_case == "username-boundary":
        username = "u" * (name_max - len(os.fsencode(".bash_history")))
    else:
        host = "h" * name_max
    event = _bash_event("long public route")
    event["username"] = username
    event["host_fqdn"] = host
    output = tmp_path / host / "bash_history" / f"{username}.bash_history"

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(event))
    assert not output.parent.exists()
    if route_case == "username-boundary":
        assert len(os.fsencode(output.name)) == name_max
    elif route_case == "host-boundary":
        assert len(os.fsencode(host)) == name_max

    batch.commit()
    writer = next(iter(emitter._writers.values()))
    journal_name = writer._journal_name
    journal_path = writer._journal_path
    assert journal_name is not None and journal_path is not None
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    plans: list[object] = []
    original_replace = writer._replace_output

    def capture_plan(plan: object) -> None:
        plans.append(plan)
        original_replace(plan)

    monkeypatch.setattr(writer, "_replace_output", capture_plan)
    emitter.flush()
    assert len(plans) == 1
    plan = plans[0]
    assert type(plan) is bash_history_module._ExportPlan
    temporary_name = plan.temporary_name
    route_stem = bash_history_module._private_route_stem(tmp_path, output)
    assert journal_name.startswith(f".{route_stem}.journal-")
    assert journal_name.endswith(".sqlite3")
    assert temporary_name.startswith(f".{route_stem}.export-")
    assert temporary_name.endswith(".tmp")

    output_path_max = int(os.pathconf(output.parent, "PC_PATH_MAX"))
    journal_name_max = int(os.pathconf(journal_path.parent, "PC_NAME_MAX"))
    journal_path_max = int(os.pathconf(journal_path.parent, "PC_PATH_MAX"))
    journal_names = (
        journal_name,
        *(f"{journal_name}{suffix}" for suffix in ("-journal", "-wal", "-shm")),
    )
    for private_name in journal_names:
        assert Path(private_name).name == private_name
        assert len(os.fsencode(private_name)) <= journal_name_max
        private_path = journal_path.parent / private_name
        assert not private_path.is_relative_to(tmp_path)
        assert len(os.fsencode(private_path)) + 1 <= journal_path_max
    assert Path(temporary_name).name == temporary_name
    assert len(os.fsencode(temporary_name)) <= name_max
    assert len(os.fsencode(output.parent / temporary_name)) + 1 <= output_path_max
    assert len(os.fsencode(output)) + 1 <= output_path_max

    batch.release_no_fail()
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("long public route") == 1
    assert emitter.event_count == 1
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("failure", ["username", "host", "path"])
def test_bash_impossible_public_path_aborts_exact_prepare_neutrally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """An impossible public route fails before participant, reservation, or mutation."""

    name_max = int(os.pathconf(tmp_path, "PC_NAME_MAX"))
    event = _bash_event("must fail before admission")
    if failure == "username":
        suffix_bytes = len(os.fsencode(".bash_history"))
        event["username"] = "u" * (name_max - suffix_bytes + 1)
    elif failure == "host":
        event["host_fqdn"] = "h" * (name_max + 1)

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    if failure == "path":
        output = _bash_path(tmp_path)
        original_limits = bash_history_module._directory_path_limits

        def impossible_path_limit(descriptor: int) -> tuple[int | None, int | None]:
            current_name_max, _current_path_max = original_limits(descriptor)
            return current_name_max, len(os.fsencode(output))

        with monkeypatch.context() as patch:
            patch.setattr(
                bash_history_module,
                "_directory_path_limits",
                impossible_path_limit,
            )
            with pytest.raises(ExactPublicationError, match="PATH_MAX"):
                batch.prepare(lambda: emitter.emit_event(event))
    else:
        with pytest.raises(ExactPublicationError, match="NAME_MAX"):
            batch.prepare(lambda: emitter.emit_event(event))

    assert batch.state == "issued"
    assert batch._participants == {}
    assert batch._prepared_rows is None
    authority_census = authority.census()
    assert authority_census.prepared_batches == 0
    assert authority_census.retained_rows == authority_census.retained_bytes == 0
    assert emitter._active_exact_publication_keys == set()
    assert emitter._exact_capacity_reservations == {}
    assert emitter._provisional_routes == set()
    assert emitter._writers == {}
    census = emitter.journal_census()
    assert census.routes == census.writers == 0
    assert census.reserved_rows == census.reserved_bytes == 0
    assert census.pending_operations == census.retained_rows == census.retained_bytes == 0
    assert list(tmp_path.iterdir()) == []

    valid = _bash_event("valid after rejected route")
    batch.publish(lambda: emitter.emit_event(valid))
    batch.release_no_fail()
    emitter.close()
    assert _bash_path(tmp_path).read_text(encoding="utf-8").count("valid after rejected route") == 1
    assert authority.census().active_batches == 0
    _assert_bash_terminal_state(emitter)


def test_bash_private_names_distinguish_long_routes_under_fixed_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full route digests keep long neighboring routes distinct under nonce reuse."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    fixed_nonce = "e" * 32
    first_user = "u" * 209 + "a"
    second_user = "u" * 209 + "b"
    first = _bash_event("first distinct route")
    first["username"] = first_user
    second = _bash_event("second distinct route", second=1)
    second["username"] = second_user
    monkeypatch.setattr(
        bash_history_module.secrets,
        "token_hex",
        lambda size: fixed_nonce if size == 16 else pytest.fail("unexpected nonce size"),
    )

    def render() -> None:
        emitter.emit_event(first)
        emitter.emit_event(second)

    batch.prepare(render)
    batch.commit()
    assert len(emitter._writers) == 2
    journals = {writer._journal_name for writer in emitter._writers.values()}
    assert None not in journals and len(journals) == 2
    export_names: dict[tuple[str, str], str] = {}
    for writer_key, writer in emitter._writers.items():
        original_replace = writer._replace_output

        def capture_plan(
            plan: object,
            *,
            key: tuple[str, str] = writer_key,
            replace: Callable[[object], None] = original_replace,
        ) -> None:
            assert type(plan) is bash_history_module._ExportPlan
            export_names[key] = plan.temporary_name
            replace(plan)

        monkeypatch.setattr(writer, "_replace_output", capture_plan)

    emitter.flush()
    assert len(set(export_names.values())) == 2
    for writer_key, writer in emitter._writers.items():
        stem = bash_history_module._private_route_stem(tmp_path, writer.output_path)
        assert writer._journal_name == f".{stem}.journal-{fixed_nonce}.sqlite3"
        assert export_names[writer_key] == f".{stem}.export-{fixed_nonce}.tmp"

    batch.release_no_fail()
    emitter.close()
    first_output = (
        tmp_path / "linux-01.example.test" / "bash_history" / f"{first_user}.bash_history"
    )
    second_output = (
        tmp_path / "linux-01.example.test" / "bash_history" / f"{second_user}.bash_history"
    )
    assert first_output.read_text(encoding="utf-8").count("first distinct route") == 1
    assert second_output.read_text(encoding="utf-8").count("second distinct route") == 1
    _assert_bash_terminal_state(emitter)


def test_bash_private_name_collisions_retry_without_following_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Private O_EXCL collisions skip attacker links without touching their target."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    output = _bash_path(tmp_path)
    output.parent.mkdir(parents=True)
    sentinel = tmp_path / "external-sentinel"
    sentinel.write_bytes(b"do-not-touch")
    stem = bash_history_module._private_route_stem(tmp_path, output)
    journal_collision_nonce = "a" * 32
    journal_retry_nonce = "b" * 32
    export_collision_nonce = "c" * 32
    export_retry_nonce = "d" * 32
    export_collision = output.parent / f".{stem}.export-{export_collision_nonce}.tmp"
    export_collision.symlink_to(sentinel)
    journal_collisions: list[str] = []
    original_create_private_file = bash_history_module._create_private_file

    def create_with_journal_collision(
        directory_descriptor: int,
        prefix: str,
        suffix: str,
    ) -> tuple[int, str]:
        if suffix == ".sqlite3" and not journal_collisions:
            collision_name = f"{prefix}{journal_collision_nonce}{suffix}"
            os.symlink(sentinel, collision_name, dir_fd=directory_descriptor)
            journal_collisions.append(collision_name)
        return original_create_private_file(directory_descriptor, prefix, suffix)

    monkeypatch.setattr(
        bash_history_module,
        "_create_private_file",
        create_with_journal_collision,
    )
    nonces = iter(
        [
            journal_collision_nonce,
            journal_retry_nonce,
            export_collision_nonce,
            export_retry_nonce,
        ]
    )

    def next_nonce(size: int) -> str:
        assert size == 16
        return next(nonces)

    monkeypatch.setattr(bash_history_module.secrets, "token_hex", next_nonce)
    batch.prepare(lambda: emitter.emit_event(_bash_event("collision safe")))
    batch.commit()
    writer = next(iter(emitter._writers.values()))
    assert writer._journal_name == f".{stem}.journal-{journal_retry_nonce}.sqlite3"
    journal_root = writer._journal_directory.path
    assert journal_root is not None
    journal_collision = journal_root / journal_collisions[0]
    plans: list[object] = []
    original_replace = writer._replace_output

    def capture_plan(plan: object) -> None:
        plans.append(plan)
        original_replace(plan)

    monkeypatch.setattr(writer, "_replace_output", capture_plan)
    emitter.flush()
    assert len(plans) == 1
    plan = plans[0]
    assert type(plan) is bash_history_module._ExportPlan
    assert plan.temporary_name == f".{stem}.export-{export_retry_nonce}.tmp"
    assert journal_collision.is_symlink()
    assert export_collision.is_symlink()
    assert sentinel.read_bytes() == b"do-not-touch"

    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("collision safe") == 1
    assert sentinel.read_bytes() == b"do-not-touch"
    _assert_bash_terminal_state(emitter)


def test_bash_private_route_names_are_python_hash_seed_independent() -> None:
    """Private route identifiers depend only on framed route bytes and SHA-256."""

    repository = Path(__file__).resolve().parents[2]
    probe = """
import json
from pathlib import Path
from evidenceforge.generation.emitters.bash_history import _private_file_prototypes
base = Path('/deterministic/bash-root')
output = base / 'linux-01.example.test' / 'bash_history' / ('u' * 210 + '.bash_history')
print(json.dumps(_private_file_prototypes(base, output)))
"""
    results: list[str] = []
    for seed in ("1", "8675309"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = os.fspath(repository / "src")
        results.append(
            subprocess.check_output(
                [sys.executable, "-c", probe],
                env=environment,
                text=True,
            ).strip()
        )
    assert results[0] == results[1]
    private_names = json.loads(results[0])
    assert len(private_names) == 5
    assert private_names[0].startswith(".")
    assert len(private_names[0].split(".")[1]) == 64


def test_bash_public_census_is_scalar_and_terminal_route_is_reclaimed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregate census never scans writers, and release reclaims empty SQLite state."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("terminal reclaim")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))
    journal_path = writer._journal_path
    assert journal_path is not None and journal_path.exists()
    monkeypatch.setattr(
        writer,
        "census",
        lambda: (_ for _ in ()).throw(AssertionError("writer scan")),
    )
    assert emitter.journal_census().writers == 1

    batch.release_no_fail()
    assert emitter._writers == {}
    assert not journal_path.exists()
    terminal = emitter.journal_census()
    assert terminal.writers == terminal.routes == 0
    assert terminal.retained_rows == terminal.retained_bytes == 0
    assert emitter.event_count == 1
    emitter.close()


def test_bash_symlinked_route_ancestry_and_output_fail_before_mutation(
    tmp_path: Path,
) -> None:
    """Neither an ancestor link nor a final-output link can redirect publication."""

    root = tmp_path / "root"
    root.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (root / "linked.example.test").symlink_to(external, target_is_directory=True)
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    ancestry = _bash_event("ancestry")
    ancestry["host_fqdn"] = "linked.example.test"
    ancestry_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="ancestry"):
        ancestry_batch.prepare(lambda: emitter.emit_event(ancestry))
    ancestry_batch.cancel()
    assert list(external.iterdir()) == []
    assert emitter.journal_census().retained_rows == 0
    emitter.close()

    output_root = tmp_path / "output-root"
    output = _bash_path(output_root)
    output.parent.mkdir(parents=True)
    target = tmp_path / "target.txt"
    target.write_text("do-not-touch", encoding="utf-8")
    output.symlink_to(target)
    output_emitter = BashHistoryEmitter(load_format("bash_history"), output_root)
    output_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="output"):
        output_batch.prepare(lambda: output_emitter.emit_event(_bash_event("redirect")))
    output_batch.cancel()
    assert target.read_text(encoding="utf-8") == "do-not-touch"
    assert output_emitter.journal_census().retained_rows == 0
    output_emitter.close()


def test_bash_symlinked_journal_fails_closed_without_touching_target(tmp_path: Path) -> None:
    """A swapped journal pathname is rejected before SQLite or output mutation."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path / "root")
    emitter.emit_event(_bash_event("pending"))
    _upgrade_pending_bash_ordinary_route(emitter)
    writer = next(iter(emitter._writers.values()))
    journal_path = writer._journal_path
    connection = writer._connection
    assert journal_path is not None and connection is not None
    target = tmp_path / "journal-target.txt"
    target.write_text("do-not-touch", encoding="utf-8")
    journal_path.unlink()
    journal_path.symlink_to(target)
    try:
        with pytest.raises(ExactPublicationError, match="journal"):
            emitter.flush()
        assert target.read_text(encoding="utf-8") == "do-not-touch"
        assert not _bash_path(tmp_path / "root").exists()
    finally:
        connection.close()
        journal_path.unlink(missing_ok=True)


@pytest.mark.parametrize("target_exists", [False, True], ids=["missing", "sentinel"])
def test_bash_journal_swap_before_sqlite_connect_cannot_mutate_external_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_exists: bool,
) -> None:
    """SQLite opens an existing journal only and validates it before issuing SQL."""

    root = tmp_path / "root"
    external = tmp_path / "external-journal.sqlite3"
    sentinel = b"external-sentinel-bytes"
    if target_exists:
        external.write_bytes(sentinel)
    original_connect = bash_history_module._connect_existing_journal
    swapped_paths: list[Path] = []

    def swap_then_connect(journal_path: Path) -> object:
        swapped_paths.append(journal_path)
        journal_path.unlink()
        journal_path.symlink_to(external)
        return original_connect(journal_path)

    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with monkeypatch.context() as patch:
        patch.setattr(bash_history_module, "_connect_existing_journal", swap_then_connect)
        with pytest.raises(ExactPublicationError, match="journal"):
            batch.prepare(lambda: emitter.emit_event(_bash_event("must not escape")))
    batch.cancel()

    assert bool(external.exists()) is target_exists
    if target_exists:
        assert external.read_bytes() == sentinel
    assert not _bash_path(root).exists()
    assert emitter.journal_census().retained_rows == 0
    assert swapped_paths
    swapped_paths[0].unlink(missing_ok=True)
    emitter.close()


def test_bash_sqlite_companion_link_is_rejected_before_first_sql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLite cannot follow a preinstalled rollback sidecar outside its private root."""

    root = tmp_path / "root"
    external = tmp_path / "external-sidecar"
    sentinel = b"external-sidecar-sentinel"
    external.write_bytes(sentinel)
    original_connect = bash_history_module._connect_existing_journal
    companion_paths: list[Path] = []

    def connect_then_install_sidecar(journal_path: Path) -> sqlite3.Connection:
        connection = original_connect(journal_path)
        companion = Path(f"{journal_path}-journal")
        companion.symlink_to(external)
        companion_paths.append(companion)
        return connection

    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with monkeypatch.context() as patch:
        patch.setattr(
            bash_history_module,
            "_connect_existing_journal",
            connect_then_install_sidecar,
        )
        with pytest.raises(ExactPublicationError, match="journal companion"):
            batch.prepare(lambda: emitter.emit_event(_bash_event("sidecar must not escape")))
    batch.cancel()

    assert external.read_bytes() == sentinel
    assert not _bash_path(root).exists()
    assert companion_paths and not companion_paths[0].exists()
    assert emitter.journal_census().retained_rows == 0
    emitter.close()


def test_bash_live_rollback_sidecar_stays_private_and_mode_0600(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live SQLite rollback journal never escapes the protected route directory."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    original_connect = bash_history_module._connect_existing_journal
    observed: list[tuple[Path, int]] = []

    class ObservingConnection:
        def __init__(self, connection: sqlite3.Connection, journal_path: Path) -> None:
            self._connection = connection
            self._journal_path = journal_path

        def execute(
            self,
            sql: str,
            parameters: tuple[object, ...] = (),
        ) -> sqlite3.Cursor:
            cursor = self._connection.execute(sql, parameters)
            if "INSERT INTO entries" in sql:
                companion = Path(f"{self._journal_path}-journal")
                metadata = companion.stat(follow_symlinks=False)
                observed.append((companion, stat.S_IMODE(metadata.st_mode)))
            return cursor

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

    def observing_connect(journal_path: Path) -> ObservingConnection:
        return ObservingConnection(original_connect(journal_path), journal_path)

    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    emitter.emit_event(_bash_event("observe rollback sidecar"))
    with monkeypatch.context() as patch:
        patch.setattr(bash_history_module, "_connect_existing_journal", observing_connect)
        _upgrade_pending_bash_ordinary_route(emitter)

    assert observed
    companion, mode = observed[-1]
    assert companion.parent.is_relative_to(spool_root)
    assert not companion.is_relative_to(root)
    assert mode == 0o600
    writer = next(iter(emitter._writers.values()))
    connection = writer._connection
    assert connection is not None
    assert connection.execute("PRAGMA temp_store").fetchone() == (2,)
    plans = (
        connection.execute(
            """EXPLAIN QUERY PLAN SELECT rendered FROM entries
            INDEXED BY entries_epoch_sequence
            WHERE sequence <= ? ORDER BY epoch, sequence""",
            (10,),
        ),
        connection.execute(
            """EXPLAIN QUERY PLAN SELECT rendered FROM entries
            INDEXED BY entries_epoch_sequence
            WHERE sequence <= ? AND (epoch, sequence) > (?, ?)
            ORDER BY epoch, sequence""",
            (10, 0, 0),
        ),
    )
    for plan in plans:
        details = [str(row[3]).upper() for row in plan]
        assert not any("USE TEMP B-TREE" in detail for detail in details)
    emitter.close()

    assert _bash_path(root).read_text(encoding="utf-8").count("observe rollback sidecar") == 1
    assert not companion.exists()
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("external_exists", [False, True], ids=["missing", "existing"])
def test_bash_output_parent_swap_cannot_redirect_private_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    external_exists: bool,
) -> None:
    """A pinned old output dirfd cannot disagree with SQLite's journal pathname."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    output = _bash_path(root)
    output.parent.mkdir(parents=True)
    held_parent = output.parent.with_name("bash_history-held")
    external_parent = tmp_path / "external-parent"
    external_parent.mkdir()

    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    original_connect = bash_history_module._connect_existing_journal
    connect_entered = Event()
    allow_connect = Event()
    prepare_finished = Event()
    private_paths: list[Path] = []
    failures: list[BaseException] = []

    def paused_connect(journal_path: Path) -> sqlite3.Connection:
        private_paths.append(journal_path)
        connect_entered.set()
        assert allow_connect.wait(timeout=2)
        return original_connect(journal_path)

    def prepare() -> None:
        try:
            batch.prepare(lambda: emitter.emit_event(_bash_event("parent swap first")))
        except BaseException as error:
            failures.append(error)
        finally:
            prepare_finished.set()

    with monkeypatch.context() as patch:
        patch.setattr(bash_history_module, "_connect_existing_journal", paused_connect)
        prepare_thread = Thread(target=prepare)
        prepare_thread.start()
        assert connect_entered.wait(timeout=2)
        assert len(private_paths) == 1
        private_path = private_paths[0]
        assert private_path.is_relative_to(spool_root)
        assert not private_path.is_relative_to(root)
        assert stat.S_IMODE(private_path.parent.stat().st_mode) == 0o700

        output.parent.rename(held_parent)
        output.parent.symlink_to(external_parent, target_is_directory=True)
        external_database = external_parent / private_path.name
        external_bytes: bytes | None = None
        if external_exists:
            with sqlite3.connect(external_database) as connection:
                connection.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
                connection.execute("INSERT INTO sentinel VALUES ('unchanged')")
            external_bytes = external_database.read_bytes()
        allow_connect.set()
        assert prepare_finished.wait(timeout=2)
        prepare_thread.join(timeout=2)

    assert failures == []
    batch.commit()
    assert external_database.exists() is external_exists
    if external_exists:
        assert external_bytes is not None
        assert external_database.read_bytes() == external_bytes
        with sqlite3.connect(
            f"{external_database.as_uri()}?mode=ro",
            uri=True,
        ) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
                )
            }
            assert tables == {"sentinel"}
            assert connection.execute("SELECT value FROM sentinel").fetchone() == ("unchanged",)
        assert list(external_parent.iterdir()) == [external_database]
    else:
        assert list(external_parent.iterdir()) == []

    retained = emitter.journal_census()
    with pytest.raises(ExactPublicationError, match="ancestry"):
        emitter.flush()
    assert emitter.journal_census() == retained
    assert external_database.exists() is external_exists
    if external_exists:
        assert external_database.read_bytes() == external_bytes
    assert not (external_parent / output.name).exists()

    output.parent.unlink()
    held_parent.rename(output.parent)
    emitter.flush()
    batch.release_no_fail()
    _publish_exact(emitter, _bash_event("parent swap later epoch", second=1))
    emitter.close()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("parent swap first") == 1
    assert rendered.count("parent swap later epoch") == 1
    assert external_database.exists() is external_exists
    if external_exists:
        assert external_database.read_bytes() == external_bytes
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_private_spool_overlap_fails_closed_and_retries_disjoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLite never falls back beneath the attacker-controlled public output root."""

    root = tmp_path / "root"
    overlapping_spool = root / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(overlapping_spool))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="outside its public output root"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("overlap rejected")))
    assert not root.exists()
    assert not overlapping_spool.exists()
    assert emitter._writers == {}

    trusted_spool = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(trusted_spool))
    batch.publish(lambda: emitter.emit_event(_bash_event("overlap rejected")))
    emitter.flush()
    batch.release_no_fail()
    emitter.close()

    assert _bash_path(root).read_text(encoding="utf-8").count("overlap rejected") == 1
    assert list(trusted_spool.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("layout", ["equal", "symlink-under-output"])
def test_bash_private_spool_resolved_overlap_is_rejected_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    layout: str,
) -> None:
    """Configured private storage cannot equal or resolve beneath the public root."""

    root = tmp_path / "root"
    if layout == "equal":
        configured_spool = root
        forbidden_target = root
    else:
        root.mkdir()
        forbidden_target = root / "private-spool"
        configured_spool = tmp_path / "configured-spool-link"
        configured_spool.symlink_to(forbidden_target, target_is_directory=True)
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(configured_spool))

    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="outside its public output root"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("resolved overlap rejected")))

    assert not forbidden_target.exists() or forbidden_target == root
    assert not (root / "private-spool").exists()
    assert emitter._writers == {}
    assert emitter.journal_census().pending_operations == 0

    trusted_spool = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(trusted_spool))
    batch.publish(lambda: emitter.emit_event(_bash_event("resolved overlap rejected")))
    batch.release_no_fail()
    emitter.close()

    assert _bash_path(root).read_text(encoding="utf-8").count("resolved overlap rejected") == 1
    assert list(trusted_spool.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_private_spool_rejects_nonsticky_writable_ancestry_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A group/other-writable nonsticky ancestor is never trusted for SQLite."""

    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    configured_spool = unsafe_parent / "spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(configured_spool))
    root = tmp_path / "root"
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="externally writable"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("unsafe ancestry retry")))
    assert not configured_spool.exists()
    assert emitter._writers == {}

    unsafe_parent.chmod(0o700)
    batch.publish(lambda: emitter.emit_event(_bash_event("unsafe ancestry retry")))
    batch.release_no_fail()
    emitter.close()

    assert _bash_path(root).read_text(encoding="utf-8").count("unsafe ancestry retry") == 1
    assert list(configured_spool.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_private_spool_accepts_sticky_shared_ancestry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root/euid-owned sticky shared ancestor retains normal POSIX temp semantics."""

    sticky_parent = tmp_path / "sticky-parent"
    sticky_parent.mkdir(mode=0o700)
    sticky_parent.chmod(0o1777)
    monkeypatch.delenv("EFORGE_SPOOL_DIR", raising=False)
    monkeypatch.setattr(
        bash_history_module.tempfile,
        "gettempdir",
        lambda: os.fspath(sticky_parent),
    )
    root = tmp_path / "root"
    emitter = BashHistoryEmitter(load_format("bash_history"), root)

    _publish_exact(emitter, _bash_event("sticky ancestry accepted"))
    writer = next(iter(emitter._writers.values()))
    private_path = writer._journal_directory.path
    journal_path = writer._journal_path
    assert private_path is not None and private_path.parent == sticky_parent
    assert journal_path is not None
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    emitter.close()

    assert _bash_path(root).read_text(encoding="utf-8").count("sticky ancestry accepted") == 1
    assert list(sticky_parent.iterdir()) == []
    sticky_parent.chmod(0o700)
    _assert_bash_terminal_state(emitter)


def test_bash_exact_upgrade_rechecks_private_leaf_owner_mode_before_sql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lazily allocated exact journal must reject a changed private leaf mode."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    emitter.emit_event(_bash_event("ordinary before strict upgrade"))
    original_finish = bash_history_module._PrivateJournalDirectory._finish_initialization
    tampered_paths: list[Path] = []

    def finish_then_tamper(
        journal_directory: bash_history_module._PrivateJournalDirectory,
    ) -> None:
        original_finish(journal_directory)
        private_path = journal_directory.path
        assert private_path is not None
        if not tampered_paths:
            private_path.chmod(0o755)
            tampered_paths.append(private_path)

    monkeypatch.setattr(
        bash_history_module._PrivateJournalDirectory,
        "_finish_initialization",
        finish_then_tamper,
    )

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="mode 0700"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("exact strict retry", second=1)))
    writer = next(iter(emitter._writers.values()))
    assert writer._journal_directory is not None
    private_path = writer._journal_directory.path
    assert private_path is not None and tampered_paths == [private_path]
    failed = emitter.journal_census()
    assert failed.pending_operations == 0
    assert failed.admission_receipts == 0

    private_path.chmod(0o700)
    batch.publish(lambda: emitter.emit_event(_bash_event("exact strict retry", second=1)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("ordinary before strict upgrade") == 1
    assert rendered.count("exact strict retry") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


def test_bash_strict_private_spool_rechecks_writable_ancestry_each_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted spool that becomes nonsticky writable blocks later exact SQL."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    _publish_exact(emitter, _bash_event("strict first epoch"))
    spool_root.chmod(0o777)

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    before = emitter.journal_census()
    with pytest.raises(ExactPublicationError, match="externally writable"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("strict later epoch", second=1)))
    failed = emitter.journal_census()
    assert failed.pending_operations == before.pending_operations == 1
    assert failed.admission_receipts == 0

    spool_root.chmod(0o755)
    batch.publish(lambda: emitter.emit_event(_bash_event("strict later epoch", second=1)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("strict first epoch") == 1
    assert rendered.count("strict later epoch") == 1
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize(
    "missing",
    ["dirfd", "stat-nofollow", "nofollow", "euid", "listdir-fd", "directory-fsync"],
)
def test_bash_exact_journal_capability_gate_is_fail_closed_but_ordinary_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    """Exact admission requires POSIX safety while ordinary rows retain compatibility."""

    root = tmp_path / "root"
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()

    with monkeypatch.context() as patch:
        if missing == "dirfd":
            patch.setattr(
                bash_history_module.os,
                "supports_dir_fd",
                frozenset(
                    operation for operation in os.supports_dir_fd if operation is not os.open
                ),
            )
        elif missing == "stat-nofollow":
            patch.setattr(
                bash_history_module.os,
                "supports_follow_symlinks",
                frozenset(
                    operation
                    for operation in os.supports_follow_symlinks
                    if operation is not os.stat
                ),
            )
        elif missing == "nofollow":
            patch.setattr(bash_history_module, "_NOFOLLOW", 0)
        elif missing == "euid":
            patch.setattr(bash_history_module, "_effective_user_id", lambda: None)
        elif missing == "listdir-fd":

            def unsupported_descriptor_listing(_descriptor: int) -> None:
                raise TypeError("listdir(fd) is unsupported")

            patch.setattr(
                bash_history_module,
                "_verify_descriptor_listing",
                unsupported_descriptor_listing,
            )
        else:

            def unsupported_directory_fsync(_descriptor: int) -> None:
                raise OSError("directory fsync is unsupported")

            patch.setattr(
                bash_history_module,
                "_verify_directory_fsync",
                unsupported_directory_fsync,
            )

        with pytest.raises(ExactPublicationError, match="requires"):
            batch.prepare(lambda: emitter.emit_event(_bash_event("unsafe exact")))
        emitter.emit_event(_bash_event("ordinary remains compatible"))

    assert batch.state == "issued"
    assert batch._participants == {}
    assert emitter._active_exact_publication_keys == set()
    assert emitter._exact_capacity_reservations == {}
    batch.publish(lambda: emitter.emit_event(_bash_event("safe exact retry", second=1)))
    batch.release_no_fail()
    emitter.close()

    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("ordinary remains compatible") == 1
    assert rendered.count("safe exact retry") == 1
    assert authority.census().active_batches == 0
    _assert_bash_terminal_state(emitter)


def test_bash_runtime_dirfd_failure_leaves_ordinary_path_fully_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual unsupported descriptor operations affect exact publication only."""

    root = tmp_path / "root"
    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    original_open = os.open
    original_stat = os.stat
    original_listdir = os.listdir

    def guarded_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is not None:
            raise NotImplementedError("openat is unavailable")
        return original_open(path, flags, mode)  # type: ignore[arg-type]

    def guarded_stat(
        path: object,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if dir_fd is not None or not follow_symlinks:
            raise NotImplementedError("statat is unavailable")
        return original_stat(path)  # type: ignore[arg-type]

    def guarded_listdir(path: object = ".") -> list[str]:
        if type(path) is int:
            raise NotImplementedError("listdir(fd) is unavailable")
        return original_listdir(path)  # type: ignore[arg-type]

    def guarded_fsync(_descriptor: int) -> None:
        raise NotImplementedError("directory fsync is unavailable")

    def forbidden_private_directory(*_args: object, **_kwargs: object) -> object:
        pytest.fail("ordinary or capability-negative admission allocated a private directory")

    def forbidden_sqlite_connect(_journal_path: Path) -> sqlite3.Connection:
        pytest.fail("ordinary or capability-negative admission opened SQLite")

    supported_dir_fd = frozenset(
        guarded_open
        if operation is original_open
        else guarded_stat
        if operation is original_stat
        else operation
        for operation in os.supports_dir_fd
    )
    supported_follow_symlinks = frozenset(
        guarded_stat if operation is original_stat else operation
        for operation in os.supports_follow_symlinks
    )

    with monkeypatch.context() as patch:
        patch.setattr(bash_history_module.os, "open", guarded_open)
        patch.setattr(bash_history_module.os, "stat", guarded_stat)
        patch.setattr(bash_history_module.os, "listdir", guarded_listdir)
        patch.setattr(bash_history_module.os, "fsync", guarded_fsync)
        patch.setattr(
            bash_history_module,
            "_PrivateJournalDirectory",
            forbidden_private_directory,
        )
        patch.setattr(
            bash_history_module,
            "_connect_existing_journal",
            forbidden_sqlite_connect,
        )
        patch.setattr(bash_history_module.os, "supports_dir_fd", supported_dir_fd)
        patch.setattr(
            bash_history_module.os,
            "supports_follow_symlinks",
            supported_follow_symlinks,
        )

        emitter.emit_event(_bash_event("ordinary before unsupported exact"))
        ordinary_writer = next(iter(emitter._writers.values()))
        assert ordinary_writer._journal_directory is None
        assert ordinary_writer._connection is None
        assert not ordinary_writer._journal_mode
        emitter.flush()
        first_bytes = _bash_path(root).read_bytes()
        assert first_bytes.count(b"ordinary before unsupported exact") == 1
        assert not spool_root.exists()
        assert emitter._writers == {}
        assert emitter.journal_census().writers == emitter.journal_census().routes == 0

        with pytest.raises(ExactPublicationError, match="requires"):
            batch.prepare(lambda: emitter.emit_event(_bash_event("unsupported exact", second=1)))
        assert batch.state == "issued"
        assert batch._participants == {}
        assert emitter._active_exact_publication_keys == set()
        assert emitter._exact_capacity_reservations == {}
        assert emitter._provisional_routes == set()
        assert emitter._writers == {}
        assert not spool_root.exists()

        emitter.emit_event(_bash_event("ordinary after unsupported exact", second=2))
        emitter.close()

    batch.cancel()
    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("ordinary before unsupported exact") == 1
    assert rendered.count("ordinary after unsupported exact") == 1
    assert "\nunsupported exact\n" not in rendered
    assert not spool_root.exists()
    assert emitter.event_count == 2
    assert authority.census().active_batches == 0
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("exact", [False, True])
def test_bash_absent_clear_only_never_creates_output(tmp_path: Path, exact: bool) -> None:
    """Legacy clear-only behavior preserves an absent history file as absent."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    if exact:
        _publish_exact(emitter, _bash_event("history -c"))
    else:
        emitter.emit_event(_bash_event("history -c"))
    emitter.flush()
    assert not _bash_path(tmp_path).exists()
    assert emitter._writers == {}
    emitter.close()
    assert not _bash_path(tmp_path).exists()


@pytest.mark.parametrize("operation", ["unlink", "fsync"])
def test_bash_cleanup_lost_return_is_retryable_and_not_prematurely_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Unlink plus directory-fsync must complete before terminal writer publication."""

    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("cleanup retry")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))
    journal_path = writer._journal_path
    assert journal_path is not None and journal_path.exists()
    fail_once = True

    if operation == "fsync":
        original_fsync = writer._fsync_cleanup_directory

        def fsync_then_raise(directory_descriptor: int) -> None:
            nonlocal fail_once
            original_fsync(directory_descriptor)
            if fail_once:
                fail_once = False
                raise RuntimeError("cleanup fsync returned late")

        monkeypatch.setattr(writer, "_fsync_cleanup_directory", fsync_then_raise)
    else:
        original_unlink = writer._unlink_cleanup_journal

        def unlink_then_raise(directory_descriptor: int, journal_name: str) -> None:
            nonlocal fail_once
            original_unlink(directory_descriptor, journal_name)
            if fail_once:
                fail_once = False
                raise RuntimeError("cleanup unlink returned late")

        monkeypatch.setattr(writer, "_unlink_cleanup_journal", unlink_then_raise)
    with pytest.raises(RuntimeError, match="returned late"):
        batch.release_no_fail()
    assert not writer._closed
    assert not writer._terminal
    assert not journal_path.exists()

    batch.release_no_fail()
    assert writer._closed and writer._terminal
    assert emitter._writers == {}
    assert emitter.journal_census().retained_rows == 0
    emitter.close()


@pytest.mark.parametrize("operation", ["rmdir", "parent-fsync"])
def test_bash_private_spool_cleanup_lost_return_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Private-root removal and its parent fsync remain owned until retry."""

    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path / "root")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("private cleanup retry")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))
    journal_directory = writer._journal_directory
    private_path = journal_directory.path
    assert private_path is not None and private_path.exists()
    fail_once = True

    if operation == "rmdir":
        original_remove = journal_directory._remove_directory

        def remove_then_raise(
            parent_descriptor: int,
            directory_name: str,
            path: Path,
        ) -> None:
            nonlocal fail_once
            original_remove(parent_descriptor, directory_name, path)
            if fail_once:
                fail_once = False
                raise RuntimeError("private rmdir returned late")

        monkeypatch.setattr(journal_directory, "_remove_directory", remove_then_raise)
    else:
        original_fsync = journal_directory._fsync_parent

        def fsync_then_raise(parent_descriptor: int) -> None:
            nonlocal fail_once
            original_fsync(parent_descriptor)
            if fail_once:
                fail_once = False
                raise RuntimeError("private parent fsync returned late")

        monkeypatch.setattr(journal_directory, "_fsync_parent", fsync_then_raise)

    with pytest.raises(RuntimeError, match="returned late"):
        batch.release_no_fail()
    assert not private_path.exists()
    assert not writer._terminal
    assert writer in emitter._writers.values()

    batch.release_no_fail()
    assert writer._terminal
    assert emitter._writers == {}
    assert list(spool_root.iterdir()) == []
    emitter.close()
    _assert_bash_terminal_state(emitter)


def test_bash_private_spool_initialization_lost_return_keeps_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-mkdtemp failure remains owned by the writer until exact retry."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    emitter.emit_event(_bash_event("private init ordinary owner"))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    original_fsync = bash_history_module._PrivateJournalDirectory._fsync_parent
    fsync_calls = 0
    fail_once = True

    def fsync_then_raise(
        journal_directory: object,
        parent_descriptor: int,
    ) -> None:
        nonlocal fail_once, fsync_calls
        fsync_calls += 1
        original_fsync(journal_directory, parent_descriptor)
        if fail_once:
            fail_once = False
            raise RuntimeError("private initialization fsync returned late")

    monkeypatch.setattr(
        bash_history_module._PrivateJournalDirectory,
        "_fsync_parent",
        fsync_then_raise,
    )

    with pytest.raises(RuntimeError, match="returned late"):
        batch.prepare(lambda: emitter.emit_event(_bash_event("private init retry", second=1)))
    writer = next(iter(emitter._writers.values()))
    private_path = writer._journal_directory.path
    assert private_path is not None and private_path.exists()
    assert writer._journal_path is None
    assert not writer._terminal
    failed = emitter.journal_census()
    assert failed.pending_operations == failed.admission_receipts == 0
    assert failed.writers == failed.routes == 1
    assert fsync_calls == 1

    batch.publish(lambda: emitter.emit_event(_bash_event("private init retry", second=1)))
    emitter.flush()
    batch.release_no_fail()
    emitter.close()

    assert fsync_calls >= 2
    rendered = _bash_path(root).read_text(encoding="utf-8")
    assert rendered.count("private init ordinary owner") == 1
    assert rendered.count("private init retry") == 1
    assert not private_path.exists()
    assert list(spool_root.iterdir()) == []
    _assert_bash_terminal_state(emitter)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_bash_residual_sqlite_components_reconcile_unlink_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    """Every owned SQLite companion stays private and cleanup survives a lost return."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("residual sidecar cleanup")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))

    with monkeypatch.context() as patch:
        patch.setattr(emitter, "_try_reclaim_writer", lambda *_args: None)
        batch.release_no_fail()

    connection = writer._connection
    journal_path = writer._journal_path
    journal_name = writer._journal_name
    assert connection is not None and journal_path is not None and journal_name is not None
    connection.close()
    writer._connection = None
    companions = [Path(f"{journal_path}{candidate}") for candidate in ("-journal", "-wal", "-shm")]
    for companion in companions:
        companion.write_bytes(f"owned {companion.suffix}".encode())

    journal_directory = writer._journal_directory
    private_path = journal_directory.path
    assert private_path is not None
    original_close = journal_directory.close
    original_unlink = journal_directory._unlink_retained_component
    original_parent_fsync = journal_directory._fsync_parent
    close_calls = 0
    target_unlink_calls = 0
    parent_fsync_calls = 0
    fail_once = True

    def counted_close() -> None:
        nonlocal close_calls
        close_calls += 1
        original_close()

    def unlink_then_raise(directory_descriptor: int, name: str) -> None:
        nonlocal fail_once, target_unlink_calls
        original_unlink(directory_descriptor, name)
        if name == f"{journal_name}{suffix}":
            target_unlink_calls += 1
            if fail_once:
                fail_once = False
                raise RuntimeError("residual sidecar unlink returned late")

    def counted_parent_fsync(parent_descriptor: int) -> None:
        nonlocal parent_fsync_calls
        parent_fsync_calls += 1
        original_parent_fsync(parent_descriptor)

    monkeypatch.setattr(journal_directory, "close", counted_close)
    monkeypatch.setattr(journal_directory, "_unlink_retained_component", unlink_then_raise)
    monkeypatch.setattr(journal_directory, "_fsync_parent", counted_parent_fsync)

    with pytest.raises(RuntimeError, match="returned late"):
        emitter._try_reclaim_writer(("alice", "linux-01.example.test"), writer)
    assert private_path.exists()
    assert target_unlink_calls == 1
    assert not Path(f"{journal_path}{suffix}").exists()
    assert not writer._terminal

    emitter._try_reclaim_writer(("alice", "linux-01.example.test"), writer)
    assert close_calls >= 2
    assert target_unlink_calls == 1
    assert parent_fsync_calls >= 1
    assert writer._terminal
    assert emitter._writers == {}
    assert not private_path.exists()
    assert list(spool_root.iterdir()) == []
    emitter.close()
    _assert_bash_terminal_state(emitter)


def test_bash_private_cleanup_retains_unowned_file_until_explicit_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal cleanup never guesses that an unrelated private-root file is owned."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("unowned cleanup guard")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))
    with monkeypatch.context() as patch:
        patch.setattr(emitter, "_try_reclaim_writer", lambda *_args: None)
        batch.release_no_fail()

    private_path = writer._journal_directory.path
    assert private_path is not None
    intruder = private_path / "not-owned-by-this-route"
    sentinel = b"unowned-private-root-sentinel"
    intruder.write_bytes(sentinel)

    with pytest.raises(ExactPublicationError, match="unowned file"):
        emitter._try_reclaim_writer(("alice", "linux-01.example.test"), writer)
    assert intruder.read_bytes() == sentinel
    assert private_path.exists()
    assert not writer._terminal

    intruder.unlink()
    emitter._try_reclaim_writer(("alice", "linux-01.example.test"), writer)
    assert writer._terminal
    assert emitter._writers == {}
    assert list(spool_root.iterdir()) == []
    emitter.close()
    _assert_bash_terminal_state(emitter)


def test_bash_private_cleanup_unlinks_owned_symlink_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An owned-looking residual link is removed without following its target."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("owned link cleanup")))
    emitter.flush()
    writer = next(iter(emitter._writers.values()))
    with monkeypatch.context() as patch:
        patch.setattr(emitter, "_try_reclaim_writer", lambda *_args: None)
        batch.release_no_fail()

    journal_directory = writer._journal_directory
    private_path = journal_directory.path
    assert private_path is not None
    target = tmp_path / "external-sidecar-target"
    sentinel = b"external-sidecar-target-sentinel"
    target.write_bytes(sentinel)
    link_name = f"{journal_directory._journal_prefix}{'a' * 32}.sqlite3-wal"
    retained_link = private_path / link_name
    retained_link.symlink_to(target)

    emitter._try_reclaim_writer(("alice", "linux-01.example.test"), writer)

    assert target.read_bytes() == sentinel
    assert not retained_link.exists()
    assert writer._terminal
    assert emitter._writers == {}
    assert list(spool_root.iterdir()) == []
    emitter.close()
    _assert_bash_terminal_state(emitter)


def test_snort_exact_candidate_freezes_final_native_line_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Candidate retry/finalization consumes frozen text, never a mutable dictionary."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("frozen candidate")
    batch.prepare(lambda: emitter.emit_event(event))
    assert not output.exists()
    assert emitter._spool_path is None
    assert emitter.ids_alert_summary == {}
    assert emitter.ids_evaluation_summary == {}
    event["message"] = "mutated candidate"

    def reject_rerender(_event_data: dict[str, object]) -> str:
        raise AssertionError("exact candidate was rerendered")

    monkeypatch.setattr(emitter, "_render_alert", reject_rerender)
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("frozen candidate") == 1
    assert "mutated candidate" not in rendered


def test_snort_exact_raw_flushes_frozen_line_to_its_route_before_close(tmp_path: Path) -> None:
    """Exact raw rows retain their final line and ordinary flush visibility level."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("frozen raw", candidate=False)
    batch.prepare(lambda: emitter.emit_event(event))
    assert not output.exists()
    assert emitter.ids_evaluation_summary == {}
    event["message"] = "mutated raw"
    batch.commit()
    batch.release_no_fail()
    emitter.flush()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("frozen raw") == 1
    assert "mutated raw" not in rendered
    emitter.close()


def test_snort_failed_close_plan_keeps_next_epoch_and_reconciles_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost replace return is fsynced again before a later epoch is exported."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    _publish_exact(emitter, _snort_event("first epoch", second=1))
    original_replace = emitter._replace_output
    fail_after = True
    reconciliations = 0
    original_reconcile = emitter._reconcile_output

    def replace_then_raise(sensor: str, payload: bytes) -> None:
        nonlocal fail_after
        original_replace(sensor, payload)
        if fail_after:
            fail_after = False
            raise RuntimeError("Snort replace returned late")

    def record_reconcile(sensor: str, digest: str, size: int) -> None:
        nonlocal reconciliations
        reconciliations += 1
        original_reconcile(sensor, digest, size)

    monkeypatch.setattr(emitter, "_replace_output", replace_then_raise)
    monkeypatch.setattr(emitter, "_reconcile_output", record_reconcile)
    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    _publish_exact(emitter, _snort_event("second epoch", second=2))
    emitter.close()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("first epoch") == 1
    assert rendered.count("second epoch") == 1
    assert reconciliations >= 2


def test_snort_capacity_charges_plans_receipts_summaries_and_gc(tmp_path: Path) -> None:
    """Journal metadata and retained public summaries share the configured ceiling."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=32,
        journal_byte_capacity=128 * 1024,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event("charged raw", candidate=False)))
    assert emitter.journal_census().reserved_rows >= 2
    batch.commit()
    emitter.flush()
    retained = emitter.journal_census()
    assert retained.admission_receipts == 1
    assert retained.export_receipts == 1
    assert retained.summary_rows >= 1
    assert retained.retained_rows >= 3

    batch.release_no_fail()
    released = emitter.journal_census()
    assert released.admission_receipts == released.export_receipts == 0
    assert released.retained_rows == released.summary_rows
    emitter.close()
    assert emitter.journal_census().pending_rows == 0


def test_snort_close_before_release_retains_only_the_admission_receipt(tmp_path: Path) -> None:
    """Physical close may precede core release while preserving terminal cleanup."""

    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "snort.log")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_snort_event("unreleased")))
    emitter.close()
    retained = emitter.journal_census()
    assert retained.pending_rows == 0
    assert retained.admission_receipts == 1
    assert emitter._close_state == "closed"
    journal_path = emitter._journal_path
    assert journal_path is not None and journal_path.exists()
    batch.release_no_fail()
    assert emitter.journal_census().admission_receipts == 0
    assert not journal_path.exists()
    emitter.close()


def test_snort_threaded_exact_drain_is_not_a_physical_flush_and_gc_is_terminal(
    tmp_path: Path,
) -> None:
    """The FIFO drain preserves one logical epoch and close collects all journal state."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    emitter.emit_raw(_snort_event("ordinary buffered", candidate=False))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event("exact buffered", second=1)))
    assert not output.exists()

    batch.commit()
    batch.release_no_fail()
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("ordinary buffered") == 1
    assert rendered.count("exact buffered") == 1
    terminal = emitter.journal_census()
    assert terminal.pending_rows == terminal.reserved_rows == 0
    assert terminal.retained_rows == terminal.retained_bytes == 0


def test_snort_threaded_drain_baseexception_is_acknowledged_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drain interruption wakes the producer without poisoning the worker."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    original = emitter._process_exact_drain
    fail_once = True

    def interrupt_once() -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise KeyboardInterrupt("Snort drain interrupted")
        original()

    monkeypatch.setattr(emitter, "_process_exact_drain", interrupt_once)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(KeyboardInterrupt, match="drain interrupted"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("retry drain")))
    batch.prepare(lambda: emitter.emit_event(_snort_event("retry drain")))
    batch.commit()
    batch.release_no_fail()
    assert emitter._thread is not None and emitter._thread.is_alive()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("retry drain") == 1


def test_snort_close_cannot_overtake_drain_registration_or_exact_enqueue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The producer RLock covers drain, participant registration, and FIFO handoff."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        threaded=True,
    )
    entered = Event()
    release_drain = Event()
    original = emitter._drain_threaded_before_exact

    def block_after_drain() -> None:
        original()
        entered.set()
        assert release_drain.wait(timeout=2)

    monkeypatch.setattr(emitter, "_drain_threaded_before_exact", block_after_drain)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    failures: list[BaseException] = []
    prepared = Event()
    producer = Thread(
        target=lambda: (
            _capture_failure(
                failures,
                lambda: batch.prepare(lambda: emitter.emit_event(_snort_event("raced exact"))),
            ),
            prepared.set(),
        )
    )
    producer.start()
    assert entered.wait(timeout=2)
    closed = Event()
    closer = Thread(target=lambda: (_capture_failure(failures, emitter.close), closed.set()))
    closer.start()
    assert not closed.wait(timeout=0.1)
    release_drain.set()
    assert prepared.wait(timeout=2)
    assert _wait_for_state(emitter, "closing")
    assert not closed.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    producer.join(timeout=2)
    closer.join(timeout=2)
    assert failures == []
    assert closed.is_set()
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_snort_event("late work", second=2))


def test_snort_journal_parameterizes_values_and_rejects_non_json_content(
    tmp_path: Path,
) -> None:
    """SQL-looking text remains data while opaque Python objects fail before admission."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    with pytest.raises(ExactPublicationError, match="frozen schema"):
        emitter._parse_exact_envelope('{"schema":1,"__class__":"opaque"}')
    unsafe = ExactPublicationAuthority(capacity=1).issue_batch()
    opaque = _snort_event("opaque") | {"opaque": object()}
    with pytest.raises(TypeError, match="JSON serializable"):
        unsafe.prepare(lambda: emitter.emit_event(opaque))
    assert emitter._journal_path is None

    injected = "x'); DROP TABLE candidates; --"
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_snort_event(injected)))
    connection = emitter._spool_connection
    assert connection is not None
    journal_path = emitter._journal_path
    assert journal_path is not None
    assert journal_path.parent.parent != output.parent
    assert output.parent not in journal_path.parents
    assert stat.S_IMODE(journal_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    assert connection.execute("SELECT COUNT(*) FROM candidates").fetchone() == (1,)
    assert connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?",
        ("table", "candidates"),
    ).fetchone() == (1,)
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count(injected) == 1


def test_snort_sql_statements_are_static_and_values_are_bound() -> None:
    """Every SQLite call uses static SQL so serialized values remain parameters."""

    tree = ast.parse(inspect.getsource(snort_module.SnortEmitter))
    sql_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"execute", "executemany"}
    ]
    assert sql_calls
    assert all(
        node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        for node in sql_calls
    )


@pytest.mark.parametrize("replacement", ["symlink", "hardlink"])
def test_snort_sqlite_open_rejects_path_substitution_without_mutating_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    """SQLite never executes SQL through a substituted journal pathname."""

    victim = tmp_path / f"victim-{replacement}.sqlite3"
    victim_connection = sqlite3.connect(victim)
    victim_connection.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
    victim_connection.execute("INSERT INTO sentinel (value) VALUES (?)", ("unchanged",))
    victim_connection.commit()
    victim_connection.close()
    victim_before = victim.read_bytes()
    original_connect = sqlite3.connect

    def substitute_path(database: object, *args: object, **kwargs: object) -> sqlite3.Connection:
        journal_path = Path(unquote(urlsplit(str(database)).path))
        journal_path.unlink()
        if replacement == "symlink":
            journal_path.symlink_to(victim)
        else:
            os.link(victim, journal_path)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", substitute_path)
    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "snort.log")
    with pytest.raises(ExactPublicationError, match="journal path changed"):
        emitter.emit_raw(_snort_event("substituted journal", candidate=False))

    assert victim.read_bytes() == victim_before
    check = original_connect(victim)
    try:
        assert check.execute(
            "SELECT name FROM sqlite_master WHERE type = ? ORDER BY name",
            ("table",),
        ).fetchall() == [("sentinel",)]
        assert check.execute("SELECT value FROM sentinel").fetchall() == [("unchanged",)]
    finally:
        check.close()


def test_snort_sqlite_initialization_failure_releases_private_path_and_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-schema durability failure cannot leak a journal directory or its dirfd."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    output = tmp_path / "public" / "snort.log"
    original_open = os.open
    original_fsync = snort_module._PrivateJournalDirectory.fsync
    directory_descriptors: list[int] = []

    def track_open(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is None:
            descriptor = original_open(path, flags, mode)
        else:
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if flags & getattr(os, "O_DIRECTORY", 0):
            directory_descriptors.append(descriptor)
        return descriptor

    def fail_private_directory_sync(
        owner: snort_module._PrivateJournalDirectory,
    ) -> None:
        original_fsync(owner)
        raise OSError("post-schema directory sync failed")

    monkeypatch.setattr(snort_module.os, "open", track_open)
    monkeypatch.setattr(
        snort_module._PrivateJournalDirectory,
        "fsync",
        fail_private_directory_sync,
    )
    emitter = SnortEmitter(load_format("snort_alert"), output)
    for second in range(2):
        with pytest.raises(OSError, match="post-schema directory sync failed"):
            emitter.emit_raw(
                _snort_event(f"initialization failure {second}", second=second, candidate=False)
            )
        assert list(spool_root.iterdir()) == []
        assert emitter._spool_connection is None
        assert emitter._journal_directory_descriptor is None

    for descriptor in directory_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)

    monkeypatch.setattr(snort_module._PrivateJournalDirectory, "fsync", original_fsync)
    emitter.close()


def test_snort_prereserved_participant_drains_prior_fifo_without_physical_flush(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-reservation drains older work before installing the exact queue fence."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    worker_waiting = Event()
    release_worker = Event()
    reserved = Event()
    failures: list[BaseException] = []
    original_wait = emitter._wait_for_exact_publication_turn
    blocked_once = False

    def pause_prior_ordinary(queued: object) -> None:
        nonlocal blocked_once
        if get_ident() == emitter._thread.ident and queued is None and not blocked_once:
            blocked_once = True
            worker_waiting.set()
            assert release_worker.wait(timeout=2)
        original_wait(queued)

    monkeypatch.setattr(emitter, "_wait_for_exact_publication_turn", pause_prior_ordinary)
    emitter.emit_raw(_snort_event("prior fifo", candidate=False))
    assert worker_waiting.wait(timeout=2)
    batch = ExactPublicationAuthority(capacity=2).issue_batch()
    reserver = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.reserve_participants((emitter,))),
            reserved.set(),
        ),
        daemon=True,
    )
    reserver.start()
    assert not reserved.wait(timeout=0.1)
    release_worker.set()
    assert reserved.wait(timeout=2)
    assert not output.exists()

    batch.publish(
        lambda: (
            emitter.emit_event(_snort_event("reserved exact one", second=1)),
            emitter.emit_event(_snort_event("reserved exact two", second=2)),
        )
    )
    batch.release_no_fail()
    emitter.close()
    reserver.join(timeout=2)
    assert failures == []
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("prior fifo") == 1
    assert rendered.count("reserved exact one") == 1
    assert rendered.count("reserved exact two") == 1


def test_snort_multirow_exact_epoch_blocks_ordinary_interposition(tmp_path: Path) -> None:
    """Ordinary admission cannot enter the FIFO between rows of one exact participant."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    batch = ExactPublicationAuthority(capacity=2).issue_batch()
    first_staged = Event()
    ordinary_started = Event()
    ordinary_returned = Event()
    prepared = Event()
    failures: list[BaseException] = []

    def render_two() -> None:
        emitter.emit_event(_snort_event("exact row one"))
        first_staged.set()
        assert ordinary_started.wait(timeout=2)
        assert not ordinary_returned.wait(timeout=0.1)
        emitter.emit_event(_snort_event("exact row two", second=1))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render_two)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)

    def emit_ordinary() -> None:
        ordinary_started.set()
        _capture_failure(
            failures,
            lambda: emitter.emit_raw(
                _snort_event("ordinary after epoch", second=2, candidate=False)
            ),
        )
        ordinary_returned.set()

    ordinary = Thread(target=emit_ordinary, daemon=True)
    ordinary.start()
    assert prepared.wait(timeout=2)
    batch.commit()
    batch.release_no_fail()
    assert ordinary_returned.wait(timeout=2)
    producer.join(timeout=2)
    ordinary.join(timeout=2)
    emitter.close()
    assert failures == []
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("exact row one") == 1
    assert rendered.count("exact row two") == 1
    assert rendered.count("ordinary after epoch") == 1


def test_snort_close_between_exact_rows_waits_for_continuation(tmp_path: Path) -> None:
    """Close may claim the boundary but cannot reject a continuation row."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    batch = ExactPublicationAuthority(capacity=2).issue_batch()
    first_staged = Event()
    continue_batch = Event()
    prepared = Event()
    closed = Event()
    failures: list[BaseException] = []

    def render_two() -> None:
        emitter.emit_event(_snort_event("close row one"))
        first_staged.set()
        assert continue_batch.wait(timeout=2)
        emitter.emit_event(_snort_event("close row two", second=1))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render_two)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)
    closer = Thread(
        target=lambda: (_capture_failure(failures, emitter.close), closed.set()),
        daemon=True,
    )
    closer.start()
    assert _wait_for_state(emitter, "closing")
    continue_batch.set()
    assert prepared.wait(timeout=2)
    assert not closed.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    assert closed.wait(timeout=2)
    producer.join(timeout=2)
    closer.join(timeout=2)
    assert failures == []
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("close row one") == 1
    assert rendered.count("close row two") == 1


def test_snort_barrier_between_exact_rows_waits_without_blocking_continuation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public barrier waits outside the producer lock while an epoch continues."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        threaded=True,
    )
    batch = ExactPublicationAuthority(capacity=2).issue_batch()
    first_staged = Event()
    continue_batch = Event()
    prepared = Event()
    barrier_waiting = Event()
    barrier_done = Event()
    barrier_threads: set[int] = set()
    failures: list[BaseException] = []
    original_wait = emitter._wait_for_exact_publication_turn

    def observe_wait(queued: object) -> None:
        if get_ident() in barrier_threads and queued is None:
            barrier_waiting.set()
        original_wait(queued)

    monkeypatch.setattr(emitter, "_wait_for_exact_publication_turn", observe_wait)

    def render_two() -> None:
        emitter.emit_event(_snort_event("barrier row one"))
        first_staged.set()
        assert continue_batch.wait(timeout=2)
        emitter.emit_event(_snort_event("barrier row two", second=1))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render_two)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)

    def run_barrier() -> None:
        barrier_threads.add(get_ident())
        _capture_failure(failures, emitter.barrier_flush)
        barrier_done.set()

    barrier = Thread(target=run_barrier, daemon=True)
    barrier.start()
    assert barrier_waiting.wait(timeout=2)
    continue_batch.set()
    assert prepared.wait(timeout=2)
    assert not barrier_done.wait(timeout=0.1)
    batch.commit()
    batch.release_no_fail()
    assert barrier_done.wait(timeout=2)
    emitter.close()
    producer.join(timeout=2)
    barrier.join(timeout=2)
    assert failures == []


def test_snort_summary_persist_lost_return_recovers_public_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable summary commit followed by an exception installs the same snapshot once."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("summary retry", candidate=False)
    batch.publish(lambda: emitter.emit_event(event))
    original = emitter._persist_summaries_unlocked
    fail_once = True

    def persist_then_raise(
        alert_summary: dict[str, dict[int, dict[str, object]]],
        evaluation_summary: dict[str, dict[str, dict[str, object]]],
    ) -> None:
        nonlocal fail_once
        original(alert_summary, evaluation_summary)
        if fail_once:
            fail_once = False
            raise RuntimeError("summary persist returned late")

    monkeypatch.setattr(emitter, "_persist_summaries_unlocked", persist_then_raise)
    with pytest.raises(RuntimeError, match="returned late"):
        emitter.flush()
    emitter.flush()
    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    expected_digest = new_ids_digest()
    update_ids_digest(expected_digest, "__direct__", event)
    assert summary["candidate"] == summary["emitted"] == 1
    assert summary["emitted_sha256"] == expected_digest.hexdigest()
    assert output.read_text(encoding="utf-8").count("summary retry") == 1
    batch.release_no_fail()
    emitter.close()


def test_snort_durable_summary_fences_later_rows_until_export_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A summary with no plan seals its epoch until a boundary exports it."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    t1 = _snort_event("sealed t1", second=1, candidate=False)
    t0 = _snort_event("later t0", candidate=False)
    emitter.emit_raw(t1)
    original = emitter._persist_summaries_unlocked
    fail_once = True

    def persist_then_raise(
        alert_summary: dict[str, dict[int, dict[str, object]]],
        evaluation_summary: dict[str, dict[str, dict[str, object]]],
    ) -> None:
        nonlocal fail_once
        original(alert_summary, evaluation_summary)
        if fail_once:
            fail_once = False
            raise RuntimeError("sealed summary returned late")

    monkeypatch.setattr(emitter, "_persist_summaries_unlocked", persist_then_raise)
    with pytest.raises(RuntimeError, match="sealed summary returned late"):
        emitter.flush()
    connection = emitter._spool_connection
    assert connection is not None
    assert connection.execute("SELECT COUNT(*) FROM export_plans").fetchone() == (0,)
    assert connection.execute(
        "SELECT COUNT(*) FROM candidates WHERE summarized = ? AND exported = ?",
        (1, 0),
    ).fetchone() == (1,)
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(t0)

    emitter.flush()
    emitter.emit_raw(t0)
    emitter.flush()
    lines = output.read_text(encoding="utf-8").splitlines()
    assert ["sealed t1" in line for line in lines] == [True, False]
    assert ["later t0" in line for line in lines] == [False, True]
    expected = new_ids_digest()
    update_ids_digest(expected, "__direct__", t1 | {"_ids_origin": "raw"})
    update_ids_digest(expected, "__direct__", t0 | {"_ids_origin": "raw"})
    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert summary["emitted_sha256"] == expected.hexdigest()
    emitter.close()


def test_snort_failed_close_charges_exported_candidates_until_terminal_gc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rows retained for cross-epoch filtering stay visible to scalar capacity accounting."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path,
        sensor_hostnames=["sensor-a", "sensor-b"],
        journal_row_capacity=32,
        journal_byte_capacity=128 * 1024,
    )
    _publish_exact(emitter, _snort_event("charged exported candidate"))
    original = emitter._replace_output

    def fail_sensor_b(sensor: str, payload: bytes) -> None:
        if sensor == "sensor-b":
            raise RuntimeError("sensor-b publication failed")
        original(sensor, payload)

    monkeypatch.setattr(emitter, "_replace_output", fail_sensor_b)
    with pytest.raises(RuntimeError, match="sensor-b publication failed"):
        emitter.close()
    connection = emitter._spool_connection
    assert connection is not None
    exported = connection.execute(
        "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM candidates WHERE exported = ?",
        (1,),
    ).fetchone()
    census = emitter.journal_census()
    assert exported is not None
    assert census.exported_rows == exported[0] == 0
    assert census.exported_bytes == exported[1]
    assert census.pending_rows == 1
    assert census.retained_rows >= census.pending_rows + census.filter_rows
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(_snort_event("late partial epoch", second=1, candidate=False))
    sensor_a = tmp_path / "sensor-a" / "snort_alert.log"
    sensor_b = tmp_path / "sensor-b" / "snort_alert.log"
    assert sensor_a.read_text(encoding="utf-8").count("charged exported candidate") == 1
    assert not sensor_b.exists()

    monkeypatch.setattr(emitter, "_replace_output", original)
    emitter.close()
    assert sensor_a.read_text(encoding="utf-8").count("charged exported candidate") == 1
    assert sensor_b.read_text(encoding="utf-8").count("charged exported candidate") == 1
    terminal = emitter.journal_census()
    assert terminal.exported_rows == terminal.pending_rows == 0
    assert terminal.retained_rows == 0


def test_snort_plan_creation_failure_keeps_partial_export_recovery_fenced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A physical first sensor keeps admission closed if the next plan was never sealed."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path,
        sensor_hostnames=["sensor-a", "sensor-b"],
    )
    _publish_exact(emitter, _snort_event("sticky plan recovery"))
    original = emitter._create_export_plan_unlocked

    def fail_sensor_b_plan(
        sensor: str,
        lines: list[str],
        cutoff: int | None,
        *,
        raw_only: bool,
    ) -> None:
        if sensor == "sensor-b":
            raise RuntimeError("sensor-b plan creation failed")
        original(sensor, lines, cutoff, raw_only=raw_only)

    monkeypatch.setattr(emitter, "_create_export_plan_unlocked", fail_sensor_b_plan)
    with pytest.raises(RuntimeError, match="sensor-b plan creation failed"):
        emitter.close()

    sensor_a = tmp_path / "sensor-a" / "snort_alert.log"
    sensor_b = tmp_path / "sensor-b" / "snort_alert.log"
    assert sensor_a.read_text(encoding="utf-8").count("sticky plan recovery") == 1
    assert not sensor_b.exists()
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(_snort_event("must remain fenced", second=1, candidate=False))

    monkeypatch.setattr(emitter, "_create_export_plan_unlocked", original)
    emitter.close()
    assert sensor_a.read_text(encoding="utf-8").count("sticky plan recovery") == 1
    assert sensor_b.read_text(encoding="utf-8").count("sticky plan recovery") == 1
    terminal = emitter.journal_census()
    assert terminal.pending_rows == terminal.exported_rows == terminal.retained_rows == 0


def test_snort_failed_threaded_close_preserves_prefix_and_later_buffer_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reconciled plan consumes its old prefix without rejecting later ordinary rows."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    emitter.emit_raw(_snort_event("planned prefix", candidate=False))
    _publish_exact(emitter, _snort_event("planned candidate", second=1))
    original = emitter._replace_output
    fail_once = True

    def replace_then_raise(sensor: str, payload: bytes) -> None:
        nonlocal fail_once
        original(sensor, payload)
        if fail_once:
            fail_once = False
            raise RuntimeError("threaded close returned late")

    monkeypatch.setattr(emitter, "_replace_output", replace_then_raise)
    with pytest.raises(RuntimeError):
        emitter.close()
    assert emitter._close_state == "open"
    assert emitter._thread is not None and emitter._thread.is_alive()
    assert all(writer._close_state == "open" for writer in emitter._writers.values())

    emitter.emit_raw(_snort_event("later suffix", second=2, candidate=False))
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("planned prefix") == 1
    assert rendered.count("planned candidate") == 1
    assert rendered.count("later suffix") == 1


def test_snort_failed_close_preserves_identical_later_buffer_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable prefix receipt distinguishes a new byte-identical ordinary row."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    repeated = _snort_event("identical ordinary", candidate=False)
    emitter.emit_raw(repeated)
    _publish_exact(emitter, _snort_event("candidate between copies", second=1))
    original = emitter._replace_output
    fail_once = True

    def replace_then_raise(sensor: str, payload: bytes) -> None:
        nonlocal fail_once
        original(sensor, payload)
        if fail_once:
            fail_once = False
            raise RuntimeError("identical-prefix close returned late")

    monkeypatch.setattr(emitter, "_replace_output", replace_then_raise)
    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    emitter.emit_raw(repeated)
    emitter.close()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("identical ordinary") == 2
    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert summary["candidate"] == summary["emitted"] == 3


def test_snort_buffer_consumption_lost_return_preserves_identical_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The local receipt bridges prefix removal before its durable marker commits."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    repeated = _snort_event("marker-lost ordinary", candidate=False)
    emitter.emit_raw(repeated)
    _publish_exact(emitter, _snort_event("marker-lost candidate", second=1))
    original = emitter._consume_plan_buffer_unlocked
    fail_once = True

    def consume_then_lose_marker(
        sensor: str,
        epoch: int,
        writer: object,
        lines: list[str],
    ) -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            if writer is not None:
                with writer._exact_publication_condition:
                    with writer._lock:
                        assert writer.buffer[: len(lines)] == lines
                        del writer.buffer[: len(lines)]
                emitter._consumed_plan_buffers.add((sensor, epoch))
            else:
                original(sensor, epoch, writer, lines)
            raise RuntimeError("buffer marker returned late")
        original(sensor, epoch, writer, lines)

    monkeypatch.setattr(emitter, "_consume_plan_buffer_unlocked", consume_then_lose_marker)
    with pytest.raises(RuntimeError, match="marker returned late"):
        emitter.close()
    emitter.emit_raw(repeated)
    emitter.close()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("marker-lost ordinary") == 2
    assert rendered.count("marker-lost candidate") == 1


def test_snort_ordinary_raw_merges_with_prior_exact_evaluation_history(
    tmp_path: Path,
) -> None:
    """Ordinary summary updates extend, rather than replace, an exact digest history."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    exact_event = _snort_event("exact history", candidate=False)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(exact_event))
    emitter.flush()
    batch.release_no_fail()

    ordinary_event = _snort_event("ordinary history", second=1, candidate=False)
    emitter.emit_raw(ordinary_event)
    emitter.flush()
    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    expected_digest = new_ids_digest()
    update_ids_digest(expected_digest, "__direct__", exact_event)
    update_ids_digest(expected_digest, "__direct__", ordinary_event | {"_ids_origin": "raw"})
    assert summary["candidate"] == summary["emitted"] == 2
    assert summary["emitted_sha256"] == expected_digest.hexdigest()
    emitter.close()


def test_snort_mixed_exact_and_ordinary_digest_follows_final_sorted_output(
    tmp_path: Path,
) -> None:
    """Evaluation hashing consumes the same global order as one physical flush."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    exact_t0 = _snort_event("exact t0", candidate=False)
    ordinary_t1 = _snort_event("ordinary t1", second=1, candidate=False)
    _publish_exact(emitter, exact_t0)
    emitter.emit_raw(ordinary_t1)
    emitter.flush()

    lines = output.read_text(encoding="utf-8").splitlines()
    assert ["exact t0" in line for line in lines] == [True, False]
    assert ["ordinary t1" in line for line in lines] == [False, True]
    expected = new_ids_digest()
    update_ids_digest(expected, "__direct__", exact_t0)
    update_ids_digest(expected, "__direct__", ordinary_t1 | {"_ids_origin": "raw"})
    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert summary["emitted_sha256"] == expected.hexdigest()
    emitter.close()


def test_snort_cross_epoch_digest_follows_append_order_for_flush_and_close(
    tmp_path: Path,
) -> None:
    """Backdated rows append across publication epochs and hash in that physical order."""

    flush_output = tmp_path / "flush.log"
    flush_emitter = SnortEmitter(load_format("snort_alert"), flush_output)
    ordinary_t1 = _snort_event("flush t1", second=1, candidate=False)
    ordinary_t0 = _snort_event("flush t0", candidate=False)
    flush_emitter.emit_raw(ordinary_t1)
    flush_emitter.flush()
    flush_emitter.emit_raw(ordinary_t0)
    flush_emitter.flush()

    flush_lines = flush_output.read_text(encoding="utf-8").splitlines()
    assert ["flush t1" in line for line in flush_lines] == [True, False]
    assert ["flush t0" in line for line in flush_lines] == [False, True]
    flush_digest = new_ids_digest()
    update_ids_digest(flush_digest, "__direct__", ordinary_t1 | {"_ids_origin": "raw"})
    update_ids_digest(flush_digest, "__direct__", ordinary_t0 | {"_ids_origin": "raw"})
    flush_summary = flush_emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert flush_summary["emitted_sha256"] == flush_digest.hexdigest()
    flush_emitter.close()

    close_output = tmp_path / "close.log"
    close_emitter = SnortEmitter(load_format("snort_alert"), close_output)
    close_t1 = _snort_event("close t1", second=1, candidate=False)
    close_t0 = _snort_event("close t0", candidate=False)
    close_emitter.emit_raw(close_t1)
    close_emitter.flush()
    _publish_exact(close_emitter, close_t0)
    close_emitter.close()

    close_lines = close_output.read_text(encoding="utf-8").splitlines()
    assert ["close t1" in line for line in close_lines] == [True, False]
    assert ["close t0" in line for line in close_lines] == [False, True]
    close_digest = new_ids_digest()
    update_ids_digest(close_digest, "__direct__", close_t1 | {"_ids_origin": "raw"})
    update_ids_digest(close_digest, "__direct__", close_t0)
    close_summary = close_emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert close_summary["emitted_sha256"] == close_digest.hexdigest()


def test_snort_ordinary_candidate_defers_render_and_accepts_non_json_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary candidates retain legacy deferred rendering and dictionary compatibility."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output, threaded=True)
    _publish_exact(emitter, _snort_event("journal seed", candidate=False))
    render_count = 0
    original = emitter._render_alert

    class Opaque:
        def __deepcopy__(self, _memo: object) -> object:
            raise AssertionError("ordinary metadata was deep-copied")

    def count_render(event_data: dict[str, object]) -> str | None:
        nonlocal render_count
        render_count += 1
        return original(event_data)

    monkeypatch.setattr(emitter, "_render_alert", count_render)
    event = _snort_event("ordinary opaque") | {"opaque": Opaque()}
    emitter.emit_event(event)
    assert render_count == 0
    emitter.close()
    assert render_count == 1
    assert output.read_text(encoding="utf-8").count("ordinary opaque") == 1


def test_snort_admission_lost_return_reconciles_durable_scalar_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retry discovers the atomic row/receipt/census commit without double charging it."""

    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "snort.log")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event("admission retry")))
    original = emitter._insert_values_unlocked
    fail_once = True

    def insert_then_lose_memory(*args: object, **kwargs: object) -> None:
        nonlocal fail_once
        original(*args, **kwargs)
        if fail_once:
            fail_once = False
            exact_key = kwargs.get("exact_key")
            if exact_key is not None:
                emitter._exact_candidate_receipts.pop(exact_key, None)
            raise RuntimeError("admission insert returned late")

    monkeypatch.setattr(emitter, "_insert_values_unlocked", insert_then_lose_memory)
    with pytest.raises(RuntimeError, match="returned late"):
        batch.commit()
    durable = emitter.journal_census()
    assert durable.pending_rows == durable.admission_receipts == 1
    connection = emitter._spool_connection
    assert connection is not None
    assert connection.execute("SELECT COUNT(*) FROM admission_receipts").fetchone() == (1,)

    batch.commit()
    reconciled = emitter.journal_census()
    assert reconciled.pending_rows == reconciled.admission_receipts == 1
    batch.release_no_fail()
    emitter.close()


@pytest.mark.parametrize(
    ("row_capacity", "byte_capacity"),
    ((5, 1_000_000), (64, 4_096)),
)
def test_snort_admission_rejects_without_terminal_summary_and_plan_headroom(
    tmp_path: Path,
    row_capacity: int,
    byte_capacity: int,
) -> None:
    """A committed exact row cannot consume capacity needed to terminalize itself."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        journal_row_capacity=row_capacity,
        journal_byte_capacity=byte_capacity,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="journal .* capacity is exhausted"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("terminal headroom")))
    batch.cancel()
    assert emitter.journal_census().retained_rows == 0
    emitter.close()


def test_snort_minimum_reserved_headroom_terminalizes_after_release(tmp_path: Path) -> None:
    """The first admitted candidate can always publish within its reserved row budget."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=8,
        journal_byte_capacity=1_000_000,
    )
    _publish_exact(emitter, _snort_event("bounded terminal"))
    emitter.close()
    assert output.read_text(encoding="utf-8").count("bounded terminal") == 1
    assert emitter.journal_census().retained_rows == 0


def test_snort_released_candidates_compact_into_bounded_filter_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Released epochs reclaim rows while a later candidate keeps filter history."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=16,
        journal_byte_capacity=128 * 1024,
    )
    policy = {
        "detection_filter": {"track": "by_src", "count": 2, "seconds": 60},
        "event_filter": None,
    }
    original = emitter._replace_output
    retained_counts: list[int] = []

    for second in range(3):
        fail_once = True

        def replace_then_return_late(sensor: str, payload: bytes) -> None:
            nonlocal fail_once
            original(sensor, payload)
            if fail_once:
                fail_once = False
                raise RuntimeError("checkpoint close returned late")

        monkeypatch.setattr(emitter, "_replace_output", replace_then_return_late)
        event = _snort_event(f"checkpoint candidate {second}", second=second)
        event["_ids_policy"] = policy
        _publish_exact(emitter, event)
        with pytest.raises(RuntimeError, match="checkpoint close returned late"):
            emitter.close()
        connection = emitter._spool_connection
        assert connection is not None
        assert connection.execute("SELECT COUNT(*) FROM candidates").fetchone() == (0,)
        census = emitter.journal_census()
        assert census.pending_rows == census.exported_rows == 0
        assert census.filter_rows == 1
        physical_rows = sum(
            connection.execute(statement).fetchone()[0]
            for statement in (
                "SELECT COUNT(*) FROM candidates",
                "SELECT COUNT(*) FROM admission_receipts",
                "SELECT COUNT(*) FROM export_receipts",
                "SELECT COUNT(*) FROM summaries",
                "SELECT COUNT(*) FROM filter_checkpoints",
                "SELECT COUNT(*) FROM export_plans",
            )
        )
        assert census.retained_rows == physical_rows
        retained_counts.append(census.retained_rows)

    assert retained_counts == [retained_counts[0]] * 3
    assert output.read_text(encoding="utf-8").count("checkpoint candidate 2") == 1
    assert "checkpoint candidate 0" not in output.read_text(encoding="utf-8")
    assert "checkpoint candidate 1" not in output.read_text(encoding="utf-8")
    monkeypatch.setattr(emitter, "_replace_output", original)
    emitter.close()
    assert emitter.journal_census().retained_rows == 0


def test_snort_exact_prepare_charges_preexisting_physical_output(tmp_path: Path) -> None:
    """Exact preparation rejects when an existing file consumed export headroom."""

    output = tmp_path / "snort.log"
    output.write_bytes((b"x" * ((33 * 1024) - 1)) + b"\n")
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=32,
        journal_byte_capacity=32 * 1024,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("no headroom")))
    batch.cancel()
    emitter.close()
    assert output.stat().st_size == 33 * 1024


def test_snort_event_only_sensor_route_charges_preexisting_physical_output(
    tmp_path: Path,
) -> None:
    """Per-event routes join the output census before exact or ordinary admission."""

    output_root = tmp_path / "sensors"
    dynamic_output = output_root / "dynamic" / "snort_alert.log"
    dynamic_output.parent.mkdir(parents=True)
    dynamic_output.write_bytes((b"x" * ((33 * 1024) - 1)) + b"\n")
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output_root,
        journal_row_capacity=32,
        journal_byte_capacity=32 * 1024,
    )
    exact_event = _snort_event("dynamic exact") | {"_sensor_hostnames": ["dynamic"]}
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        batch.prepare(lambda: emitter.emit_event(exact_event))
    batch.cancel()

    ordinary_event = _snort_event("dynamic ordinary", candidate=False) | {
        "_sensor_hostnames": ["dynamic"]
    }
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        emitter.emit_raw(ordinary_event)
    emitter.close()
    assert dynamic_output.stat().st_size == 33 * 1024


def test_snort_deferred_ordinary_candidate_reserves_render_and_export_copies(
    tmp_path: Path,
) -> None:
    """A long deferred candidate is rejected early or can always finish publication."""

    message = "ordinary deferred " + ("x" * 20_000)
    rejected = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "rejected.log",
        journal_row_capacity=32,
        journal_byte_capacity=70 * 1024,
    )
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        rejected.emit_event(_snort_event(message))
    rejected.close()

    admitted_output = tmp_path / "admitted.log"
    admitted = SnortEmitter(
        load_format("snort_alert"),
        admitted_output,
        journal_row_capacity=32,
        journal_byte_capacity=192 * 1024,
    )
    admitted.emit_event(_snort_event(message))
    admitted.close()
    assert admitted_output.read_text(encoding="utf-8").count(message) == 1
    assert admitted.journal_census().retained_rows == 0


def test_snort_threshold_flush_preserves_deferred_candidate_headroom(tmp_path: Path) -> None:
    """Raw threshold flushes cannot consume capacity reserved by a deferred candidate."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        buffer_size=1,
        journal_row_capacity=64,
        journal_byte_capacity=256 * 1024,
    )
    candidate_message = "protected deferred " + ("c" * 20_000)
    emitter.emit_event(_snort_event(candidate_message))
    rejected = False
    for second in range(1, 10):
        ordinary = _snort_event(
            f"threshold-{second}-" + ("r" * 8_000),
            second=second,
            candidate=False,
        )
        try:
            emitter.emit_raw(ordinary)
        except ExactPublicationError as error:
            assert "byte capacity is exhausted" in str(error)
            rejected = True
            break
    assert rejected
    assert (output.stat().st_size if output.exists() else 0) < 256 * 1024
    emitter.close()
    assert output.read_text(encoding="utf-8").count(candidate_message) == 1


def test_snort_threshold_flush_cannot_consume_pending_exact_headroom(tmp_path: Path) -> None:
    """Ordinary threshold flushes reject before a pending exact row becomes stranded."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        buffer_size=1,
        journal_row_capacity=64,
        journal_byte_capacity=64 * 1024,
    )
    _publish_exact(emitter, _snort_event("protected threshold exact"))
    rejected = False
    for second in range(1, 20):
        ordinary = _snort_event(
            f"ordinary-{second}-" + ("x" * 2_500),
            second=second,
            candidate=False,
        )
        try:
            emitter.emit_raw(ordinary)
        except ExactPublicationError as error:
            assert "byte capacity is exhausted" in str(error)
            rejected = True
            break
    assert rejected
    assert output.exists()
    assert output.stat().st_size < 64 * 1024
    emitter.close()
    assert output.read_text(encoding="utf-8").count("protected threshold exact") == 1


def test_snort_terminal_headroom_materializes_transactionally_and_fences_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Virtual headroom becomes actual line bytes once, before export admission reopens."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=64,
        journal_byte_capacity=256 * 1024,
    )
    emitter.emit_event(_snort_event("materialized " + ("m" * 20_000)))
    connection = emitter._spool_connection
    assert connection is not None
    before_payload = connection.execute("SELECT payload_bytes FROM candidates").fetchone()
    assert before_payload is not None
    before = emitter.journal_census()
    assert before.terminal_headroom_bytes > 0
    assert connection.execute(
        "SELECT COALESCE(SUM(terminal_headroom_bytes), 0) FROM candidates"
    ).fetchone() == (before.terminal_headroom_bytes,)

    original = emitter._create_export_plan_unlocked

    def reject_plan(
        sensor: str,
        lines: list[str],
        cutoff: int | None,
        *,
        raw_only: bool,
    ) -> None:
        raise RuntimeError(f"sealed plan blocked for {sensor}:{cutoff}:{raw_only}")

    monkeypatch.setattr(emitter, "_create_export_plan_unlocked", reject_plan)
    with pytest.raises(RuntimeError, match="sealed plan blocked"):
        emitter.close()

    after = emitter.journal_census()
    after_payload = connection.execute(
        "SELECT payload_bytes, terminal_headroom_bytes, summarized FROM candidates"
    ).fetchone()
    assert after_payload is not None
    assert after_payload[0] > before_payload[0]
    assert after_payload[1:] == (0, 1)
    assert after.terminal_headroom_bytes == 0
    assert connection.execute(
        "SELECT COALESCE(SUM(terminal_headroom_bytes), 0) FROM candidates"
    ).fetchone() == (0,)
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(_snort_event("late materialization", second=1, candidate=False))

    monkeypatch.setattr(emitter, "_create_export_plan_unlocked", original)
    emitter.close()
    assert output.read_text(encoding="utf-8").count("materialized") == 1
    assert emitter.journal_census().retained_rows == 0


def test_snort_admission_headroom_uses_constant_time_scalar_census() -> None:
    """Prepare and admission never rescan retained candidate headroom."""

    for operation in (
        SnortEmitter._reserve_exact_publication_row,
        SnortEmitter._insert_values_unlocked,
        SnortEmitter.journal_census,
        SnortEmitter._state_unlocked,
    ):
        assert "SUM(" not in inspect.getsource(operation).upper()


def test_snort_filter_checkpoint_fanout_is_reserved_before_exact_admission(
    tmp_path: Path,
) -> None:
    """Long tracked values and both filter families cannot strand summary persistence."""

    policy = {
        "detection_filter": {"track": "by_src", "count": 2, "seconds": 60},
        "event_filter": {
            "type": "limit",
            "track": "by_src",
            "count": 1,
            "seconds": 60,
        },
    }
    event = _snort_event("checkpoint fanout")
    event["src_ip"] = "tracked-" + ("x" * 20_000)
    event["_ids_policy"] = policy

    rejected = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "rejected.log",
        journal_row_capacity=64,
        journal_byte_capacity=128 * 1024,
    )
    rejected_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        rejected_batch.prepare(lambda: rejected.emit_event(event))
    rejected_batch.cancel()
    assert rejected.journal_census().retained_rows == 0
    rejected.close()

    output = tmp_path / "admitted.log"
    admitted = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=64,
        journal_byte_capacity=1024 * 1024,
    )
    _publish_exact(admitted, event)
    admitted.close()
    assert output.read_text(encoding="utf-8") == ""
    assert admitted.journal_census().retained_rows == 0


def test_snort_filter_policy_claims_reject_conflicts_before_durable_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checkpoint and same-batch policy conflicts fail while the core can still cancel."""

    policy_one = {
        "detection_filter": None,
        "event_filter": {
            "type": "limit",
            "track": "by_src",
            "count": 1,
            "seconds": 60,
        },
    }
    policy_two = {
        "detection_filter": None,
        "event_filter": {
            "type": "limit",
            "track": "by_src",
            "count": 2,
            "seconds": 60,
        },
    }
    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "checkpoint.log")
    first = _snort_event("checkpoint policy")
    first["_ids_policy"] = policy_one
    _publish_exact(emitter, first)
    original_replace = emitter._replace_output
    fail_once = True

    def replace_then_return_late(sensor: str, payload: bytes) -> None:
        nonlocal fail_once
        original_replace(sensor, payload)
        if fail_once:
            fail_once = False
            raise RuntimeError("checkpoint publication returned late")

    monkeypatch.setattr(emitter, "_replace_output", replace_then_return_late)
    with pytest.raises(RuntimeError, match="returned late"):
        emitter.close()
    connection = emitter._spool_connection
    assert connection is not None
    assert connection.execute("SELECT COUNT(*) FROM filter_checkpoints").fetchone() == (1,)

    changed = _snort_event("changed policy", second=1)
    changed["_ids_policy"] = policy_two
    changed_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="policy changed"):
        changed_batch.prepare(lambda: emitter.emit_event(changed))
    changed_batch.cancel()
    assert emitter._exact_capacity_reservations == {}
    assert emitter._exact_prepared_policy_limits == {}
    assert emitter._exact_provisional_output_states == {}
    monkeypatch.setattr(emitter, "_replace_output", original_replace)
    emitter.close()

    pending = SnortEmitter(load_format("snort_alert"), tmp_path / "pending.log")
    first_pending = _snort_event("first pending")
    first_pending["_ids_policy"] = policy_one
    second_pending = _snort_event("second pending", second=1)
    second_pending["_ids_policy"] = policy_two
    pending_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="one exact publication"):
        pending_batch.prepare(
            lambda: (
                pending.emit_event(first_pending),
                pending.emit_event(second_pending),
            )
        )
    pending_batch.cancel()
    assert pending._exact_capacity_reservations == {}
    assert pending._exact_prepared_policy_limits == {}
    assert pending._exact_provisional_output_states == {}
    assert pending.journal_census().retained_rows == 0
    pending.close()


def test_snort_dynamic_routes_are_rollback_neutral_and_batch_cumulative(
    tmp_path: Path,
) -> None:
    """No-op/rejected routes vanish, while every prepared route joins one baseline census."""

    root = tmp_path / "sensors"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        root,
        journal_row_capacity=64,
        journal_byte_capacity=100 * 1024,
    )
    for index in range(100):
        emitter.emit_raw(
            {
                "timestamp": T0,
                "_sensor_hostnames": [f"noop-{index}"],
            }
        )
    assert emitter._known_output_sensors == set()
    assert emitter._writers == {}
    assert emitter._spool_connection is None
    no_op_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    no_op_batch.prepare(
        lambda: emitter.emit_raw(
            {
                "timestamp": T0,
                "_sensor_hostnames": ["exact-noop"],
            }
        )
    )
    assert emitter._exact_provisional_output_states == {}
    assert emitter._known_output_sensors == set()
    no_op_batch.cancel()

    for sensor in ("sensor-a", "sensor-b"):
        output = root / sensor / "snort_alert.log"
        output.parent.mkdir(parents=True)
        output.write_bytes((b"x" * ((60 * 1024) - 1)) + b"\n")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event_a = _snort_event("route a", candidate=False) | {"_sensor_hostnames": ["sensor-a"]}
    event_b = _snort_event("route b", second=1, candidate=False) | {
        "_sensor_hostnames": ["sensor-b"]
    }
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        batch.prepare(lambda: (emitter.emit_raw(event_a), emitter.emit_raw(event_b)))
    batch.cancel()
    assert emitter._known_output_sensors == set()
    assert emitter._exact_capacity_reservations == {}
    assert emitter._exact_provisional_output_states == {}
    assert emitter._exact_prepared_policy_limits == {}
    assert emitter.journal_census().retained_rows == 0
    emitter.close()


def test_snort_exact_batch_reuses_capacity_census_and_policy_claim_map(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multi-sensor preparation stays linear and clears participant-local accounting."""

    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "sensors")
    original_headroom = emitter._buffer_plan_headroom
    headroom_calls = 0

    def count_headroom(**kwargs: object) -> tuple[int, int]:
        nonlocal headroom_calls
        headroom_calls += 1
        return original_headroom(**kwargs)

    original_reserve = emitter._reserve_exact_publication_row
    policy_map_ids: list[int] = []

    def record_policy_map(
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        original_reserve(key, digest, retained_bytes)
        policy_map_ids.append(id(emitter._exact_prepared_policy_limits[key[:2]]))

    monkeypatch.setattr(emitter, "_buffer_plan_headroom", count_headroom)
    monkeypatch.setattr(emitter, "_reserve_exact_publication_row", record_policy_map)
    policy = {
        "detection_filter": None,
        "event_filter": {
            "type": "limit",
            "track": "by_src",
            "count": 1,
            "seconds": 60,
        },
    }
    events = [
        _snort_event(f"linear route {index}", second=index)
        | {
            "_ids_policy": policy,
            "_sensor_hostnames": [f"sensor-{index}"],
        }
        for index in range(16)
    ]
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: tuple(emitter.emit_event(event) for event in events))

    assert headroom_calls == 1
    assert len(policy_map_ids) == len(events)
    assert len(set(policy_map_ids)) == 1
    assert len(emitter._exact_prepared_policy_limits[batch._participant_key]) == len(events)
    assert len(emitter._exact_buffer_plan_headroom) == 1

    batch.cancel()
    assert emitter._exact_prepared_policy_limits == {}
    assert emitter._exact_buffer_plan_headroom == {}
    assert emitter._exact_provisional_output_states == {}
    emitter.close()


def test_snort_global_multisensor_baseline_is_rechecked_before_plan_sealing(
    tmp_path: Path,
) -> None:
    """Aggregate external output growth cannot partially seal or publish an epoch."""

    root = tmp_path / "sensors"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        root,
        journal_row_capacity=64,
        journal_byte_capacity=100 * 1024,
    )
    sensor_a = root / "sensor-a" / "snort_alert.log"
    emitter.emit_raw(
        _snort_event("establish inactive route", candidate=False)
        | {"_sensor_hostnames": ["sensor-a"]}
    )
    emitter.flush()
    sensor_a_before = sensor_a.read_bytes()
    _publish_exact(
        emitter,
        _snort_event("aggregate baseline") | {"_sensor_hostnames": ["sensor-b"]},
    )
    sensor_b = root / "sensor-b" / "snort_alert.log"
    sensor_b.parent.mkdir(parents=True, exist_ok=True)
    sensor_a_growth = (b"x" * ((60 * 1024) - 1)) + b"\n"
    sensor_b_growth = (b"x" * ((60 * 1024) - 1)) + b"\n"
    sensor_a.write_bytes(sensor_a_before + sensor_a_growth)
    sensor_b.write_bytes(sensor_b_growth)

    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        emitter.close()
    connection = emitter._spool_connection
    assert connection is not None
    assert connection.execute("SELECT COUNT(*) FROM export_plans").fetchone() == (0,)
    assert sensor_a.read_bytes() == sensor_a_before + sensor_a_growth
    assert sensor_b.read_bytes() == sensor_b_growth
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(_snort_event("late aggregate", second=1, candidate=False))

    sensor_a.write_bytes(sensor_a_before)
    sensor_b.write_bytes(b"")
    emitter.close()
    assert sensor_a.read_bytes() == sensor_a_before
    assert sensor_b.read_text(encoding="utf-8").count("aggregate baseline") == 1
    assert emitter.journal_census().retained_rows == 0


def test_snort_publication_transition_invariant_table(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every prepare/commit/export/release/cancel/close transition has one owner."""

    root = tmp_path / "sensors"
    output = root / "dynamic" / "snort_alert.log"
    emitter = SnortEmitter(load_format("snort_alert"), root)
    policy = {
        "detection_filter": None,
        "event_filter": {
            "type": "limit",
            "track": "by_src",
            "count": 1,
            "seconds": 60,
        },
    }
    event = _snort_event("invariant row") | {
        "_ids_policy": policy,
        "_sensor_hostnames": ["dynamic"],
    }

    def snapshot(stage: str) -> tuple[object, ...]:
        census = emitter.journal_census()
        connection = emitter._spool_connection
        if connection is None:
            durable = (0, 0, 0, 0)
        else:
            durable = (
                int(connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]),
                int(
                    connection.execute(
                        "SELECT COALESCE(SUM(terminal_headroom_bytes), 0) FROM candidates"
                    ).fetchone()[0]
                ),
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM candidates WHERE event_key IS NOT NULL"
                    ).fetchone()[0]
                ),
                int(connection.execute("SELECT COUNT(*) FROM filter_checkpoints").fetchone()[0]),
            )
            assert durable[1] == census.terminal_headroom_bytes
        provisional = sum(
            len(states) for states in emitter._exact_provisional_output_states.values()
        )
        prepared_claims = sum(
            len(claims) for claims in emitter._exact_prepared_policy_limits.values()
        )
        return (
            stage,
            census.pending_rows,
            census.exported_rows,
            census.admission_receipts,
            census.export_receipts,
            census.terminal_headroom_bytes,
            durable,
            output.stat().st_size if output.exists() else 0,
            tuple(sorted(emitter._known_output_sensors)),
            provisional,
            prepared_claims,
            census.reserved_rows,
        )

    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(event))
    prepared = snapshot("prepare")
    batch.commit()
    committed = snapshot("commit")

    original_compact = emitter._compact_terminal_journal_unlocked
    fail_once = True

    def fail_cleanup_once() -> bool:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("terminal cleanup returned early")
        return original_compact()

    monkeypatch.setattr(emitter, "_compact_terminal_journal_unlocked", fail_cleanup_once)
    with pytest.raises(RuntimeError, match="terminal cleanup returned early"):
        emitter.close()
    exported = snapshot("export")
    batch.release_no_fail()
    released = snapshot("release")
    emitter.close()
    terminal = snapshot("close")

    assert prepared[1:7] == (0, 0, 0, 0, 0, (0, 0, 0, 0))
    assert prepared[7:] == (0, (), 1, 1, 8)
    assert committed[1:5] == (1, 0, 1, 0)
    assert committed[5] > 0
    assert committed[6][0] == committed[6][2] == 1
    assert committed[6][1] == committed[5]
    assert committed[7:] == (0, ("dynamic",), 0, 0, 0)
    assert emitter._exact_buffer_plan_headroom == {}
    assert exported[1:5] == (0, 1, 1, 1)
    assert exported[5] == exported[6][1] == 0
    assert exported[6][0] == exported[6][2] == exported[6][3] == 1
    assert exported[7] > 0
    assert released[1:5] == (0, 0, 0, 0)
    assert released[6][0] == 0
    assert released[6][3] == 1
    assert released[7] == exported[7]
    assert terminal[1:7] == (0, 0, 0, 0, 0, (0, 0, 0, 0))
    assert terminal[7] == exported[7]
    assert not emitter._terminal_cleanup_pending

    cancelled = SnortEmitter(load_format("snort_alert"), tmp_path / "cancelled")
    cancel_event = event | {"_sensor_hostnames": ["cancelled"]}
    cancel_batch = ExactPublicationAuthority(capacity=1).issue_batch()
    cancel_batch.prepare(lambda: cancelled.emit_event(cancel_event))
    assert cancelled.journal_census().reserved_rows == 8
    assert cancelled._exact_provisional_output_states
    assert cancelled._exact_prepared_policy_limits
    cancel_batch.cancel()
    assert cancelled.journal_census().reserved_rows == 0
    assert cancelled._exact_provisional_output_states == {}
    assert cancelled._exact_prepared_policy_limits == {}
    assert cancelled._known_output_sensors == set()
    assert cancelled._spool_connection is None
    cancelled.close()


def test_snort_rejects_later_ordinary_buffer_that_would_strand_exact_export(
    tmp_path: Path,
) -> None:
    """Ordinary suffix admission preserves byte headroom for a committed exact row."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        journal_row_capacity=64,
        journal_byte_capacity=64 * 1024,
        threaded=True,
    )
    _publish_exact(emitter, _snort_event("protected exact"))
    oversized = _snort_event("x" * (64 * 1024), second=1, candidate=False)
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        emitter.emit_raw(oversized)
    assert emitter._thread is not None and emitter._thread.is_alive()
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("protected exact") == 1
    assert "x" * 100 not in rendered


def test_snort_admitted_barrier_finishes_before_close_and_late_barrier_rejects(
    tmp_path: Path,
) -> None:
    """Close waits an admitted boundary while boundaries after its claim fail promptly."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        threaded=True,
    )
    batch = ExactPublicationAuthority(capacity=2).issue_batch()
    first_staged = Event()
    continue_batch = Event()
    prepared = Event()
    barrier_done = Event()
    closed = Event()
    failures: list[BaseException] = []

    def render_two() -> None:
        emitter.emit_event(_snort_event("admitted barrier one"))
        first_staged.set()
        assert continue_batch.wait(timeout=2)
        emitter.emit_event(_snort_event("admitted barrier two", second=1))

    producer = Thread(
        target=lambda: (
            _capture_failure(failures, lambda: batch.prepare(render_two)),
            prepared.set(),
        ),
        daemon=True,
    )
    producer.start()
    assert first_staged.wait(timeout=2)
    barrier = Thread(
        target=lambda: (_capture_failure(failures, emitter.barrier_flush), barrier_done.set()),
        daemon=True,
    )
    barrier.start()
    for _ in range(1_000):
        if emitter._queue_admissions == 1:
            break
        Event().wait(0.001)
    assert emitter._queue_admissions == 1

    closer = Thread(
        target=lambda: (_capture_failure(failures, emitter.close), closed.set()),
        daemon=True,
    )
    closer.start()
    assert _wait_for_state(emitter, "closing")
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.barrier_flush()

    continue_batch.set()
    assert prepared.wait(timeout=2)
    batch.commit()
    batch.release_no_fail()
    assert barrier_done.wait(timeout=2)
    assert closed.wait(timeout=2)
    producer.join(timeout=2)
    barrier.join(timeout=2)
    closer.join(timeout=2)
    assert failures == []


def test_snort_terminal_cleanup_retries_without_reopening_stopped_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-writer cleanup failure remains retryable from the terminal state."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        threaded=True,
    )
    _publish_exact(emitter, _snort_event("cleanup retry"))
    original = emitter._compact_terminal_journal_unlocked
    fail_once = True

    def fail_before_compaction() -> bool:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("terminal cleanup interrupted")
        return original()

    monkeypatch.setattr(emitter, "_compact_terminal_journal_unlocked", fail_before_compaction)
    with pytest.raises(RuntimeError, match="cleanup interrupted"):
        emitter.close()
    assert emitter._close_state == "closed"
    assert emitter._thread is not None and not emitter._thread.is_alive()
    assert all(writer._close_state == "closed" for writer in emitter._writers.values())

    emitter.close()
    terminal = emitter.journal_census()
    assert terminal.retained_rows == terminal.retained_bytes == 0


def test_snort_ordinary_only_close_has_terminal_zero_census(tmp_path: Path) -> None:
    """In-memory ordinary summary charges are released after physical close."""

    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "snort.log")
    emitter.emit_raw(_snort_event("ordinary terminal", candidate=False))
    assert emitter._journal_path is not None
    assert emitter.journal_census().pending_rows == 1
    emitter.close()
    terminal = emitter.journal_census()
    assert terminal.retained_rows == terminal.retained_bytes == 0


def test_snort_custom_template_is_rendered_once_and_measured_before_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unbounded custom expansion is measured before any durable candidate state."""

    custom = load_format("snort_alert").model_copy(deep=True)
    custom.output.template = "{{ message }}" * 100
    message = "z" * 1_000
    rejected = SnortEmitter(
        custom,
        tmp_path / "rejected.log",
        journal_row_capacity=64,
        journal_byte_capacity=64 * 1024,
    )
    with pytest.raises(ExactPublicationError, match="byte capacity is exhausted"):
        rejected.emit_event(_snort_event(message))
    assert rejected._spool_connection is None
    assert rejected.journal_census().retained_rows == 0
    rejected.close()

    output = tmp_path / "admitted.log"
    admitted = SnortEmitter(
        custom,
        output,
        journal_row_capacity=64,
        journal_byte_capacity=2 * 1024 * 1024,
    )
    original_render = admitted._render_alert
    render_count = 0

    def count_render(event_data: dict[str, object]) -> str | None:
        nonlocal render_count
        render_count += 1
        return original_render(event_data)

    monkeypatch.setattr(admitted, "_render_alert", count_render)
    admitted.emit_event(_snort_event(message))
    assert render_count == 1

    def reject_rerender(_event_data: dict[str, object]) -> str:
        raise AssertionError("custom candidate rendered twice")

    monkeypatch.setattr(admitted, "_render_alert", reject_rerender)
    admitted.close()
    assert output.read_text(encoding="utf-8") == (message * 100) + "\n"


def test_snort_raw_threshold_uses_transactional_sensor_scalar(tmp_path: Path) -> None:
    """Raw threshold admission stays O(1) and its scalar follows export cleanup."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "snort.log",
        buffer_size=2,
    )
    emitter.emit_raw(_snort_event("raw scalar one", candidate=False))
    connection = emitter._spool_connection
    assert connection is not None
    assert connection.execute(
        "SELECT pending_rows FROM raw_sensor_state WHERE sensor = ?",
        ("__direct__",),
    ).fetchone() == (1,)
    assert connection.execute(
        """SELECT COUNT(*) FROM candidates
        WHERE sensor = ? AND row_kind = ? AND exported = ?""",
        ("__direct__", "raw", 0),
    ).fetchone() == (1,)

    emitter.emit_raw(_snort_event("raw scalar two", second=1, candidate=False))
    assert (
        connection.execute(
            "SELECT pending_rows FROM raw_sensor_state WHERE sensor = ?",
            ("__direct__",),
        ).fetchone()
        is None
    )
    assert connection.execute(
        """SELECT COUNT(*) FROM candidates
        WHERE sensor = ? AND row_kind = ? AND exported = ?""",
        ("__direct__", "raw", 0),
    ).fetchone() == (0,)
    source = inspect.getsource(SnortEmitter._render_event)
    assert "COUNT(" not in source
    emitter.close()


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_snort_threaded_threshold_failure_is_adapter_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    """A worker threshold failure stays behind the adapter recovery fence."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(
        load_format("snort_alert"),
        output,
        buffer_size=1,
        threaded=True,
    )
    original = emitter._replace_output
    failed = Event()
    fail_once = True

    def fail_worker_once(sensor: str, payload: bytes) -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            failed.set()
            raise failure_type("worker threshold publication failed")
        original(sensor, payload)

    monkeypatch.setattr(emitter, "_replace_output", fail_worker_once)
    emitter.emit_raw(_snort_event("worker recovery", candidate=False))
    assert failed.wait(timeout=2)
    for _ in range(1_000):
        if emitter._export_recovery_pending:
            break
        Event().wait(0.001)
    assert emitter._thread is not None and emitter._thread.is_alive()
    assert emitter._thread_error is None
    assert emitter._export_recovery_pending
    with pytest.raises(RuntimeError, match="terminal export recovery"):
        emitter.emit_raw(_snort_event("late worker row", second=1, candidate=False))

    monkeypatch.setattr(emitter, "_replace_output", original)
    emitter.close()
    assert output.read_text(encoding="utf-8").count("worker recovery") == 1
    assert emitter.journal_census().retained_rows == 0


def test_snort_custom_template_freezes_each_projected_sensor_outside_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom rows render once per projected sensor before admission locks."""

    custom = load_format("snort_alert").model_copy(deep=True)
    custom.output.template = "{{ src_ip }}|{{ message }}"
    emitter = SnortEmitter(
        custom,
        tmp_path / "sensors",
        sensor_hostnames=["sensor-a", "sensor-b"],
    )
    render_count = 0
    original_render = emitter._render_alert

    def count_render(event_data: dict[str, object]) -> str | None:
        nonlocal render_count
        assert not emitter._producer_lock._is_owned()
        assert not emitter._spool_lock._is_owned()
        render_count += 1
        return original_render(event_data)

    def accept_observation(*_args: object, **_kwargs: object) -> None:
        return None

    def project_observation(
        render_data: dict[str, object],
        observation: object,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        render_data["src_ip"] = str(observation)

    monkeypatch.setattr(emitter, "_render_alert", count_render)
    monkeypatch.setattr(emitter, "_require_frozen_source_keys", accept_observation)
    monkeypatch.setattr(emitter, "_apply_sensor_observation", project_observation)
    event = _snort_event("projected custom") | {
        "_sensor_hostnames": ["sensor-a", "sensor-b"],
        "_network_observations_planned": True,
        "_network_sensor_observations": {
            "sensor-a": "192.0.2.10",
            "sensor-b": "198.51.100.20",
        },
    }
    emitter.emit_event(event)
    assert render_count == 2
    emitter.close()
    assert (tmp_path / "sensors" / "sensor-a" / "snort_alert.log").read_text(
        encoding="utf-8"
    ) == "192.0.2.10|projected custom\n"
    assert (tmp_path / "sensors" / "sensor-b" / "snort_alert.log").read_text(
        encoding="utf-8"
    ) == "198.51.100.20|projected custom\n"


def test_snort_custom_template_planned_empty_route_is_noop(tmp_path: Path) -> None:
    """A planned-empty custom row renders nothing and allocates no journal route."""

    custom = load_format("snort_alert").model_copy(deep=True)
    custom.output.template = "{{ message }}" * 100
    emitter = SnortEmitter(custom, tmp_path / "sensors", sensor_hostnames=["sensor-a"])
    emitter.emit_event(
        _snort_event("planned empty")
        | {
            "_sensor_hostnames": [],
            "_network_observations_planned": True,
        }
    )
    assert emitter._spool_connection is None
    assert emitter._output_route_states == {}
    assert emitter.journal_census().retained_rows == 0
    emitter.close()
    assert not (tmp_path / "sensors").exists()


def test_snort_custom_template_callback_can_reenter_outside_locks(tmp_path: Path) -> None:
    """Template stringification may reenter without deadlock or row loss."""

    custom = load_format("snort_alert").model_copy(deep=True)
    custom.output.template = "{{ message }}"
    output = tmp_path / "snort.log"
    emitter = SnortEmitter(custom, output)
    reentered = False

    class ReentrantMessage(str):
        def __str__(self) -> str:
            nonlocal reentered
            assert not emitter._producer_lock._is_owned()
            assert not emitter._spool_lock._is_owned()
            if not reentered:
                reentered = True
                emitter.emit_raw(_snort_event("reentrant raw", candidate=False))
            return super().__str__()

    emitter.emit_event(_snort_event(ReentrantMessage("outer custom")))
    emitter.close()
    rendered = output.read_text(encoding="utf-8")
    assert reentered
    assert rendered.count("reentrant raw") == 1
    assert rendered.count("outer custom") == 1


def test_snort_private_spool_is_disjoint_owner_only_and_temp_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SQLite main file and rollback sidecar stay in one protected root."""

    spool_root = tmp_path / "private-spool"
    public_root = tmp_path / "public"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    emitter = SnortEmitter(load_format("snort_alert"), public_root / "snort.log")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_snort_event("private spool")))
    journal_path = emitter._journal_path
    connection = emitter._spool_connection
    assert journal_path is not None and connection is not None
    assert spool_root in journal_path.parents
    assert public_root not in journal_path.parents
    assert stat.S_IMODE(journal_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    assert connection.execute("PRAGMA temp_store").fetchone() == (2,)

    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "UPDATE spool_state SET total_events = total_events + ? WHERE singleton = ?",
        (1, 1),
    )
    rollback = Path(f"{journal_path}-journal")
    assert rollback.exists()
    assert rollback.parent == journal_path.parent
    assert stat.S_IMODE(rollback.stat().st_mode) == 0o600
    connection.rollback()

    batch.release_no_fail()
    emitter.close()
    assert list(spool_root.iterdir()) == []


def test_snort_exact_spool_overlap_fails_closed_and_same_batch_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A private spool below public output cannot receive exact journal bytes."""

    public_root = tmp_path / "public"
    output = public_root / "snort.log"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(public_root / "private"))
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="outside its public output root"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("overlap retry")))
    assert emitter._spool_connection is None
    assert emitter.journal_census().retained_rows == 0

    safe_spool = tmp_path / "safe-private"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(safe_spool))
    batch.publish(lambda: emitter.emit_event(_snort_event("overlap retry")))
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("overlap retry") == 1
    assert list(safe_spool.iterdir()) == []


def test_snort_unsafe_exact_spool_fails_at_prepare_and_same_batch_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact admission probes protected-spool trust before retaining participant state."""

    unsafe_spool = tmp_path / "unsafe-private"
    unsafe_spool.mkdir(mode=0o700)
    unsafe_spool.chmod(0o777)
    output = tmp_path / "public" / "snort.log"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(unsafe_spool))
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()

    with pytest.raises(ExactPublicationError, match="externally writable"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("unsafe spool retry")))
    assert emitter._spool_connection is None
    assert emitter._journal_owner is None
    assert emitter.journal_census().retained_rows == 0

    unsafe_spool.chmod(0o700)
    batch.publish(lambda: emitter.emit_event(_snort_event("unsafe spool retry")))
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("unsafe spool retry") == 1
    assert list(unsafe_spool.iterdir()) == []


def test_snort_exact_capability_probe_failure_is_prepare_neutral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient capability-gate failure retains no exact participant state."""

    output = tmp_path / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    original = snort_module._require_exact_journal_capabilities
    failed_once = False

    def fail_once(base_dir: Path) -> None:
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            raise ExactPublicationError("capability probe failed")
        original(base_dir)

    monkeypatch.setattr(snort_module, "_require_exact_journal_capabilities", fail_once)
    with pytest.raises(ExactPublicationError, match="capability probe failed"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("capability retry")))
    assert emitter._spool_connection is None
    assert emitter._journal_owner is None
    assert emitter.journal_census().retained_rows == 0

    batch.publish(lambda: emitter.emit_event(_snort_event("capability retry")))
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("capability retry") == 1


def test_snort_private_sqlite_ignores_output_parent_swap_and_decoy_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLite opens only below the protected root while public ancestry is swapped."""

    spool_root = tmp_path / "private-spool"
    public = tmp_path / "public"
    held = tmp_path / "held-public"
    output = public / "snort.log"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event("private despite swap")))
    original_connect = snort_module._connect_existing_journal
    decoy = public / "decoy.sqlite3"
    decoy_before = b""
    swapped = False

    def swap_output_then_connect(journal_path: Path) -> sqlite3.Connection:
        nonlocal decoy_before, swapped
        if not swapped:
            swapped = True
            public.rename(held)
            public.mkdir()
            decoy_connection = sqlite3.connect(decoy)
            decoy_connection.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
            decoy_connection.execute(
                "INSERT INTO sentinel (value) VALUES (?)",
                ("unchanged",),
            )
            decoy_connection.commit()
            decoy_connection.close()
            decoy_before = decoy.read_bytes()
        assert spool_root in journal_path.parents
        assert public not in journal_path.parents
        return original_connect(journal_path)

    monkeypatch.setattr(snort_module, "_connect_existing_journal", swap_output_then_connect)
    batch.commit()
    assert decoy.read_bytes() == decoy_before
    assert list(public.glob("*.sqlite3-*")) == []

    decoy.unlink()
    public.rmdir()
    held.rename(public)
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("private despite swap") == 1
    assert list(spool_root.iterdir()) == []


def test_snort_initialization_cleanup_lost_return_keeps_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema failure plus cleanup failure cannot orphan a private directory."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    emitter = SnortEmitter(load_format("snort_alert"), tmp_path / "public" / "snort.log")
    original_schema = emitter._initialize_spool_schema
    original_unlink = emitter._unlink_cleanup_journal
    schema_fail_once = True
    unlink_fail_once = True

    def fail_schema_once(connection: sqlite3.Connection) -> None:
        nonlocal schema_fail_once
        original_schema(connection)
        if schema_fail_once:
            schema_fail_once = False
            raise RuntimeError("schema initialization returned late")

    def fail_unlink_once(*args: object) -> None:
        nonlocal unlink_fail_once
        original_unlink(*args)
        if unlink_fail_once:
            unlink_fail_once = False
            raise OSError("initialization unlink returned late")

    monkeypatch.setattr(emitter, "_initialize_spool_schema", fail_schema_once)
    monkeypatch.setattr(emitter, "_unlink_cleanup_journal", fail_unlink_once)
    with pytest.raises(RuntimeError, match="schema initialization returned late") as captured:
        emitter.emit_raw(_snort_event("failed initialization", candidate=False))
    assert any("cleanup also failed" in note for note in captured.value.__notes__)
    assert emitter._journal_owner is not None
    assert emitter._journal_cleanup_pending
    assert len(list(spool_root.iterdir())) == 1

    monkeypatch.setattr(emitter, "_initialize_spool_schema", original_schema)
    monkeypatch.setattr(emitter, "_unlink_cleanup_journal", original_unlink)
    emitter.emit_raw(_snort_event("recovered initialization", candidate=False))
    emitter.close()
    assert emitter._journal_owner is None
    assert not emitter._journal_cleanup_pending
    assert list(spool_root.iterdir()) == []


@pytest.mark.parametrize(
    "fault",
    ["connection_close", "unlink", "leaf_fsync", "rmdir", "parent_fsync"],
)
def test_snort_close_before_release_retains_cleanup_owner_across_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    """The final release cursor owns every fallible private cleanup barrier."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    output = tmp_path / "public" / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_snort_event(f"cleanup {fault}")))
    emitter.close()
    assert emitter._terminal_cleanup_pending
    owner = emitter._journal_owner
    assert owner is not None
    fail_once = True

    if fault == "connection_close":
        original = emitter._close_spool_connection

        def fail(*args: object) -> None:
            nonlocal fail_once
            original(*args)
            if fail_once:
                fail_once = False
                raise OSError("connection close returned late")

        monkeypatch.setattr(emitter, "_close_spool_connection", fail)
    elif fault == "unlink":
        original = emitter._unlink_cleanup_journal

        def fail(*args: object) -> None:
            nonlocal fail_once
            original(*args)
            if fail_once:
                fail_once = False
                raise OSError("journal unlink returned late")

        monkeypatch.setattr(emitter, "_unlink_cleanup_journal", fail)
    elif fault == "leaf_fsync":
        original = emitter._fsync_cleanup_directory

        def fail(*args: object) -> None:
            nonlocal fail_once
            original(*args)
            if fail_once:
                fail_once = False
                raise OSError("leaf fsync returned late")

        monkeypatch.setattr(emitter, "_fsync_cleanup_directory", fail)
    elif fault == "rmdir":
        original = owner._remove_directory

        def fail(*args: object) -> None:
            nonlocal fail_once
            original(*args)
            if fail_once:
                fail_once = False
                raise OSError("rmdir returned late")

        monkeypatch.setattr(owner, "_remove_directory", fail)
    else:
        original = owner._fsync_parent

        def fail(*args: object) -> None:
            nonlocal fail_once
            original(*args)
            if fail_once:
                fail_once = False
                raise OSError("parent fsync returned late")

        monkeypatch.setattr(owner, "_fsync_parent", fail)

    with pytest.raises(OSError, match="returned late"):
        batch.release_no_fail()
    assert emitter._terminal_cleanup_pending
    assert len(emitter._exact_candidate_receipts) == 1

    batch.release_no_fail()
    assert batch.released
    assert emitter._journal_owner is None
    assert not emitter._terminal_cleanup_pending
    assert emitter._journal_directory_descriptor is None
    assert list(spool_root.iterdir()) == []
    emitter.close()
    assert output.read_text(encoding="utf-8").count(f"cleanup {fault}") == 1


def test_snort_private_leaf_initialization_retries_the_same_owned_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost private-leaf fsync retains one owner and resumes the same leaf."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    output = tmp_path / "public" / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event("same private leaf")))
    original = snort_module._PrivateJournalDirectory._fsync_parent
    fail_once = True

    def fsync_then_raise(owner: object, parent: int) -> None:
        nonlocal fail_once
        original(owner, parent)
        if fail_once:
            fail_once = False
            raise OSError("private leaf fsync returned late")

    monkeypatch.setattr(
        snort_module._PrivateJournalDirectory,
        "_fsync_parent",
        fsync_then_raise,
    )
    with pytest.raises(OSError, match="private leaf fsync returned late"):
        batch.commit()
    owner = emitter._journal_owner
    assert owner is not None and owner.path is not None
    retained_path = owner.path
    assert retained_path.exists()
    assert emitter._spool_connection is None
    assert emitter.journal_census().retained_rows == 0

    monkeypatch.setattr(
        snort_module._PrivateJournalDirectory,
        "_fsync_parent",
        original,
    )
    batch.commit()
    assert emitter._journal_owner is owner
    assert owner.path == retained_path
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count("same private leaf") == 1
    assert list(spool_root.iterdir()) == []


@pytest.mark.parametrize("limit", ["name", "path"])
def test_snort_private_journal_limits_reject_before_sql_and_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    """Derived main and sidecar names fit the pinned filesystem before SQLite."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    output = tmp_path / "public" / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_snort_event(f"{limit} limit")))
    original = snort_module._directory_path_limits
    longest = len(os.fsencode(f"journal-{'0' * 32}.sqlite3-journal"))

    def reject_limit(descriptor: int) -> tuple[int, int]:
        name_max, path_max = original(descriptor)
        if limit == "name":
            return longest - 1, path_max
        return name_max, 1

    monkeypatch.setattr(snort_module, "_directory_path_limits", reject_limit)
    with pytest.raises(ExactPublicationError, match=f"{limit.upper()}_MAX"):
        batch.commit()
    owner = emitter._journal_owner
    assert owner is not None and owner.path is not None
    assert emitter._spool_connection is None
    assert list(owner.path.iterdir()) == []
    assert emitter.journal_census().retained_rows == 0

    monkeypatch.setattr(snort_module, "_directory_path_limits", original)
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").count(f"{limit} limit") == 1
    assert list(spool_root.iterdir()) == []


def test_snort_export_temporary_name_is_preflighted_before_exact_admission(
    tmp_path: Path,
) -> None:
    """A valid long destination cannot strand a plan whose temporary name is too long."""

    output = tmp_path / f"{'x' * 226}.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="private export.*NAME_MAX"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("long export name")))
    batch.cancel()
    assert emitter._spool_connection is None
    assert emitter.journal_census().retained_rows == 0
    assert not output.exists()
    emitter.close()


@pytest.mark.parametrize("lost_return", [False, True])
def test_snort_closed_close_retries_connection_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """A failed SQLite close retains or reconciles ownership for closed-close retry."""

    spool_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool_root))
    output = tmp_path / "public" / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    emitter.emit_raw(_snort_event("connection cleanup", candidate=False))
    original = emitter._close_spool_connection
    fail_once = True

    def fail(connection: sqlite3.Connection) -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            if lost_return:
                original(connection)
            raise OSError("connection cleanup failed")
        original(connection)

    monkeypatch.setattr(emitter, "_close_spool_connection", fail)
    with pytest.raises(OSError, match="connection cleanup failed"):
        emitter.close()
    assert emitter._close_state == "closed"
    assert emitter._terminal_cleanup_pending
    assert (emitter._spool_connection is None) is lost_return

    emitter.close()
    assert emitter._journal_owner is None
    assert not emitter._terminal_cleanup_pending
    assert list(spool_root.iterdir()) == []
    assert output.read_text(encoding="utf-8").count("connection cleanup") == 1


def test_snort_symlinked_sensor_output_is_rejected_before_exact_admission(
    tmp_path: Path,
) -> None:
    """No sensor may redirect final publication through symlink ancestry."""

    root = tmp_path / "sensors"
    victim_dir = tmp_path / "victim"
    victim_dir.mkdir()
    victim = victim_dir / "snort_alert.log"
    victim.write_bytes(b"victim\n")
    root.mkdir()
    (root / "sensor-a").symlink_to(victim_dir, target_is_directory=True)
    emitter = SnortEmitter(
        load_format("snort_alert"),
        root,
        sensor_hostnames=["sensor-a"],
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("symlink route") | {"_sensor_hostnames": ["sensor-a"]}
    with pytest.raises(ExactPublicationError, match="Unsafe Snort directory ancestry"):
        batch.prepare(lambda: emitter.emit_event(event))
    batch.cancel()
    assert emitter.journal_census().retained_rows == 0
    assert emitter._spool_connection is None
    assert victim.read_bytes() == b"victim\n"
    emitter.close()


def test_snort_sensor_route_must_already_be_one_canonical_component(tmp_path: Path) -> None:
    """Sanitization cannot silently merge two caller-supplied route identities."""

    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "sensors",
        sensor_hostnames=["sensor/a"],
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("unsafe route") | {"_sensor_hostnames": ["sensor/a"]}
    with pytest.raises(ExactPublicationError, match="canonical component"):
        batch.prepare(lambda: emitter.emit_event(event))
    batch.cancel()
    assert emitter._spool_connection is None
    emitter.close()


def test_snort_hardlinked_sensor_outputs_reject_one_physical_owner(tmp_path: Path) -> None:
    """Two lexical sensor routes cannot seal plans for one physical file."""

    root = tmp_path / "sensors"
    output_a = root / "sensor-a" / "snort_alert.log"
    output_b = root / "sensor-b" / "snort_alert.log"
    output_a.parent.mkdir(parents=True)
    output_b.parent.mkdir(parents=True)
    output_a.write_bytes(b"baseline\n")
    os.link(output_a, output_b)
    emitter = SnortEmitter(
        load_format("snort_alert"),
        root,
        sensor_hostnames=["sensor-a", "sensor-b"],
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    event = _snort_event("hardlink route") | {"_sensor_hostnames": ["sensor-a"]}
    with pytest.raises(ExactPublicationError, match="one physical output"):
        batch.prepare(lambda: emitter.emit_event(event))
    batch.cancel()
    assert output_a.read_bytes() == output_b.read_bytes() == b"baseline\n"
    assert emitter._spool_connection is None
    emitter.close()


def test_snort_unterminated_baseline_rejects_before_plan_or_journal(tmp_path: Path) -> None:
    """A partial baseline cannot fuse with the first admitted fast-alert line."""

    output = tmp_path / "snort.log"
    output.write_bytes(b"partial")
    emitter = SnortEmitter(load_format("snort_alert"), output)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="not newline terminated"):
        batch.prepare(lambda: emitter.emit_event(_snort_event("must stay separate")))
    batch.cancel()
    assert emitter._spool_connection is None
    assert output.read_bytes() == b"partial"
    emitter.close()


def test_snort_route_baseline_census_is_linear_then_constant_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configured routes are inspected once and known-route admission is O(1)."""

    sensors = [f"sensor-{index}" for index in range(8)]
    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path / "sensors",
        buffer_size=100,
        sensor_hostnames=sensors,
    )
    original = emitter._inspect_output_route_unlocked
    inspected = 0

    def count_inspection(
        sensor: str,
        *,
        include_payload: bool = False,
    ) -> tuple[snort_module._OutputRouteState, bytes | None, str]:
        nonlocal inspected
        inspected += 1
        return original(sensor, include_payload=include_payload)

    monkeypatch.setattr(emitter, "_inspect_output_route_unlocked", count_inspection)
    for second in range(4):
        emitter.emit_raw(
            _snort_event(f"known route {second}", second=second, candidate=False)
            | {"_sensor_hostnames": ["sensor-0"]}
        )
    assert inspected == len(sensors)
    assert emitter._output_baseline_bytes == sum(
        state.size for state in emitter._output_route_states.values()
    )
    source = inspect.getsource(SnortEmitter._buffer_plan_headroom)
    assert ".stat(" not in source
    assert "_known_output_sensors" not in source
    emitter.close()


def test_snort_dirfd_export_does_not_mutate_swapped_output_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic replacement remains anchored when the lexical parent is swapped."""

    public = tmp_path / "public"
    output = public / "snort.log"
    emitter = SnortEmitter(load_format("snort_alert"), output)
    _publish_exact(emitter, _snort_event("dirfd anchored"))
    original_rename = os.rename
    held = tmp_path / "held-public"
    decoy_bytes = b"decoy\n"
    swapped = False

    def swap_then_rename(
        source: str | bytes,
        destination: str | bytes,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped and src_dir_fd is not None and dst_dir_fd is not None:
            swapped = True
            original_rename(public, held)
            public.mkdir()
            output.write_bytes(decoy_bytes)
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(snort_module.os, "rename", swap_then_rename)
    with pytest.raises(ExactPublicationError, match="output parent identity changed"):
        emitter.close()
    assert output.read_bytes() == decoy_bytes

    output.unlink()
    public.rmdir()
    original_rename(held, public)
    emitter.close()
    assert output.read_text(encoding="utf-8").count("dirfd anchored") == 1
    assert emitter.journal_census().retained_rows == 0


def test_bash_close_before_release_retains_private_receipt_until_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Physical close retains the Bash route until the core releases its receipt."""

    root = tmp_path / "root"
    spool_root = tmp_path / "trusted-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = BashHistoryEmitter(load_format("bash_history"), root)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: emitter.emit_event(_bash_event("unreleased bash exact")))
    writer = next(iter(emitter._writers.values()))
    journal_path = writer._journal_path
    private_path = writer._journal_directory.path
    assert journal_path is not None and private_path is not None

    emitter.close()

    retained = emitter.journal_census()
    assert emitter._close_state == "closed"
    assert retained.pending_operations == 0
    assert retained.admission_receipts == 1
    assert retained.export_receipts == 1
    assert writer._close_requested and not writer._terminal
    assert writer in emitter._writers.values()
    assert journal_path.exists() and private_path.exists()
    assert _bash_path(root).read_text(encoding="utf-8").count("unreleased bash exact") == 1

    batch.release_no_fail()

    assert writer._terminal
    assert emitter._writers == {}
    assert not journal_path.exists()
    assert not private_path.exists()
    assert list(spool_root.iterdir()) == []
    emitter.close()
    _assert_bash_terminal_state(emitter)


def _assert_bash_terminal_state(emitter: BashHistoryEmitter) -> None:
    assert emitter._close_state == "closed"
    assert emitter._active_exact_publication_keys == set()
    assert emitter._queue_admissions == 0
    census = emitter.journal_census()
    assert census.pending_operations == 0
    assert census.reserved_rows == 0
    assert census.retained_rows == census.retained_bytes == 0
    if emitter._event_queue is not None:
        assert emitter._event_queue.unfinished_tasks == 0
    if emitter._thread is not None:
        assert not emitter._thread.is_alive()


def _capture_failure(
    failures: list[BaseException],
    operation: Callable[[], object],
) -> None:
    try:
        operation()
    except BaseException as error:
        failures.append(error)


def _wait_for_state(emitter: object, expected: str) -> bool:
    for _ in range(1_000):
        if emitter._close_state == expected:
            return True
        Event().wait(0.001)
    return False
