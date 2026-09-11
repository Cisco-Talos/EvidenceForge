# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Fault-neutral exact publication tests for deferred transport rendering."""

from __future__ import annotations

import gc
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from weakref import ref

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import base as emitter_base
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    ExactPublicationKey,
    LogEmitter,
    stage_exact_publication_row,
)
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class _TestHostEmitter(HostMultiplexEmitter):
    """Small host multiplexer used to exercise the production worker loop."""

    _log_filename = "host.log"

    def _render_event(self, event_data: dict[str, object]) -> str:
        return str(event_data["message"])


class _TestSensorEmitter(SensorMultiplexEmitter):
    """Small sensor multiplexer used to exercise the production worker loop."""

    _log_filename = "sensor.log"
    _sort_before_flush = False

    def _render_event(self, event_data: dict[str, object]) -> str:
        return str(event_data["message"])


class _TestBaseEmitter(LogEmitter):
    """Minimal base worker used to prove exact BaseException acknowledgement."""

    def emit_event(self, event_data: dict[str, object]) -> None:
        if self.threaded:
            self._emit_threaded(event_data)
            return
        rendered = self._render_event(event_data)
        self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, object]) -> str:
        if event_data["message"] == "interrupt":
            raise KeyboardInterrupt
        return str(event_data["message"])


def _new_batch() -> ExactPublicationBatch:
    return ExactPublicationAuthority(capacity=1).issue_batch()


def _wait_for_pending_exact_registration(emitter: LogEmitter) -> None:
    deadline = monotonic() + 2
    while monotonic() < deadline:
        with emitter._exact_publication_condition:
            if emitter._pending_exact_publication_key is not None:
                return
        sleep(0.01)
    raise AssertionError("emitter did not install its pending exact registration")


def _start_close_waiting_on_active_exact(
    emitter: LogEmitter,
) -> tuple[Thread, Event, list[BaseException]]:
    """Start close and prove it owns the close transition behind an active fence."""

    returned = Event()
    failures: list[BaseException] = []

    def close() -> None:
        try:
            emitter.close()
            returned.set()
        except BaseException as error:
            failures.append(error)

    closer = Thread(target=close, daemon=True)
    closer.start()
    deadline = monotonic() + 1
    while monotonic() < deadline:
        with emitter._exact_publication_condition:
            if emitter._close_state == "closing":
                assert emitter._active_exact_publication_keys
                return closer, returned, failures
        sleep(0.01)
    raise AssertionError("close did not wait behind the active exact owner")


def test_exact_publication_discards_failed_render_and_resumes_sink_commit() -> None:
    """A failed render publishes nothing and a fail-after sink mutation is exact-once."""

    batch = _new_batch()
    rows: list[str] = []
    receipts: dict[ExactPublicationKey, str] = {}
    render_calls = 0
    fail_render = True
    fail_after_commit = True
    fail_after_release = True

    def publish_row(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal fail_after_commit
        assert type(frozen) is str
        value = frozen
        retained = receipts.get(key)
        if retained is None:
            rows.append(value)
            receipts[key] = digest
        elif retained != digest:
            raise AssertionError("publication content changed")
        if fail_after_commit and value == "second":
            fail_after_commit = False
            raise RuntimeError("sink failed after the exact append")

    def release_row(key: ExactPublicationKey) -> None:
        nonlocal fail_after_release
        receipts.pop(key, None)
        if fail_after_release:
            fail_after_release = False
            raise RuntimeError("release failed after removing the receipt")

    def render() -> str:
        nonlocal fail_render, render_calls
        render_calls += 1
        for value in ("first", "second"):
            assert stage_exact_publication_row(
                rows,
                value,
                publish=publish_row,
                release=release_row,
            )
            if fail_render and value == "first":
                fail_render = False
                raise RuntimeError("render failed before the batch froze")
        return "published"

    with pytest.raises(RuntimeError, match="render failed"):
        batch.publish(render)
    assert rows == []

    with pytest.raises(RuntimeError, match="sink failed"):
        batch.publish(render)
    assert rows == ["first", "second"]
    assert batch.publish(render) == "published"
    assert rows == ["first", "second"]
    assert render_calls == 2

    with pytest.raises(RuntimeError, match="release failed"):
        batch.release_no_fail()
    batch.release_no_fail()
    assert batch.released
    assert receipts == {}


def test_exact_publication_uses_non_recycled_sink_keys() -> None:
    """Released batches retain distinct durable keys independent of object identity reuse."""

    authority = ExactPublicationAuthority(capacity=2)
    committed_keys: list[ExactPublicationKey] = []
    for value in ("first", "second"):
        batch = authority.issue_batch()
        batch.publish(
            lambda value=value: stage_exact_publication_row(
                committed_keys,
                value,
                publish=lambda key, _digest, _frozen: committed_keys.append(key),
                release=lambda _key: None,
            )
        )
        batch.release_no_fail()

    assert len(committed_keys) == 2
    assert committed_keys[0][:2] != committed_keys[1][:2]


def test_exact_publication_prepare_freezes_payload_before_sink_admission() -> None:
    """Preparation mutates no sink and later caller changes cannot alter the admitted row."""

    batch = _new_batch()
    caller_payload = {"values": ["original"]}
    admitted: list[str] = []
    receipts: dict[ExactPublicationKey, str] = {}

    def publish(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        retained = receipts.get(key)
        if retained is not None:
            assert retained == digest
            return
        admitted.append(frozen)
        receipts[key] = digest

    prepared_result = batch.prepare(
        lambda: (
            stage_exact_publication_row(
                admitted,
                "|".join(caller_payload["values"]),
                publish=publish,
                release=lambda key: receipts.pop(key, None),
            ),
            {"result": ["stable"]},
        )[1]
    )
    assert admitted == []
    caller_payload["values"].append("mutated")
    prepared_result["result"].append("caller-change")

    assert batch.commit() == {"result": ["stable"]}
    assert admitted == ["original"]
    batch.release_no_fail()


def test_exact_publication_rejects_non_string_rows_before_copy_or_participant() -> None:
    """The final-row boundary rejects active objects before copying or sink registration."""

    batch = _new_batch()
    copied = False
    registrations = 0

    class HostileContent:
        def __deepcopy__(self, _memo: dict[int, object]) -> HostileContent:
            nonlocal copied
            copied = True
            raise AssertionError("active exact content must never be copied")

    class Sink:
        def _register_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            nonlocal registrations
            registrations += 1

        def _complete_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            return

        def _abort_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            return

    with pytest.raises(ExactPublicationError, match="one exact str"):
        batch.prepare(
            lambda: stage_exact_publication_row(
                Sink(),
                HostileContent(),
                publish=lambda _key, _digest, _frozen: None,
                release=lambda _key: None,
            )
        )
    assert not copied
    assert registrations == 0
    assert batch.state == "issued"
    batch.cancel()


def test_exact_publication_revalidates_inert_string_preimage() -> None:
    """Owner-private corruption of an exact string row is rejected before admission."""

    batch = _new_batch()
    admitted: list[str] = []
    batch.prepare(
        lambda: stage_exact_publication_row(
            admitted,
            "before",
            publish=lambda _key, _digest, frozen: admitted.append(str(frozen)),
            release=lambda _key: None,
        )
    )
    prepared_rows = batch._prepared_rows
    assert prepared_rows is not None
    object.__setattr__(prepared_rows[0], "frozen_content", "tampered")

    with pytest.raises(ExactPublicationError, match="frozen payload changed"):
        batch.commit()
    assert admitted == []


def test_exact_publication_capacity_refuses_before_sink_mutation_and_recovers() -> None:
    """Row capacity is charged at prepare and released by precanonical cancellation."""

    authority = ExactPublicationAuthority(capacity=2, row_capacity=1, byte_capacity=4_096)
    admitted: list[str] = []
    first = authority.issue_batch()
    second = authority.issue_batch()

    def render(value: str):
        def freeze() -> bool:
            return stage_exact_publication_row(
                admitted,
                value,
                publish=lambda _key, _digest, frozen: admitted.append(str(frozen)),
                release=lambda _key: None,
            )

        return freeze

    first.prepare(render("first"))
    with pytest.raises(ExactPublicationError, match="row capacity"):
        second.prepare(render("second"))
    assert admitted == []
    assert authority.census().retained_rows == 1

    first.cancel()
    second.prepare(render("second"))
    assert second.commit() is True
    assert admitted == ["second"]
    second.release_no_fail()
    census = authority.census()
    assert census.active_batches == 0
    assert census.retained_rows == 0
    assert census.retained_bytes == 0
    assert census.high_water_rows == 1


def test_exact_publication_fail_before_retries_same_frozen_row() -> None:
    """A fail-before callback leaves its cursor retryable without rerendering."""

    batch = _new_batch()
    rows: list[str] = []
    calls = 0

    def publish(_key: ExactPublicationKey, _digest: str, frozen: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("failed before append")
        rows.append(str(frozen))

    render_calls = 0

    def render() -> None:
        nonlocal render_calls
        render_calls += 1
        stage_exact_publication_row(
            rows,
            "stable",
            publish=publish,
            release=lambda _key: None,
        )

    with pytest.raises(RuntimeError, match="before append"):
        batch.publish(render)
    batch.publish(render)
    assert rows == ["stable"]
    assert calls == 2
    assert render_calls == 1
    batch.release_no_fail()


def test_exact_publication_serializes_release_against_commit() -> None:
    """Release cannot race an active commit or duplicate its sink cleanup callback."""

    batch = _new_batch()
    commit_entered = Event()
    allow_commit = Event()
    errors: list[BaseException] = []

    def publish(_key: ExactPublicationKey, _digest: str, _frozen: object) -> None:
        commit_entered.set()
        allow_commit.wait()

    batch.prepare(
        lambda: stage_exact_publication_row(
            errors,
            "row",
            publish=publish,
            release=lambda _key: None,
        )
    )

    def commit() -> None:
        try:
            batch.commit()
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=commit)
    thread.start()
    assert commit_entered.wait(timeout=1)
    with pytest.raises(ExactPublicationError, match="already active"):
        batch.release_no_fail()
    allow_commit.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert errors == []

    release_entered = Event()
    allow_release = Event()
    release_calls = 0
    second = _new_batch()

    def release(_key: ExactPublicationKey) -> None:
        nonlocal release_calls
        release_calls += 1
        release_entered.set()
        allow_release.wait()

    second.publish(
        lambda: stage_exact_publication_row(
            errors,
            "row",
            publish=lambda _key, _digest, _frozen: None,
            release=release,
        )
    )
    release_thread = Thread(target=second.release_no_fail)
    release_thread.start()
    assert release_entered.wait(timeout=1)
    with pytest.raises(ExactPublicationError, match="already active"):
        second.release_no_fail()
    allow_release.set()
    release_thread.join(timeout=1)
    second.release_no_fail()
    assert release_calls == 1


def test_exact_publication_terminal_release_drops_callback_and_payload_graph() -> None:
    """Terminal release clears retained callbacks and prepared result graphs."""

    class Payload:
        pass

    class Publisher:
        def __call__(
            self,
            _key: ExactPublicationKey,
            _digest: str,
            _frozen: object,
        ) -> None:
            return

    batch = _new_batch()
    publisher_holder = [Publisher()]
    publisher_ref = ref(publisher_holder[0])
    batch.prepare(
        lambda: (
            stage_exact_publication_row(
                batch,
                "retained-row",
                publish=publisher_holder[0],
                release=lambda _key: None,
            ),
            Payload(),
        )[1]
    )
    prepared_result = batch._prepared_result
    assert isinstance(prepared_result, Payload)
    payload_ref = ref(prepared_result)
    del prepared_result
    batch.commit()
    publisher_holder.clear()
    assert payload_ref() is not None
    assert publisher_ref() is not None

    batch.release_no_fail()
    gc.collect()
    assert payload_ref() is None
    assert publisher_ref() is None


def test_exact_publication_base_worker_acknowledges_base_exception(tmp_path: Path) -> None:
    """An exact queued BaseException reaches the caller without stranding the worker."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    batch = _new_batch()
    try:
        with pytest.raises(KeyboardInterrupt):
            batch.publish(lambda: emitter.emit_event({"message": "interrupt"}))
        batch.publish(lambda: emitter.emit_event({"message": "accepted"}))
        batch.release_no_fail()
        emitter.barrier_flush()
    finally:
        emitter.stop_thread()

    assert (tmp_path / "base.log").read_text(encoding="utf-8").splitlines() == ["accepted"]


def test_prereserved_exact_worker_base_exception_releases_fence_for_retry(
    tmp_path: Path,
) -> None:
    """A proactively fenced worker failure aborts cleanly before a fresh retry."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    batch = _new_batch()
    try:
        batch.reserve_participants((emitter,))
        with pytest.raises(KeyboardInterrupt):
            batch.publish(lambda: emitter.emit_event({"message": "interrupt"}))
        with emitter._exact_publication_condition:
            assert emitter._pending_exact_publication_key is None
            assert emitter._active_exact_publication_keys == set()
        batch.publish(lambda: emitter.emit_event({"message": "accepted"}))
        batch.release_no_fail()
        emitter.barrier_flush()
    finally:
        emitter.stop_thread()

    assert (tmp_path / "base.log").read_text(encoding="utf-8").splitlines() == ["accepted"]


def test_exact_publication_fences_close_until_direct_admission(tmp_path: Path) -> None:
    """Close cannot overtake a prepared direct-file row or report success before commit."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "admitted-before-close"}))
    close_returned = Event()

    def close() -> None:
        emitter.close()
        close_returned.set()

    thread = Thread(target=close)
    thread.start()
    assert not close_returned.wait(timeout=0.05)
    assert not output.exists()

    batch.commit()
    assert close_returned.wait(timeout=1)
    thread.join(timeout=1)
    batch.release_no_fail()
    assert output.read_text(encoding="utf-8").splitlines() == ["admitted-before-close"]


def test_exact_direct_admission_flushes_prior_buffer_before_installing_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A threshold-independent exact receipt follows the final fsynced append boundary."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, buffer_size=100)
    emitter.emit_event({"message": "ordinary-before"})
    assert not output.exists()
    original_commit = emitter._commit_exact_buffer_row
    fail_after = True

    def append_then_raise(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal fail_after
        original_commit(key, digest, frozen)
        if fail_after:
            fail_after = False
            raise RuntimeError("append completed before lost return")

    monkeypatch.setattr(emitter, "_commit_exact_buffer_row", append_then_raise)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "exact-after"}))
    assert not output.exists()
    with pytest.raises(RuntimeError, match="lost return"):
        batch.commit()
    assert output.read_text(encoding="utf-8").splitlines() == [
        "ordinary-before",
        "exact-after",
    ]
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == [
        "ordinary-before",
        "exact-after",
    ]


def test_exact_direct_admission_preserves_buffered_prefix_and_later_suffix(
    tmp_path: Path,
) -> None:
    """A nonexact suffix waits so the exact row remains between prior and later buffers."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, buffer_size=100)
    emitter.emit_event({"message": "prefix"})
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    suffix_started = Event()
    suffix_returned = Event()

    def emit_suffix() -> None:
        suffix_started.set()
        emitter.emit_event({"message": "suffix"})
        suffix_returned.set()

    thread = Thread(target=emit_suffix)
    thread.start()
    assert suffix_started.wait(timeout=1)
    assert not suffix_returned.wait(timeout=0.05)

    batch.commit()
    assert suffix_returned.wait(timeout=1)
    thread.join(timeout=1)
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["prefix", "exact", "suffix"]


def test_exact_direct_admission_recovers_partial_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable partial append is truncated and replaced once on retry."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, buffer_size=100)
    emitter.emit_event({"message": "prefix"})
    original_commit = emitter._commit_exact_buffer_row
    fail_partial = True

    def partial_then_raise(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal fail_partial
        if not fail_partial:
            original_commit(key, digest, frozen)
            return
        fail_partial = False
        assert type(frozen) is str
        payload = f"{frozen}\n".encode()
        with emitter._file_lock:
            emitter._flush_unlocked()
            output.parent.mkdir(parents=True, exist_ok=True)
            offset = output.stat().st_size
            emitter._exact_file_pending[key] = (digest, offset, len(payload))
            with output.open("ab") as stream:
                stream.write(payload[:3])
                stream.flush()
                emitter_base.os.fsync(stream.fileno())
        raise RuntimeError("partial append interrupted")

    monkeypatch.setattr(emitter, "_commit_exact_buffer_row", partial_then_raise)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    with pytest.raises(RuntimeError, match="partial append"):
        batch.commit()
    assert output.read_bytes().endswith(b"exa")

    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["prefix", "exact"]


def test_exact_direct_admission_reconciles_fsync_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed fsync that raises is re-fsynced and acknowledged without another append."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output)
    original_fsync = emitter_base.os.fsync
    fail_after = True

    def fsync_then_raise(descriptor: int) -> None:
        nonlocal fail_after
        original_fsync(descriptor)
        if fail_after:
            fail_after = False
            raise OSError("fsync return lost")

    monkeypatch.setattr(emitter_base.os, "fsync", fsync_then_raise)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    with pytest.raises(OSError, match="fsync return lost"):
        batch.commit()
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["exact"]


def test_exact_publication_rejects_second_concurrent_commit() -> None:
    """Two commit calls on one exact carrier cannot execute the same callback concurrently."""

    batch = _new_batch()
    entered = Event()
    allow = Event()
    calls = 0

    def publish(_key: ExactPublicationKey, _digest: str, _frozen: object) -> None:
        nonlocal calls
        calls += 1
        entered.set()
        allow.wait()

    batch.prepare(
        lambda: stage_exact_publication_row(
            batch,
            "row",
            publish=publish,
            release=lambda _key: None,
        )
    )
    thread = Thread(target=batch.commit)
    thread.start()
    assert entered.wait(timeout=1)
    with pytest.raises(ExactPublicationError, match="already active"):
        batch.commit()
    allow.set()
    thread.join(timeout=1)
    assert calls == 1
    assert batch.commit() is True
    batch.release_no_fail()


def test_direct_writer_refuses_second_exact_batch_before_mutation(tmp_path: Path) -> None:
    """One unresolved writer owner rejects a competing prepared batch precanonically."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output)
    authority = ExactPublicationAuthority(capacity=2)
    first = authority.issue_batch()
    second = authority.issue_batch()
    first.prepare(lambda: emitter.emit_event({"message": "first"}))

    with pytest.raises(ExactPublicationError, match="unresolved exact publication"):
        second.prepare(lambda: emitter.emit_event({"message": "second"}))
    assert not output.exists()
    first.commit()
    first.release_no_fail()

    second.prepare(lambda: emitter.emit_event({"message": "second"}))
    second.commit()
    second.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["first", "second"]


def test_exact_header_and_footer_close_are_idempotent_after_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty destination gains one header/footer and closed emitters never reopen."""

    output = tmp_path / "windows.xml"
    output.touch()
    emitter = _TestBaseEmitter(load_format("windows_event_security"), output)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "<Event>exact</Event>"}))
    assert output.read_bytes() == b""
    batch.commit()
    batch.release_no_fail()

    original_footer = emitter._write_footer
    fail_after_footer = True

    def footer_then_raise() -> None:
        nonlocal fail_after_footer
        original_footer()
        if fail_after_footer:
            fail_after_footer = False
            raise RuntimeError("close return lost")

    monkeypatch.setattr(emitter, "_write_footer", footer_then_raise)
    with pytest.raises(RuntimeError, match="close return lost"):
        emitter.close()
    with pytest.raises(RuntimeError, match="closed"):
        emitter.emit_event({"message": "late"})
    emitter.close()
    content = output.read_text(encoding="utf-8")
    assert content.count("<?xml") == 1
    assert content.count("<Events>") == 1
    assert content.count("<Event>exact</Event>") == 1
    assert content.count("</Events>") == 1


def test_exact_worker_barrier_waits_for_durable_admission(tmp_path: Path) -> None:
    """A worker acknowledgement cannot let a queued barrier overtake sink admission."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=True)
    batch = _new_batch()
    batch.prepare(lambda: emitter.emit_event({"message": "before-barrier"}))
    barrier_returned = Event()

    def barrier() -> None:
        emitter.barrier_flush()
        barrier_returned.set()

    thread = Thread(target=barrier)
    thread.start()
    assert not barrier_returned.wait(timeout=0.05)
    assert not output.exists()
    batch.commit()
    assert barrier_returned.wait(timeout=1)
    thread.join(timeout=1)
    batch.release_no_fail()
    emitter.stop_thread()
    assert output.read_text(encoding="utf-8").splitlines() == ["before-barrier"]


def test_exact_registration_drains_prefix_and_fences_ordinary_and_barrier_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pending registration drains B/O/barrier before fencing its exact suffix."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=True)
    blocker_entered = Event()
    release_blocker = Event()
    dispatch_order: list[str] = []
    original_render = emitter._render_event

    def render(event_data: dict[str, object]) -> str:
        label = str(event_data["message"])
        dispatch_order.append(label)
        if label == "blocker":
            blocker_entered.set()
            assert release_blocker.wait(timeout=2)
        return original_render(event_data)

    monkeypatch.setattr(emitter, "_render_event", render)
    emitter.emit_event({"message": "blocker"})
    assert blocker_entered.wait(timeout=1)
    emitter.emit_event({"message": "ordinary"})

    prefix_barrier_returned = Event()
    prefix_barrier = Thread(
        target=lambda: (emitter.barrier_flush(), prefix_barrier_returned.set()),
        daemon=True,
    )
    prefix_barrier.start()
    deadline = monotonic() + 1
    while monotonic() < deadline:
        with emitter._exact_publication_condition:
            if emitter._queue_admissions == 1:
                break
        sleep(0.01)
    else:
        raise AssertionError("prefix barrier did not retain its queue admission")

    batch = _new_batch()
    reserve_failures: list[BaseException] = []
    reserve_returned = Event()

    def reserve() -> None:
        try:
            batch.reserve_participants((emitter,))
            reserve_returned.set()
        except BaseException as error:
            reserve_failures.append(error)

    reserver = Thread(target=reserve, daemon=True)
    reserver.start()
    _wait_for_pending_exact_registration(emitter)

    suffix_returned = Event()
    suffix = Thread(
        target=lambda: (emitter.emit_event({"message": "suffix"}), suffix_returned.set()),
        daemon=True,
    )
    post_barrier_returned = Event()
    post_barrier = Thread(
        target=lambda: (emitter.barrier_flush(), post_barrier_returned.set()),
        daemon=True,
    )
    suffix.start()
    post_barrier.start()
    assert not suffix_returned.wait(timeout=0.05)
    assert not post_barrier_returned.wait(timeout=0.05)

    release_blocker.set()
    assert prefix_barrier_returned.wait(timeout=1)
    assert reserve_returned.wait(timeout=1)
    reserver.join(timeout=1)
    prefix_barrier.join(timeout=1)
    assert reserve_failures == []
    assert not suffix_returned.is_set()
    assert not post_barrier_returned.is_set()

    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    assert dispatch_order == ["blocker", "ordinary", "exact"]
    batch.commit()
    assert suffix_returned.wait(timeout=1)
    assert post_barrier_returned.wait(timeout=1)
    suffix.join(timeout=1)
    post_barrier.join(timeout=1)
    batch.release_no_fail()
    emitter.close()
    assert dispatch_order == ["blocker", "ordinary", "exact", "suffix"]
    assert output.read_text(encoding="utf-8").splitlines() == [
        "blocker",
        "ordinary",
        "exact",
        "suffix",
    ]


def test_nonthreaded_buffer_waits_for_pending_exact_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A direct ordinary buffer mutation cannot overtake pending exact ownership."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=False)
    batch = _new_batch()
    activation_entered = Event()
    release_activation = Event()
    original_activate = emitter._activate_exact_publication_batch

    def activate(key: tuple[int, int]) -> None:
        activation_entered.set()
        assert release_activation.wait(timeout=2)
        original_activate(key)

    monkeypatch.setattr(emitter, "_activate_exact_publication_batch", activate)
    reserve_returned = Event()
    reserver = Thread(
        target=lambda: (batch.reserve_participants((emitter,)), reserve_returned.set()),
        daemon=True,
    )
    reserver.start()
    assert activation_entered.wait(timeout=1)
    _wait_for_pending_exact_registration(emitter)

    ordinary_returned = Event()
    ordinary = Thread(
        target=lambda: (emitter.emit_event({"message": "ordinary"}), ordinary_returned.set()),
        daemon=True,
    )
    ordinary.start()
    assert not ordinary_returned.wait(timeout=0.05)
    assert emitter.buffer == []

    release_activation.set()
    assert reserve_returned.wait(timeout=1)
    reserver.join(timeout=1)
    assert not ordinary_returned.wait(timeout=0.05)
    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    batch.commit()
    assert ordinary_returned.wait(timeout=1)
    ordinary.join(timeout=1)
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["exact", "ordinary"]


def test_zero_row_participant_releases_post_fence_suffix(tmp_path: Path) -> None:
    """A proactively reserved zero-row participant releases its ordinary suffix at commit."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=True)
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    assert batch.prepare(lambda: "zero-row") == "zero-row"
    suffix_returned = Event()
    suffix = Thread(
        target=lambda: (emitter.emit_event({"message": "suffix"}), suffix_returned.set()),
        daemon=True,
    )
    suffix.start()
    assert not suffix_returned.wait(timeout=0.05)

    assert batch.commit() == "zero-row"
    assert suffix_returned.wait(timeout=1)
    suffix.join(timeout=1)
    batch.release_no_fail()
    emitter.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["suffix"]


def test_active_threaded_exact_owner_renders_after_register_first_close(tmp_path: Path) -> None:
    """Register-first close waits while its active threaded owner queues a nonzero row."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=True)
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    closer, close_returned, close_failures = _start_close_waiting_on_active_exact(emitter)

    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    assert not close_returned.is_set()
    batch.commit()
    batch.release_no_fail()
    assert close_returned.wait(timeout=1)
    closer.join(timeout=1)
    assert close_failures == []
    assert output.read_text(encoding="utf-8").splitlines() == ["exact"]


def test_active_nonthreaded_base_owner_stages_after_register_first_close(tmp_path: Path) -> None:
    """A direct base buffer stages for its matching active owner while close waits."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=False)
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    closer, close_returned, close_failures = _start_close_waiting_on_active_exact(emitter)

    batch.prepare(lambda: emitter.emit_event({"message": "exact"}))
    assert not close_returned.is_set()
    batch.commit()
    batch.release_no_fail()
    assert close_returned.wait(timeout=1)
    closer.join(timeout=1)
    assert close_failures == []
    assert output.read_text(encoding="utf-8").splitlines() == ["exact"]


@pytest.mark.parametrize("emitter_kind", ["host", "sensor"])
def test_active_nonthreaded_multiplexer_owner_renders_after_register_first_close(
    tmp_path: Path,
    emitter_kind: str,
) -> None:
    """Host and sensor synchronous admissions retain their active exact close owner."""

    output = tmp_path / f"{emitter_kind}.log"
    if emitter_kind == "host":
        emitter: LogEmitter = _TestHostEmitter(load_format("syslog"), output)
        event = {"message": "exact", "_host_fqdn": ""}
    else:
        emitter = _TestSensorEmitter(load_format("zeek_conn"), output)
        event = {"message": "exact"}
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    closer, close_returned, close_failures = _start_close_waiting_on_active_exact(emitter)

    batch.prepare(lambda: emitter.emit_event(event))
    assert not close_returned.is_set()
    batch.commit()
    batch.release_no_fail()
    assert close_returned.wait(timeout=1)
    closer.join(timeout=1)
    assert close_failures == []
    assert output.read_text(encoding="utf-8").splitlines() == ["exact"]


def test_register_first_close_releases_after_exact_render_failure(tmp_path: Path) -> None:
    """A failed nonzero render aborts its active fence and lets the waiting close finish."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=False)
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    closer, close_returned, close_failures = _start_close_waiting_on_active_exact(emitter)

    def render() -> None:
        emitter.emit_event({"message": "discarded"})
        raise RuntimeError("render failed after staging")

    with pytest.raises(RuntimeError, match="render failed after staging"):
        batch.prepare(render)
    assert close_returned.wait(timeout=1)
    closer.join(timeout=1)
    assert close_failures == []
    assert not output.exists()


def test_register_first_pending_owner_completes_before_close(tmp_path: Path) -> None:
    """A close that loses to pending registration waits for its zero-row completion."""

    output = tmp_path / "base.log"
    emitter = _TestBaseEmitter(load_format("syslog"), output, threaded=True)
    blocker_entered = Event()
    release_blocker = Event()
    original_render = emitter._render_event

    def render(event_data: dict[str, object]) -> str:
        blocker_entered.set()
        assert release_blocker.wait(timeout=2)
        return original_render(event_data)

    emitter._render_event = render
    emitter.emit_event({"message": "prefix"})
    assert blocker_entered.wait(timeout=1)
    batch = _new_batch()
    reserve_returned = Event()
    reserve_failures: list[BaseException] = []

    def reserve() -> None:
        try:
            batch.reserve_participants((emitter,))
            reserve_returned.set()
        except BaseException as error:
            reserve_failures.append(error)

    reserver = Thread(target=reserve, daemon=True)
    reserver.start()
    _wait_for_pending_exact_registration(emitter)
    close_returned = Event()
    close_failures: list[BaseException] = []

    def close() -> None:
        try:
            emitter.close()
            close_returned.set()
        except BaseException as error:
            close_failures.append(error)

    closer = Thread(target=close, daemon=True)
    closer.start()
    assert not close_returned.wait(timeout=0.05)
    release_blocker.set()
    assert reserve_returned.wait(timeout=1)
    assert not close_returned.is_set()

    batch.prepare(lambda: "zero-row")
    batch.commit()
    assert close_returned.wait(timeout=1)
    reserver.join(timeout=1)
    closer.join(timeout=1)
    batch.release_no_fail()
    assert reserve_failures == []
    assert close_failures == []
    assert output.read_text(encoding="utf-8").splitlines() == ["prefix"]


def test_close_first_rejects_exact_registration_before_render(tmp_path: Path) -> None:
    """A close that claims admission first rejects a later exact participant."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    blocker_entered = Event()
    release_blocker = Event()
    original_render = emitter._render_event

    def render(event_data: dict[str, object]) -> str:
        blocker_entered.set()
        assert release_blocker.wait(timeout=2)
        return original_render(event_data)

    emitter._render_event = render
    emitter.emit_event({"message": "prefix"})
    assert blocker_entered.wait(timeout=1)
    close_failures: list[BaseException] = []

    def close() -> None:
        try:
            emitter.close()
        except BaseException as error:
            close_failures.append(error)

    closer = Thread(target=close, daemon=True)
    closer.start()
    deadline = monotonic() + 1
    while monotonic() < deadline:
        with emitter._exact_publication_condition:
            if emitter._close_state == "closing":
                break
        sleep(0.01)
    else:
        raise AssertionError("close did not claim the emitter before registration")

    batch = _new_batch()
    with pytest.raises(ExactPublicationError, match="closing or closed"):
        batch.reserve_participants((emitter,))
    assert batch.state == "issued"
    release_blocker.set()
    closer.join(timeout=1)
    assert not closer.is_alive()
    assert close_failures == []
    batch.cancel()


def test_exact_registration_failure_clears_pending_fence_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fail-before FIFO drain leaves no pending/active owner and can be retried."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    original_drain = emitter._drain_threaded_before_exact_publication
    fail_once = True

    def drain() -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("injected exact registration drain failure")
        original_drain()

    monkeypatch.setattr(emitter, "_drain_threaded_before_exact_publication", drain)
    batch = _new_batch()
    with pytest.raises(RuntimeError, match="registration drain failure"):
        batch.reserve_participants((emitter,))
    with emitter._exact_publication_condition:
        assert emitter._pending_exact_publication_key is None
        assert emitter._active_exact_publication_keys == set()
        assert emitter._queue_admissions == 0
    assert batch.state == "issued"

    batch.reserve_participants((emitter,))
    batch.prepare(lambda: emitter.emit_event({"message": "recovered"}))
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert (tmp_path / "base.log").read_text(encoding="utf-8").splitlines() == ["recovered"]


def test_later_participant_registration_failure_aborts_generic_fence(tmp_path: Path) -> None:
    """A later participant fail-before removes an earlier generic emitter fence."""

    emitter = _TestBaseEmitter(load_format("syslog"), tmp_path / "base.log")
    abort_calls = 0

    class FailingParticipant:
        def _register_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            raise RuntimeError("later participant rejected")

        def _complete_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            raise AssertionError("failed reservation cannot complete")

        def _abort_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            nonlocal abort_calls
            abort_calls += 1

    batch = _new_batch()
    with pytest.raises(RuntimeError, match="later participant rejected"):
        batch.reserve_participants((emitter, FailingParticipant()))
    with emitter._exact_publication_condition:
        assert emitter._pending_exact_publication_key is None
        assert emitter._active_exact_publication_keys == set()
    assert abort_calls == 1
    emitter.emit_event({"message": "ordinary-after-abort"})
    emitter.close()
    batch.cancel()
    assert (tmp_path / "base.log").read_text(encoding="utf-8").splitlines() == [
        "ordinary-after-abort"
    ]


def test_active_exact_render_rejects_reentrant_barrier(tmp_path: Path) -> None:
    """A control request cannot self-queue behind the exact fence that owns its render."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    batch = _new_batch()
    batch.reserve_participants((emitter,))
    with pytest.raises(ExactPublicationError, match="barrier cannot re-enter"):
        batch.prepare(emitter.barrier_flush)
    assert batch.state == "issued"

    batch.publish(lambda: emitter.emit_event({"message": "recovered"}))
    batch.release_no_fail()
    emitter.close()
    assert (tmp_path / "base.log").read_text(encoding="utf-8").splitlines() == ["recovered"]


def test_worker_thread_rejects_exact_participant_registration(tmp_path: Path) -> None:
    """A worker cannot enqueue a drain marker behind the item it is currently rendering."""

    emitter = _TestBaseEmitter(
        load_format("syslog"),
        tmp_path / "base.log",
        threaded=True,
    )
    batch = _new_batch()
    failures: list[BaseException] = []
    original_render = emitter._render_event

    def render(event_data: dict[str, object]) -> str:
        try:
            batch.reserve_participants((emitter,))
        except BaseException as error:
            failures.append(error)
        return original_render(event_data)

    emitter._render_event = render
    emitter.emit_event({"message": "ordinary"})
    emitter.barrier_flush()
    assert len(failures) == 1
    assert isinstance(failures[0], ExactPublicationError)
    assert "cannot register from its worker" in str(failures[0])
    with emitter._exact_publication_condition:
        assert emitter._pending_exact_publication_key is None
        assert emitter._active_exact_publication_keys == set()
    batch.cancel()
    emitter.close()


@pytest.mark.parametrize("emitter_kind", ["host", "sensor"])
def test_exact_multiplexer_retry_preserves_caller_payload(
    tmp_path: Path,
    emitter_kind: str,
) -> None:
    """Host and sensor routing freeze copies instead of destructively consuming caller data."""

    if emitter_kind == "host":
        emitter = _TestHostEmitter(load_format("syslog"), tmp_path / "host.log")
        event = {"message": "stable", "_host_fqdn": ""}
    else:
        emitter = _TestSensorEmitter(load_format("zeek_conn"), tmp_path / "sensor.log")
        event = {"message": "stable"}
    original = dict(event)
    batch = _new_batch()
    fail_render = True

    def render() -> None:
        nonlocal fail_render
        emitter.emit_event(event)
        if fail_render:
            fail_render = False
            raise RuntimeError("render failed after routing")

    with pytest.raises(RuntimeError, match="render failed"):
        batch.prepare(render)
    assert event == original
    batch.prepare(render)
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert emitter.output_path.read_text(encoding="utf-8").splitlines() == ["stable"]


def test_exact_publication_crosses_host_and_sensor_worker_boundaries(tmp_path: Path) -> None:
    """Host and sensor worker overrides retain the producer's exact staging attempt."""

    host_path = tmp_path / "host.log"
    host = _TestHostEmitter(load_format("syslog"), host_path, threaded=True)
    sensor_path = tmp_path / "sensor.log"
    sensor = _TestSensorEmitter(load_format("zeek_conn"), sensor_path, threaded=True)
    host_batch = _new_batch()
    sensor_batch = _new_batch()
    try:
        host_batch.publish(lambda: host.emit_event({"message": "host-row", "_host_fqdn": ""}))
        sensor_batch.publish(lambda: sensor.emit_event({"message": "sensor-row"}))
        host_batch.release_no_fail()
        sensor_batch.release_no_fail()
        host.barrier_flush()
        sensor.barrier_flush()
    finally:
        host.close()
        sensor.close()

    assert host_path.read_text(encoding="utf-8").splitlines() == ["host-row"]
    assert sensor_path.read_text(encoding="utf-8").splitlines() == ["sensor-row"]


def test_participant_completion_is_terminal_reentrant_and_lock_free() -> None:
    """A pinned completion observes committed state and may make a read-only reentry."""

    batch = _new_batch()
    observations: list[tuple[str, object]] = []

    class Participant:
        def __init__(self) -> None:
            self.complete_calls = 0
            self.abort_calls = 0

        def _register_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            return

        def _complete_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            self.complete_calls += 1

            def inspect() -> None:
                observations.append((batch.state, batch.commit()))

            probe = Thread(target=inspect, daemon=True)
            probe.start()
            probe.join(timeout=1)
            assert not probe.is_alive()

        def _abort_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            self.abort_calls += 1

    participant = Participant()
    batch.reserve_participants((participant,))
    batch.prepare(lambda: "stable")
    assert batch.commit() == "stable"
    assert observations == [("committed", "stable")]
    assert participant.complete_calls == 1
    assert participant.abort_calls == 0
    assert batch.commit() == "stable"
    assert participant.complete_calls == 1
    batch.release_no_fail()


def test_prepared_result_copy_is_reentrant_outside_the_batch_lock() -> None:
    """Ready and committed result copies may inspect state without locking themselves out."""

    batch = _new_batch()
    observed_states: list[str] = []

    class CopyProbe:
        def __deepcopy__(self, _memo: dict[int, object]) -> CopyProbe:
            observed: list[str] = []
            probe = Thread(target=lambda: observed.append(batch.state), daemon=True)
            probe.start()
            probe.join(timeout=1)
            assert not probe.is_alive()
            observed_states.extend(observed)
            return self

    result = CopyProbe()
    assert batch.prepare(lambda: result) is result
    assert batch.prepare(lambda: pytest.fail("ready batches must not rerender")) is result
    assert batch.commit() is result
    assert batch.commit() is result
    assert observed_states == ["preparing", "ready", "ready", "committed", "committed"]
    batch.release_no_fail()


def test_terminal_copy_failure_remains_primary_and_completes_participants_once() -> None:
    """A terminal copy failure cannot strand, reopen, or double-complete participants."""

    batch = _new_batch()
    completion_calls = 0

    class CopyFailure:
        def __init__(self) -> None:
            self.failed = False

        def __deepcopy__(self, _memo: dict[int, object]) -> CopyFailure:
            if batch.state == "committed" and not self.failed:
                self.failed = True
                raise ValueError("copy-primary")
            return self

    class Participant:
        def _register_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            return

        def _complete_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            nonlocal completion_calls
            completion_calls += 1
            raise RuntimeError("callback-secondary")

        def _abort_exact_publication_batch(self, _key: tuple[str, int]) -> None:
            raise AssertionError("committed participants must not abort")

    result = CopyFailure()
    batch.reserve_participants((Participant(),))
    assert batch.prepare(lambda: result) is result
    with pytest.raises(ValueError, match="copy-primary") as raised:
        batch.commit()
    assert completion_calls == 1
    assert batch.state == "committed"
    assert any("callback-secondary" in note for note in getattr(raised.value, "__notes__", ()))
    assert batch.commit() is result
    assert completion_calls == 1
    batch.release_no_fail()


@pytest.mark.parametrize(
    ("terminal_operation", "terminal_state"),
    [("release", "released"), ("cancel", "canceled")],
)
def test_terminal_reference_finalizers_run_reentrantly_outside_batch_lock(
    terminal_operation: str,
    terminal_state: str,
) -> None:
    """Dropping prepared rows/results at release or cancel cannot hold the batch lock."""

    batch = _new_batch()
    observations: list[tuple[str, bool, tuple[str, ...]]] = []

    def observe_finalizer(name: str) -> None:
        states: list[str] = []
        probe = Thread(target=lambda: states.append(batch.state), daemon=True)
        probe.start()
        probe.join(timeout=1)
        observations.append((name, probe.is_alive(), tuple(states)))

    class ResultOwner:
        def __deepcopy__(self, _memo: dict[int, object]) -> ResultOwner:
            return self

        def __del__(self) -> None:
            observe_finalizer("result")

    class CallbackOwner:
        def publish(self, _key: ExactPublicationKey, _digest: str, _frozen: object) -> None:
            return

        def release(self, _key: ExactPublicationKey) -> None:
            return

        def __del__(self) -> None:
            observe_finalizer("row")

    callback_holder = [CallbackOwner()]

    def render() -> ResultOwner:
        assert stage_exact_publication_row(
            [],
            "terminal-row",
            publish=callback_holder[0].publish,
            release=callback_holder[0].release,
        )
        return ResultOwner()

    batch.prepare(render)
    callback_holder.clear()
    if terminal_operation == "release":
        batch.commit()
        batch.release_no_fail()
    else:
        batch.cancel()
    gc.collect()
    assert sorted(observations) == [
        ("result", False, (terminal_state,)),
        ("row", False, (terminal_state,)),
    ]


def test_participant_operations_are_resolved_lock_free_and_pinned_once() -> None:
    """Descriptor lookup cannot run under the batch lock or change after registration."""

    batch = _new_batch()
    lookups: list[str] = []
    completions: list[str] = []

    class Participant:
        def _lookup(self, name: str, callback: object) -> object:
            observed: list[str] = []
            probe = Thread(target=lambda: observed.append(batch.state), daemon=True)
            probe.start()
            probe.join(timeout=1)
            assert not probe.is_alive()
            assert observed == ["issued"]
            lookups.append(name)
            return callback

        @property
        def _register_exact_publication_batch(self) -> object:
            return self._lookup("register", self.register)

        @property
        def _complete_exact_publication_batch(self) -> object:
            return self._lookup("complete", self.complete)

        @property
        def _abort_exact_publication_batch(self) -> object:
            return self._lookup("abort", self.abort)

        def register(self, _key: tuple[str, int]) -> None:
            return

        def complete(self, _key: tuple[str, int]) -> None:
            completions.append("pinned")

        def abort(self, _key: tuple[str, int]) -> None:
            raise AssertionError("committed participant must not abort")

    participant = Participant()
    batch.reserve_participants((participant,))
    participant.complete = lambda _key: completions.append("mutated")  # type: ignore[method-assign]
    batch.prepare(lambda: "stable")
    assert batch.commit() == "stable"
    assert lookups == ["register", "complete", "abort"]
    assert completions == ["pinned"]
    batch.release_no_fail()


def test_participant_completion_preserves_first_failure_and_runs_each_once() -> None:
    """Every detached completion runs once while the first callback remains primary."""

    batch = _new_batch()
    calls: list[str] = []

    class Participant:
        def __init__(self, name: str) -> None:
            self.name = name

        def _register_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            return

        def _complete_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            calls.append(self.name)
            raise RuntimeError(self.name)

        def _abort_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            raise AssertionError("committed participants must not abort")

    batch.reserve_participants((Participant("first"), Participant("second")))
    batch.prepare(lambda: "stable")
    with pytest.raises(RuntimeError, match="first") as raised:
        batch.commit()
    assert calls == ["first", "second"]
    assert batch.state == "committed"
    assert any("second" in note for note in getattr(raised.value, "__notes__", ()))
    assert batch.commit() == "stable"
    assert calls == ["first", "second"]
    batch.release_no_fail()


def test_participant_abort_preserves_render_failure_and_terminal_cancel_reentry() -> None:
    """Abort cleanup cannot replace a render failure or deadlock terminal cancellation."""

    batch = _new_batch()
    abort_states: list[str] = []

    class Participant:
        def _register_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            return

        def _complete_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            raise AssertionError("failed preparation must not complete")

        def _abort_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            abort_states.append(batch.state)
            raise RuntimeError("abort-cleanup")

    batch.reserve_participants((Participant(),))

    def fail_render() -> None:
        raise ValueError("render-primary")

    with pytest.raises(ValueError, match="render-primary") as raised:
        batch.prepare(fail_render)
    assert abort_states == ["issued"]
    assert any("abort-cleanup" in note for note in getattr(raised.value, "__notes__", ()))

    class CancelParticipant(Participant):
        def _abort_exact_publication_batch(
            self,
            _key: tuple[str, int],
        ) -> None:
            abort_states.append(batch.state)
            batch.cancel()

    batch.reserve_participants((CancelParticipant(),))
    batch.cancel()
    assert abort_states == ["issued", "canceled"]
    batch.cancel()


@pytest.mark.parametrize("exact", [False, True])
def test_terminal_close_rejects_late_render_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exact: bool,
) -> None:
    """A render that passed an early check cannot append after terminal close."""

    output = tmp_path / ("exact.log" if exact else "ordinary.log")
    emitter = _TestBaseEmitter(load_format("syslog"), output)
    render_entered = Event()
    allow_render = Event()
    errors: list[BaseException] = []

    def blocked_render(event_data: dict[str, object]) -> str:
        render_entered.set()
        allow_render.wait(timeout=2)
        return str(event_data["message"])

    monkeypatch.setattr(emitter, "_render_event", blocked_render)
    batch = _new_batch() if exact else None

    def emit() -> None:
        try:
            if batch is None:
                emitter.emit_event({"message": "late"})
            else:
                batch.prepare(lambda: emitter.emit_event({"message": "late"}))
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=emit)
    thread.start()
    assert render_entered.wait(timeout=1)
    emitter.close()
    allow_render.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert len(errors) == 1
    assert "closing or closed" in str(errors[0])
    assert not output.exists()
    if batch is not None:
        batch.cancel()
