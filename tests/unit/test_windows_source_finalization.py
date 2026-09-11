# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused Windows Security terminal source-finalization tests."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    ExactPublicationKey,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.windows import (
    WindowsEventEmitter,
    _spool_decode,
    _spool_encode,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.source_finalization import (
    ExactChunkPublisher,
    ExactSourceRow,
    SourceFinalizationCoordinator,
    SourceFinalizationEpoch,
    SourceFinalizationError,
)
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)
from evidenceforge.output_targets import OutputTarget

pytestmark = pytest.mark.slow


def _event(timestamp: datetime, username: str) -> dict[str, object]:
    return {
        "EventID": 4624,
        "TimeCreated": timestamp,
        "Computer": "WIN-TEST-01.corp.local",
        "Channel": "Security",
        "Level": 0,
        "ExecutionProcessID": 4,
        "ExecutionThreadID": 100,
        "TargetUserName": username,
        "TargetDomainName": "CORP",
        "TargetLogonId": f"0x{timestamp.second:06x}",
        "LogonType": 2,
        "WorkstationName": "WIN-TEST-01",
        "IpAddress": "192.168.1.100",
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
    }


def _authority() -> ExactPublicationAuthority:
    return ExactPublicationAuthority(
        capacity=1,
        row_capacity=512,
        byte_capacity=20 * 1024 * 1024,
    )


@pytest.mark.parametrize(
    "key",
    [
        ("A" * 32, 1, 0),
        ("a" * 31, 1, 0),
        ("a" * 32, True, 0),
        ("a" * 32, 2**63, 0),
        ("a" * 32, 1, 2**63),
    ],
)
def test_windows_exact_candidate_key_rejects_unbounded_or_noncanonical_values(
    key: object,
) -> None:
    """Journal receipt keys are exact, canonical, and SQLite-safe."""

    with pytest.raises(ExactPublicationError, match="key is malformed"):
        WindowsEventEmitter._validate_exact_candidate_key(key)  # type: ignore[arg-type]


def _scenario() -> Scenario:
    return Scenario(
        version="1.0",
        name="windows-source-finalization",
        description="Focused terminal source test",
        environment=Environment(
            description="One Windows host",
            users=[
                User(
                    username="testuser",
                    full_name="Test User",
                    email="test@example.com",
                    enabled=True,
                    primary_system="WIN-TEST-01",
                )
            ],
            systems=[
                System(
                    hostname="WIN-TEST-01",
                    ip="10.0.0.1",
                    os="Windows 11",
                    type="workstation",
                )
            ],
        ),
        time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="1h"),
        baseline_activity=BaselineActivity(
            description="Focused baseline",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}],
            destination="./output",
            compression=False,
        ),
        personas=[],
    )


@pytest.mark.parametrize("threaded", [False, True])
def test_windows_exact_candidate_prepare_reserves_without_admitting_and_cancel_is_neutral(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Exact Type-5 candidates stay private until commit and cancel releases capacity."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    first = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once")
    second = {
        **first,
        "EventID": 4672,
        "PrivilegeList": "SeSecurityPrivilege",
    }

    try:
        batch.prepare(lambda: (emitter.emit_event(first), emitter.emit_event(second)))

        assert emitter._event_dicts == []
        assert emitter._event_queue is None or emitter._event_queue.empty()
        census = emitter.source_finalization_census()
        assert census.candidate_rows == 2
        assert census.candidate_bytes > 0
        exact_census = emitter.exact_candidate_census()
        assert (
            exact_census.current_rows,
            exact_census.current_participants,
            exact_census.released_rows,
        ) == (2, 1, 0)
        assert exact_census.current_bytes > 0

        batch.cancel()

        census = emitter.source_finalization_census()
        assert census.candidate_rows == 0
        assert census.candidate_bytes == 0
        assert emitter._event_dicts == []
        assert emitter._event_queue is None or emitter._event_queue.empty()
        assert emitter._spool_sequence == 0
        exact_census = emitter.exact_candidate_census()
        assert (
            exact_census.current_rows,
            exact_census.current_bytes,
            exact_census.current_participants,
        ) == (0, 0, 0)
        assert (
            exact_census.high_water_rows,
            exact_census.high_water_participants,
        ) == (2, 1)

        replacement = _authority().issue_batch()
        replacement.prepare(lambda: emitter.emit_event(first))
        replacement.commit()
        with emitter._file_lock:
            assert emitter._spool_conn is not None
            exact_sequences = emitter._spool_conn.execute(
                "SELECT sequence FROM events WHERE route_kind = ?",
                ("exact-candidate-v1",),
            ).fetchall()
        assert exact_sequences == [(0,)]
        replacement.release_no_fail()
        coordinator = SourceFinalizationCoordinator((emitter,), _authority())
        coordinator.finalize()
        emitter.close()
        coordinator.mark_closed()
    finally:
        if not batch.released and batch.state != "canceled":
            batch.cancel()
        emitter.close()


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_exact_candidate_commit_resumes_4672_without_duplicate_4624(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    threaded: bool,
    lost_return: bool,
) -> None:
    """A second-row failure resumes the same journal candidates and batch cursor."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    first = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once")
    second = {**first, "EventID": 4672, "PrivilegeList": "SeSecurityPrivilege"}
    original_commit = emitter._commit_exact_candidate_row
    faulted = False

    def fail_second_once(key: tuple[str, int, int], digest: str, frozen: object) -> None:
        nonlocal faulted
        if key[2] == 1 and not faulted:
            faulted = True
            if lost_return:
                original_commit(key, digest, frozen)
            raise RuntimeError("4672 exact candidate return lost")
        original_commit(key, digest, frozen)

    monkeypatch.setattr(emitter, "_commit_exact_candidate_row", fail_second_once)
    batch.prepare(lambda: (emitter.emit_event(first), emitter.emit_event(second)))

    with pytest.raises(RuntimeError, match="4672 exact candidate return lost"):
        batch.commit()
    assert batch.state == "ready"
    assert emitter.exact_candidate_census().current_rows == 2

    batch.commit()
    batch.release_no_fail()
    exact_census = emitter.exact_candidate_census()
    assert (
        exact_census.released_rows,
        exact_census.released_bytes,
        exact_census.completed_participants,
    ) == (
        exact_census.current_rows,
        exact_census.current_bytes,
        exact_census.current_participants,
    )

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("<EventID>4624</EventID>") == 1
    assert output.count("<EventID>4672</EventID>") == 1
    terminal_census = emitter.exact_candidate_census()
    assert (
        terminal_census.current_rows,
        terminal_census.current_bytes,
        terminal_census.current_participants,
        terminal_census.released_rows,
        terminal_census.released_bytes,
        terminal_census.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)


def test_windows_exact_candidate_release_fences_quiesce_until_receipt_retires(
    tmp_path: Path,
) -> None:
    """Terminal source finalization cannot overtake an unresolved candidate receipt."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    batch.commit()
    started = Event()
    completed = Event()

    def quiesce() -> None:
        started.set()
        emitter.quiesce_source_finalization()
        completed.set()

    thread = Thread(target=quiesce)
    thread.start()
    assert started.wait(timeout=1.0)
    assert not completed.wait(timeout=0.1)

    batch.release_no_fail()
    assert completed.wait(timeout=2.0)
    thread.join(timeout=1.0)
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


def test_windows_exact_candidate_release_call_original_then_raise_is_resumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost release return reuses the retained released reservation."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    original_release = emitter._release_exact_candidate_row
    lost_return = True

    def release_then_raise(key: tuple[str, int, int]) -> None:
        nonlocal lost_return
        original_release(key)
        if lost_return:
            lost_return = False
            raise RuntimeError("candidate release return lost")

    monkeypatch.setattr(emitter, "_release_exact_candidate_row", release_then_raise)
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    batch.commit()

    with pytest.raises(RuntimeError, match="candidate release return lost"):
        batch.release_no_fail()
    assert batch.state == "releasing"

    batch.release_no_fail()
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    terminal_census = emitter.exact_candidate_census()
    assert (
        terminal_census.current_rows,
        terminal_census.current_bytes,
        terminal_census.current_participants,
    ) == (0, 0, 0)


def test_windows_exact_candidate_journal_commit_lost_return_reconciles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Candidate insertion recognizes a committed private-journal transaction."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    original_commit = emitter._commit_journal_unlocked
    lost_return = True

    def commit_then_raise() -> None:
        nonlocal lost_return
        original_commit()
        if lost_return:
            lost_return = False
            raise RuntimeError("candidate journal commit return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", commit_then_raise)
    batch.commit()
    batch.release_no_fail()
    assert not lost_return

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()


def test_windows_exact_candidate_release_rejects_tampered_journal_payload(
    tmp_path: Path,
) -> None:
    """A receipt cannot release a row whose exact journal payload was changed."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    batch.commit()

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        retained = emitter._spool_conn.execute(
            "SELECT sequence, payload FROM events WHERE route_kind = ?",
            ("exact-candidate-v1",),
        ).fetchone()
        assert retained is not None
        sequence, payload = retained
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ? WHERE sequence = ?",
            (payload + " ", sequence),
        )
        emitter._commit_journal_unlocked()

    with pytest.raises(ExactPublicationError, match="conflicting journal state"):
        batch.release_no_fail()

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ? WHERE sequence = ?",
            (payload, sequence),
        )
        emitter._commit_journal_unlocked()
    batch.release_no_fail()
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()


def _run_windows_post_release_seal_tamper(
    tmp_path: Path,
    *,
    tamper_payload: bool,
) -> None:
    output_root = tmp_path / "output"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_root,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 29, tzinfo=UTC), "ordinary-row"))
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    batch.commit()
    batch.release_no_fail()
    released_census = emitter.exact_candidate_census()
    assert (
        released_census.current_rows,
        released_census.released_rows,
        released_census.current_participants,
        released_census.completed_participants,
    ) == (1, 1, 1, 1)
    emitter.quiesce_source_finalization()

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        retained = emitter._spool_conn.execute(
            "SELECT sequence, payload, sort_key FROM events WHERE route_kind = ?",
            ("exact-candidate-v1",),
        ).fetchone()
        assert retained is not None
        sequence, payload, sort_key = retained
        if tamper_payload:
            tampered_payload = payload.replace("svc-once", "svc-twce", 1)
            assert tampered_payload != payload
            assert len(tampered_payload.encode("utf-8")) == len(payload.encode("utf-8"))
            assert _spool_decode(tampered_payload)["TargetUserName"] == "svc-twce"
            emitter._spool_conn.execute(
                "UPDATE events SET payload = ? WHERE sequence = ?",
                (tampered_payload, sequence),
            )
        else:
            emitter._spool_conn.execute(
                "UPDATE events SET sort_key = ? WHERE sequence = ?",
                (sort_key + "0", sequence),
            )
        emitter._commit_journal_unlocked()

    with pytest.raises(ExactPublicationError, match="changed payload or sort key"):
        emitter.seal_source_finalization()
    rejected_census = emitter.exact_candidate_census()
    assert (
        rejected_census.current_rows,
        rejected_census.released_rows,
        rejected_census.current_participants,
        rejected_census.completed_participants,
    ) == (1, 1, 1, 1)

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ?, sort_key = ? WHERE sequence = ?",
            (payload, sort_key, sequence),
        )
        emitter._commit_journal_unlocked()
    epoch = emitter.seal_source_finalization()
    sealed_census = emitter.exact_candidate_census()
    assert (
        sealed_census.current_rows,
        sealed_census.released_rows,
        sealed_census.current_participants,
        sealed_census.completed_participants,
    ) == (1, 1, 1, 1)
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()

    output = (output_root / "WIN-TEST-01.corp.local" / "windows_event_security.xml").read_text(
        encoding="utf-8"
    )
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    exact_census = emitter.exact_candidate_census()
    assert (
        exact_census.current_rows,
        exact_census.current_bytes,
        exact_census.current_participants,
        exact_census.released_rows,
        exact_census.released_bytes,
        exact_census.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)


def test_windows_seal_rejects_post_release_same_length_valid_json_payload_tamper(
    tmp_path: Path,
) -> None:
    """Seal reauthenticates released exact payloads while ignoring ordinary rows."""

    _run_windows_post_release_seal_tamper(tmp_path, tamper_payload=True)


def test_windows_seal_rejects_post_release_sort_key_only_tamper(tmp_path: Path) -> None:
    """Seal recomputes exact candidate sort keys before terminal fixups overwrite them."""

    _run_windows_post_release_seal_tamper(tmp_path, tamper_payload=False)


def _released_windows_abort_close_emitter(
    tmp_path: Path,
    target: OutputTarget | None = None,
    *,
    threaded: bool = False,
) -> WindowsEventEmitter:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    if target is not None:
        emitter.configure_output_target(target)
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 29, tzinfo=UTC), "ordinary-row"))
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once"))
    )
    batch.commit()
    batch.release_no_fail()
    return emitter


def _windows_exact_candidate_journal_row(
    emitter: WindowsEventEmitter,
) -> tuple[int, str, str]:
    with emitter._file_lock:
        assert emitter._spool_conn is not None
        retained = emitter._spool_conn.execute(
            "SELECT sequence, payload, sort_key FROM events WHERE route_kind = ?",
            ("exact-candidate-v1",),
        ).fetchone()
    assert retained is not None
    return retained


def test_windows_abort_close_rejects_post_release_same_length_payload_tamper(
    tmp_path: Path,
) -> None:
    """Abort close authenticates released exact payloads before legacy rendering."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    sequence, payload, sort_key = _windows_exact_candidate_journal_row(emitter)
    tampered_payload = payload.replace("svc-once", "svc-twce", 1)
    assert tampered_payload != payload
    assert len(tampered_payload.encode("utf-8")) == len(payload.encode("utf-8"))
    assert _spool_decode(tampered_payload)["TargetUserName"] == "svc-twce"
    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ? WHERE sequence = ?",
            (tampered_payload, sequence),
        )
        emitter._commit_journal_unlocked()

    with pytest.raises(
        SourceFinalizationError,
        match="released exact candidates require authenticated abort close",
    ):
        emitter.flush(force=True)
    assert not (tmp_path / "output").exists()

    with pytest.raises(ExactPublicationError, match="changed payload or sort key"):
        emitter.close()

    assert not (tmp_path / "output").exists()
    assert emitter.source_finalization_census().state == "open"
    rejected = emitter.exact_candidate_census()
    assert (
        rejected.current_rows,
        rejected.released_rows,
        rejected.current_participants,
        rejected.completed_participants,
    ) == (1, 1, 1, 1)

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ?, sort_key = ? WHERE sequence = ?",
            (payload, sort_key, sequence),
        )
        emitter._commit_journal_unlocked()
    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert "svc-twce" not in output
    assert emitter.exact_candidate_census().current_rows == 0


def test_windows_abort_close_rejects_post_release_sort_key_only_tamper(
    tmp_path: Path,
) -> None:
    """Abort close recomputes released exact candidate sort keys before rendering."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    sequence, payload, sort_key = _windows_exact_candidate_journal_row(emitter)
    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET sort_key = ? WHERE sequence = ?",
            (sort_key + "0", sequence),
        )
        emitter._commit_journal_unlocked()

    with pytest.raises(ExactPublicationError, match="changed payload or sort key"):
        emitter.close()

    assert not (tmp_path / "output").exists()
    rejected = emitter.exact_candidate_census()
    assert (rejected.current_rows, rejected.released_rows) == (1, 1)
    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ?, sort_key = ? WHERE sequence = ?",
            (payload, sort_key, sequence),
        )
        emitter._commit_journal_unlocked()
    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("threaded", [False, True])
def test_windows_valid_abort_close_preserves_legacy_bytes_and_zeroes_exact_census(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """A valid exact candidate abort close retains legacy source bytes exactly once."""

    timestamp = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)
    reference_root = tmp_path / "reference"
    reference = WindowsEventEmitter(
        load_format("windows_event_security"),
        reference_root,
    )
    reference.emit_event(_event(timestamp - timedelta(minutes=1), "ordinary-row"))
    reference.emit_event(_event(timestamp, "svc-once"))
    reference.close()

    emitter = _released_windows_abort_close_emitter(tmp_path, threaded=threaded)
    emitter.close()

    filename = Path("WIN-TEST-01.corp.local/windows_event_security.xml")
    assert (tmp_path / "output" / filename).read_bytes() == (reference_root / filename).read_bytes()
    exact_census = emitter.exact_candidate_census()
    assert (
        exact_census.current_rows,
        exact_census.current_bytes,
        exact_census.current_participants,
        exact_census.released_rows,
        exact_census.released_bytes,
        exact_census.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)
    assert emitter.source_finalization_census().state == "aborted"


def test_windows_abort_close_authentication_lost_return_retries_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost authentication return preserves receipts for one exact retry."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    original_validate = emitter._validate_exact_candidate_receipts_before_seal_unlocked
    lost_return = True

    def validate_then_raise() -> None:
        nonlocal lost_return
        original_validate()
        if lost_return:
            lost_return = False
            raise RuntimeError("abort authentication return lost")

    monkeypatch.setattr(
        emitter,
        "_validate_exact_candidate_receipts_before_seal_unlocked",
        validate_then_raise,
    )
    with pytest.raises(RuntimeError, match="abort authentication return lost"):
        emitter.close()

    assert not (tmp_path / "output").exists()
    retained = emitter.exact_candidate_census()
    assert (retained.current_rows, retained.released_rows) == (1, 1)

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_abort_close_render_failure_retains_exact_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """Abort rendering cannot retire exact receipts before retryable completion."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    original_seal = emitter._seal_source_finalization
    faulted = False

    def fail_render_once() -> SourceFinalizationEpoch:
        nonlocal faulted
        if not faulted:
            faulted = True
            if lost_return:
                original_seal()
            raise RuntimeError("abort render return lost")
        return original_seal()

    monkeypatch.setattr(emitter, "_seal_source_finalization", fail_render_once)
    with pytest.raises(RuntimeError, match="abort render return lost"):
        emitter.close()

    retained = emitter.exact_candidate_census()
    assert (
        retained.current_rows,
        retained.released_rows,
        retained.current_participants,
        retained.completed_participants,
    ) == (1, 1, 1, 1)
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert emitter.exact_candidate_census().current_rows == 0


def test_windows_abort_close_partial_internal_render_rolls_back_before_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-cohort renderer failure cannot strand partially written exact rows."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "ordinary-last"))
    original_finalize = emitter._finalize_event_for_output
    faulted = False

    def finalize_then_raise(*args: object, **kwargs: object) -> object:
        nonlocal faulted
        result = original_finalize(*args, **kwargs)
        if not faulted and args[1] == 1:
            faulted = True
            raise RuntimeError("abort renderer failed mid-cohort")
        return result

    monkeypatch.setattr(emitter, "_finalize_event_for_output", finalize_then_raise)
    with pytest.raises(RuntimeError, match="abort renderer failed mid-cohort"):
        emitter.close()

    assert not (tmp_path / "output").exists()
    assert emitter._exact_candidate_abort_close_rendering
    assert not emitter._exact_candidate_abort_close_rows_rendered
    with emitter._file_lock:
        assert emitter._journal_state_unlocked()[0] == "candidate"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert output.count("ordinary-last") == 1
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("fault_point", ["commit", "checkpoint", "release"])
@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_abort_close_exact_row_failure_resumes_one_final_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
    lost_return: bool,
) -> None:
    """Abort row commit, cursor, and release failures retain one bounded retry owner."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    faulted = False

    if fault_point == "commit":
        original_commit = _SingleHostWriter._commit_exact_row

        def commit_then_raise(
            writer: _SingleHostWriter,
            key: ExactPublicationKey,
            digest: str,
            frozen: object,
        ) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original_commit(writer, key, digest, frozen)
                raise RuntimeError("abort exact row commit failed")
            original_commit(writer, key, digest, frozen)

        monkeypatch.setattr(_SingleHostWriter, "_commit_exact_row", commit_then_raise)
    elif fault_point == "checkpoint":
        original_checkpoint = emitter._checkpoint_source_chunk

        def checkpoint_then_raise(start: int, end: int) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original_checkpoint(start, end)
                raise RuntimeError("abort exact row checkpoint failed")
            original_checkpoint(start, end)

        monkeypatch.setattr(emitter, "_checkpoint_source_chunk", checkpoint_then_raise)
    else:
        original_release = _SingleHostWriter._release_exact_row

        def release_then_raise(
            writer: _SingleHostWriter,
            key: ExactPublicationKey,
        ) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original_release(writer, key)
                raise RuntimeError("abort exact row release failed")
            original_release(writer, key)

        monkeypatch.setattr(_SingleHostWriter, "_release_exact_row", release_then_raise)

    with pytest.raises(RuntimeError, match=f"abort exact row {fault_point} failed"):
        emitter.close()

    retained = emitter.exact_candidate_census()
    assert (retained.current_rows, retained.released_rows) == (1, 1)
    assert emitter._exact_candidate_abort_pending_row is not None
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert output.count("</Events>") == 1
    assert emitter._exact_candidate_abort_pending_row is None
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_abort_close_writer_flush_failure_retains_exact_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """A terminal writer flush failure preserves authenticated abort ownership."""

    emitter = _released_windows_abort_close_emitter(tmp_path, OutputTarget.SPLUNK)
    original_flush = _SingleHostWriter.flush
    faulted = False

    def fail_writer_flush_once(writer: _SingleHostWriter) -> None:
        nonlocal faulted
        if not faulted:
            faulted = True
            if lost_return:
                original_flush(writer)
            raise RuntimeError("abort writer flush return lost")
        original_flush(writer)

    monkeypatch.setattr(_SingleHostWriter, "flush", fail_writer_flush_once)
    with pytest.raises(RuntimeError, match="abort writer flush return lost"):
        emitter.close()

    retained = emitter.exact_candidate_census()
    assert (retained.current_rows, retained.released_rows) == (1, 1)
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_abort_close_footer_failure_retains_exact_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """Abort footer retries cannot discard or duplicate rendered exact rows."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    original_footer = _SingleHostWriter.write_footer
    faulted = False

    def fail_footer_once(writer: _SingleHostWriter, footer: str) -> None:
        nonlocal faulted
        if faulted:
            original_footer(writer, footer)
            return
        faulted = True
        if lost_return:
            original_footer(writer, footer)
        raise RuntimeError("abort footer return lost")

    monkeypatch.setattr(_SingleHostWriter, "write_footer", fail_footer_once)
    with pytest.raises(RuntimeError, match="abort footer return lost"):
        emitter.close()

    retained = emitter.exact_candidate_census()
    assert (retained.current_rows, retained.released_rows) == (1, 1)
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert output.count("</Events>") == 1
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("lost_return", [False, True])
def test_windows_abort_close_journal_cleanup_failure_retains_exact_retry_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """Journal cleanup failure keeps the rendered exact rows owned for retry."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    original_cleanup = emitter._cleanup_spool_unlocked
    faulted = False

    def cleanup_then_raise() -> None:
        nonlocal faulted
        if faulted:
            original_cleanup()
            return
        faulted = True
        if lost_return:
            original_cleanup()
        raise RuntimeError("abort journal cleanup return lost")

    monkeypatch.setattr(emitter, "_cleanup_spool_unlocked", cleanup_then_raise)
    with pytest.raises(RuntimeError, match="abort journal cleanup return lost"):
        emitter.close()

    retained = emitter.exact_candidate_census()
    assert (retained.current_rows, retained.released_rows) == (1, 1)
    assert (emitter._spool_conn is None) is lost_return
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert emitter.exact_candidate_census().current_rows == 0


def test_windows_abort_close_render_owner_fences_new_work_until_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained abort render owner rejects late candidates and target mutation."""

    emitter = _released_windows_abort_close_emitter(tmp_path)
    original_seal = emitter._seal_source_finalization
    lost_return = True

    def render_then_raise() -> SourceFinalizationEpoch:
        nonlocal lost_return
        result = original_seal()
        if lost_return:
            lost_return = False
            raise RuntimeError("abort render return lost")
        return result

    monkeypatch.setattr(emitter, "_seal_source_finalization", render_then_raise)
    with pytest.raises(RuntimeError, match="abort render return lost"):
        emitter.close()

    with pytest.raises(ExactPublicationError, match="retry owner rejects new candidate"):
        emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "late-ordinary"))
    late_batch = _authority().issue_batch()
    with pytest.raises(ExactPublicationError, match="retry owner rejects exact candidate"):
        late_batch.prepare(
            lambda: emitter.emit_event(
                _event(datetime(2024, 1, 15, 10, 32, tzinfo=UTC), "late-exact")
            )
        )
    with pytest.raises(SourceFinalizationError, match="terminal source ownership"):
        emitter.configure_output_target(OutputTarget.SPLUNK)
    with pytest.raises(SourceFinalizationError, match="retry owner rejects an external flush"):
        emitter.flush(force=True)
    with pytest.raises(SourceFinalizationError, match="retry owner rejects an external barrier"):
        emitter.barrier_flush()
    with pytest.raises(SourceFinalizationError, match="retry owner rejects source quiescence"):
        emitter.quiesce_source_finalization()

    emitter.close()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.count("ordinary-row") == 1
    assert output.count("svc-once") == 1
    assert "late-ordinary" not in output
    assert "late-exact" not in output
    assert emitter.exact_candidate_census().current_rows == 0


@pytest.mark.parametrize("threaded", [False, True])
def test_windows_prior_ordinary_equal_time_candidate_precedes_exact_candidate(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Exact registration drains prior FIFO work before reserving journal sequences."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        threaded=threaded,
        source_finalization=True,
    )
    timestamp = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)
    emitter.emit_event(_event(timestamp, "ordinary-first"))
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(timestamp, "exact-second")))
    batch.commit()
    batch.release_no_fail()

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    output = (
        tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    ).read_text(encoding="utf-8")
    assert output.index("ordinary-first") < output.index("exact-second")


def test_windows_exact_candidate_capacity_failure_cleans_journal_and_reservations(
    tmp_path: Path,
) -> None:
    """A later exact candidate capacity failure removes every precanonical reservation."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
        finalization_row_capacity=1,
    )
    batch = _authority().issue_batch()
    first = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "svc-once")
    second = {**first, "EventID": 4672, "PrivilegeList": "SeSecurityPrivilege"}

    with pytest.raises(SourceFinalizationError, match="row capacity"):
        batch.prepare(lambda: (emitter.emit_event(first), emitter.emit_event(second)))

    census = emitter.source_finalization_census()
    assert (census.candidate_rows, census.candidate_bytes) == (0, 0)
    exact_census = emitter.exact_candidate_census()
    assert (
        exact_census.current_rows,
        exact_census.current_bytes,
        exact_census.current_participants,
    ) == (0, 0, 0)
    with emitter._file_lock:
        assert emitter._spool_conn is None
    batch.cancel()
    emitter.close()


def test_exact_chunk_retries_checkpoint_and_release_without_duplicate_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _SingleHostWriter(tmp_path / "exact.log")
    publisher = ExactChunkPublisher(_authority())
    epoch = SourceFinalizationEpoch()
    checkpointed = False
    checkpoint_attempts = 0

    def checkpoint() -> None:
        nonlocal checkpointed, checkpoint_attempts
        checkpoint_attempts += 1
        if checkpoint_attempts == 1:
            raise RuntimeError("checkpoint return lost")
        checkpointed = True

    original_release = ExactPublicationBatch.release_no_fail
    release_return_lost = True

    def release_then_raise(batch: ExactPublicationBatch) -> None:
        nonlocal release_return_lost
        original_release(batch)
        if release_return_lost:
            release_return_lost = False
            raise RuntimeError("release return lost")

    monkeypatch.setattr(ExactPublicationBatch, "release_no_fail", release_then_raise)
    rows = (ExactSourceRow(writer=writer, content="one"),)
    with pytest.raises(RuntimeError, match="checkpoint return lost"):
        publisher.publish_chunk(
            epoch,
            0,
            rows,
            is_checkpointed=lambda: checkpointed,
            checkpoint=checkpoint,
        )
    with pytest.raises(RuntimeError, match="release return lost"):
        publisher.resume(epoch)
    publisher.resume(epoch)

    assert (tmp_path / "exact.log").read_text(encoding="utf-8") == "one\n"
    assert publisher.census().active_child == 0


def test_windows_exact_commit_lost_return_reuses_retained_epoch_and_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once"))
    emitter.quiesce_source_finalization()
    epoch = emitter.seal_source_finalization()
    publisher = ExactChunkPublisher(_authority())
    original_commit = ExactPublicationBatch.commit
    commit_return_lost = True

    def commit_then_raise(batch: ExactPublicationBatch) -> object:
        nonlocal commit_return_lost
        result = original_commit(batch)
        if commit_return_lost:
            commit_return_lost = False
            raise RuntimeError("commit return lost")
        return result

    monkeypatch.setattr(ExactPublicationBatch, "commit", commit_then_raise)
    with pytest.raises(RuntimeError, match="commit return lost"):
        emitter.publish_source_finalization(epoch, publisher)
    assert publisher.census().active_child == 1
    assert emitter.seal_source_finalization() is epoch

    emitter.publish_source_finalization(epoch, publisher)
    emitter.close()
    path = tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    assert path.read_text(encoding="utf-8").count("once") == 1


def test_windows_seal_and_checkpoint_commit_lost_returns_reconcile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once"))
    emitter.quiesce_source_finalization()
    original_commit = emitter._commit_journal_unlocked
    seal_return_lost = True
    checkpoint_return_lost = True

    def commit_then_raise() -> None:
        nonlocal seal_return_lost, checkpoint_return_lost
        original_commit()
        state = emitter._journal_state_unlocked()
        if state[0] == "sealed" and state[6] == 0 and seal_return_lost:
            seal_return_lost = False
            raise RuntimeError("seal commit return lost")
        if state[0] == "sealed" and state[6] > 0 and checkpoint_return_lost:
            checkpoint_return_lost = False
            raise RuntimeError("checkpoint commit return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", commit_then_raise)
    epoch = emitter.seal_source_finalization()
    assert emitter.seal_source_finalization() is epoch
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()

    assert not seal_return_lost
    assert not checkpoint_return_lost


def test_windows_candidate_commit_lost_return_adopts_exact_rows_and_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once"))
    original_commit = emitter._commit_journal_unlocked
    candidate_return_lost = True

    def commit_then_raise() -> None:
        nonlocal candidate_return_lost
        original_commit()
        state = emitter._journal_state_unlocked()
        if state[0] == "candidate" and state[1] == 1 and candidate_return_lost:
            candidate_return_lost = False
            raise RuntimeError("candidate commit return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", commit_then_raise)
    emitter.quiesce_source_finalization()

    assert not candidate_return_lost
    assert emitter._spool_sequence == 1
    assert emitter._event_dicts == []
    with emitter._file_lock:
        assert emitter._journal_state_unlocked()[1] == 1
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


def test_windows_terminal_seal_sorts_late_earlier_row_and_uses_exact_writer(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "output"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_dir,
        buffer_size=1,
        source_finalization=True,
    )
    later = datetime(2024, 1, 15, 10, 30, 20, tzinfo=UTC)
    emitter.emit_event(_event(later, "later"))
    emitter.barrier_flush()
    assert not output_dir.exists()
    emitter.emit_event(_event(later - timedelta(seconds=10), "earlier"))

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    path = output_dir / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    content_before_footer = path.read_text(encoding="utf-8")
    assert content_before_footer.index("earlier") < content_before_footer.index("later")
    assert "</Events>" not in content_before_footer
    assert coordinator.publisher.census().active_child == 0

    emitter.close()
    content = path.read_text(encoding="utf-8")
    assert content.endswith("</Events>\n")
    assert emitter.source_finalization_census().final_rows == 0
    assert not list(tmp_path.glob("**/.windows_event_spool_*.sqlite3"))


@pytest.mark.parametrize(
    ("target", "filename", "expected_digest"),
    [
        (
            OutputTarget.DEFAULT,
            "windows_event_security.xml",
            "9ec121916c848dda0fd0f166a73bae1af440e9dfd6b3012dbcbbbc39e97fdbba",
        ),
        (
            OutputTarget.SPLUNK,
            "windows_event_security.xml",
            "9ccf838f378962e4d6de9522a8bd65e5036f3e6c9a5838453733d0b4ca64a06f",
        ),
        (
            OutputTarget.SOF_ELK,
            "windows_event_security_snare.log",
            "d6cdf8ebc88d3c170841f7cd3d0e0b35f8f336105ff34e6262172e90e1ef9124",
        ),
    ],
)
def test_windows_exact_abort_and_direct_legacy_bytes_match_immutable_parent_hashes(
    tmp_path: Path,
    target: OutputTarget,
    filename: str,
    expected_digest: str,
) -> None:
    timestamp = datetime(2024, 1, 15, 10, 30, 20, tzinfo=UTC)
    direct_path = tmp_path / "direct" / "windows.xml"
    direct = WindowsEventEmitter(
        load_format("windows_event_security"),
        direct_path,
        buffer_size=1,
    )
    direct.configure_output_target(target)
    direct.emit_event(_event(timestamp, "later"))
    direct.emit_event(_event(timestamp - timedelta(seconds=10), "earlier"))
    direct.close()
    direct_output = (
        direct_path.with_name(filename) if target == OutputTarget.SOF_ELK else direct_path
    )

    exact_root = tmp_path / "exact"
    exact = WindowsEventEmitter(
        load_format("windows_event_security"),
        exact_root,
        buffer_size=1,
        source_finalization=True,
    )
    exact.configure_output_target(target)
    candidate_batch = _authority().issue_batch()
    candidate_batch.prepare(
        lambda: (
            exact.emit_event(_event(timestamp, "later")),
            exact.emit_event(_event(timestamp - timedelta(seconds=10), "earlier")),
        )
    )
    candidate_batch.commit()
    candidate_batch.release_no_fail()
    coordinator = SourceFinalizationCoordinator((exact,), _authority())
    coordinator.finalize()
    exact.close()
    coordinator.mark_closed()
    exact_output = next(exact_root.rglob(filename))

    abort_root = tmp_path / "abort"
    abort = WindowsEventEmitter(
        load_format("windows_event_security"),
        abort_root,
        buffer_size=1,
        source_finalization=True,
    )
    abort.configure_output_target(target)
    abort_batch = _authority().issue_batch()
    abort_batch.prepare(
        lambda: (
            abort.emit_event(_event(timestamp, "later")),
            abort.emit_event(_event(timestamp - timedelta(seconds=10), "earlier")),
        )
    )
    abort_batch.commit()
    abort_batch.release_no_fail()
    abort.close()
    abort_output = next(abort_root.rglob(filename))

    direct_bytes = direct_output.read_bytes()
    exact_bytes = exact_output.read_bytes()
    abort_bytes = abort_output.read_bytes()
    assert exact_bytes == direct_bytes
    assert abort_bytes == direct_bytes
    assert hashlib.sha256(exact_bytes).hexdigest() == expected_digest
    assert hashlib.sha256(abort_bytes).hexdigest() == expected_digest


@pytest.mark.parametrize(
    ("threaded", "buffer_size"),
    [(False, 1), (False, 100), (True, 1), (True, 100)],
)
def test_windows_default_exact_bytes_are_thread_and_buffer_invariant(
    tmp_path: Path,
    threaded: bool,
    buffer_size: int,
) -> None:
    output_root = tmp_path / f"output-{threaded}-{buffer_size}"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_root,
        buffer_size=buffer_size,
        threaded=threaded,
        source_finalization=True,
    )
    timestamp = datetime(2024, 1, 15, 10, 30, 20, tzinfo=UTC)
    emitter.emit_event(_event(timestamp, "later"))
    candidate_batch = _authority().issue_batch()
    candidate_batch.prepare(
        lambda: emitter.emit_event(_event(timestamp - timedelta(seconds=10), "earlier"))
    )
    candidate_batch.commit()
    candidate_batch.release_no_fail()
    assert not output_root.exists()
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()

    output = output_root / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    assert (
        hashlib.sha256(output.read_bytes()).hexdigest()
        == "9ec121916c848dda0fd0f166a73bae1af440e9dfd6b3012dbcbbbc39e97fdbba"
    )


def test_real_generation_engine_generate_uses_windows_source_coordinator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)

    def focused_baseline(**_kwargs: object) -> None:
        emitter = engine.emitters["windows_event_security"]
        emitter.emit_event(_event(engine.start_time + timedelta(seconds=20), "later"))
        emitter.barrier_flush()
        emitter.emit_event(_event(engine.start_time + timedelta(seconds=10), "earlier"))

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    engine.generate()

    coordinator = engine._source_finalization_coordinator
    authority = engine._source_finalization_authority
    assert coordinator is not None and coordinator.complete
    assert authority is not None
    census = authority.census()
    assert (
        census.active_batches,
        census.prepared_batches,
        census.retained_rows,
        census.retained_bytes,
    ) == (0, 0, 0, 0)
    emitter = engine.emitters["windows_event_security"]
    assert emitter.source_finalization_census().state == "closed"
    path = tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    content = path.read_text(encoding="utf-8")
    assert content.index("earlier") < content.index("later")


def test_generation_engine_retries_footer_without_reinitializing_or_regenerating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    baseline_calls = 0

    def focused_baseline(**_kwargs: object) -> None:
        nonlocal baseline_calls
        baseline_calls += 1
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "once")
        )

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    original_footer = _SingleHostWriter.write_footer
    footer_return_lost = True

    def footer_then_raise(writer: _SingleHostWriter, footer: str) -> None:
        nonlocal footer_return_lost
        original_footer(writer, footer)
        if footer_return_lost:
            footer_return_lost = False
            raise RuntimeError("footer return lost")

    monkeypatch.setattr(_SingleHostWriter, "write_footer", footer_then_raise)
    with pytest.raises(RuntimeError, match="footer return lost"):
        engine.generate()
    retained_coordinator = engine._source_finalization_coordinator
    assert retained_coordinator is not None
    assert retained_coordinator.publication_complete
    assert not retained_coordinator.complete

    engine.generate()

    assert baseline_calls == 1
    assert engine._source_finalization_coordinator is retained_coordinator
    assert retained_coordinator.complete
    path = tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    assert path.read_text(encoding="utf-8").count("</Events>") == 1


def test_generation_engine_resumes_exact_commit_from_a_different_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)

    def focused_baseline(**_kwargs: object) -> None:
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "once")
        )

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    original_commit = ExactPublicationBatch.commit
    lost_return = True

    def commit_then_raise(batch: ExactPublicationBatch) -> object:
        nonlocal lost_return
        result = original_commit(batch)
        if lost_return:
            lost_return = False
            raise RuntimeError("cross-thread commit return lost")
        return result

    monkeypatch.setattr(ExactPublicationBatch, "commit", commit_then_raise)
    errors: list[BaseException] = []

    def first_generate() -> None:
        try:
            engine.generate()
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=first_generate)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert len(errors) == 1 and "cross-thread commit return lost" in str(errors[0])

    engine.generate()
    assert engine._source_finalization_coordinator.complete
    path = tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    assert path.read_text(encoding="utf-8").count("once") == 1


def test_generation_failure_uses_terminal_aborted_legacy_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)

    def failing_baseline(**_kwargs: object) -> None:
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "partial")
        )
        raise ValueError("body failed")

    monkeypatch.setattr(engine, "_generate_baseline", failing_baseline)
    with pytest.raises(ValueError, match="body failed"):
        engine.generate()

    coordinator = engine._source_finalization_coordinator
    emitter = engine.emitters["windows_event_security"]
    assert coordinator is not None and not coordinator.publication_complete
    assert emitter.source_finalization_census().state == "aborted"
    retained = coordinator
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        engine.generate()
    assert engine._source_finalization_coordinator is retained


def test_generation_abort_cleanup_failure_retries_cleanup_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    baseline_calls = 0
    close_calls = 0

    def failing_baseline(**_kwargs: object) -> None:
        nonlocal baseline_calls
        baseline_calls += 1
        emitter = engine.emitters["windows_event_security"]
        original_close = emitter.close

        def fail_close_once() -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                raise OSError("abort close failed")
            original_close()

        monkeypatch.setattr(emitter, "close", fail_close_once)
        emitter.emit_event(_event(engine.start_time + timedelta(seconds=10), "partial"))
        raise ValueError("body failed")

    monkeypatch.setattr(engine, "_generate_baseline", failing_baseline)
    with pytest.raises(ValueError, match="body failed"):
        engine.generate()
    assert engine._finalization_aborted
    assert not engine._finalization_complete

    with pytest.raises(RuntimeError, match="cannot be restarted"):
        engine.generate()
    assert engine._finalization_complete
    assert baseline_calls == 1
    assert close_calls == 2
    assert engine.emitters["windows_event_security"].source_finalization_census().state == "aborted"


def test_generation_hostile_primary_and_progress_failure_cannot_skip_abort_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class HostilePrimaryError(RuntimeError):
        def add_note(self, note: str) -> None:
            raise AssertionError(f"hostile add_note: {note}")

    def progress(event_type: str, data: dict[str, object]) -> None:
        if event_type == "phase_start" and data.get("phase") == "finalize":
            raise OSError("progress failed")

    engine = GenerationEngine(
        _scenario(),
        tmp_path / "output",
        scenario_root=tmp_path,
        progress_callback=progress,
    )

    def failing_baseline(**_kwargs: object) -> None:
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "partial")
        )
        raise HostilePrimaryError("hostile body failure")

    monkeypatch.setattr(engine, "_generate_baseline", failing_baseline)
    with pytest.raises(HostilePrimaryError, match="hostile body failure"):
        engine.generate()

    assert engine._finalization_complete
    assert engine.emitters["windows_event_security"].source_finalization_census().state == "aborted"


def test_generation_engine_rejects_concurrent_and_reentrant_generate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reentrant_errors: list[BaseException] = []
    engine: GenerationEngine

    def progress(event_type: str, data: dict[str, object]) -> None:
        if event_type == "phase_start" and data.get("phase") == "initialize":
            try:
                engine.generate()
            except BaseException as error:
                reentrant_errors.append(error)

    engine = GenerationEngine(
        _scenario(),
        tmp_path / "output",
        scenario_root=tmp_path,
        progress_callback=progress,
    )
    original_initialize = engine._initialize
    initialized = Event()
    release = Event()

    def blocking_initialize() -> None:
        original_initialize()
        initialized.set()
        if not release.wait(timeout=5):
            raise AssertionError("initialize release timed out")

    monkeypatch.setattr(engine, "_initialize", blocking_initialize)
    monkeypatch.setattr(engine, "_generate_baseline", lambda **_kwargs: None)
    errors: list[BaseException] = []

    def run_generate() -> None:
        try:
            engine.generate()
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=run_generate)
    worker.start()
    assert initialized.wait(timeout=5)
    with pytest.raises(RuntimeError, match="concurrently or re-enter"):
        engine.generate()
    release.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert errors == []
    assert len(reentrant_errors) == 1
    assert "concurrently or re-enter" in str(reentrant_errors[0])


def test_generation_ids_summary_is_applied_once_across_later_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    apply_calls = 0
    manifest_calls = 0
    close_calls = 0

    class FakeSnort:
        ids_alert_summary = {"cluster": {1: {"emitted_visible": 1}}}
        ids_evaluation_summary = None

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls > 1:
                raise AssertionError("closed fake Snort emitter was closed twice")

    def focused_baseline(**_kwargs: object) -> None:
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "once")
        )
        engine.emitters["snort_alert"] = FakeSnort()

        def manifest_fails_once() -> None:
            nonlocal manifest_calls
            manifest_calls += 1
            if manifest_calls == 1:
                raise OSError("artifact manifest failed")

        monkeypatch.setattr(
            engine.activity_generator,
            "write_artifacts_manifest",
            manifest_fails_once,
        )

    def count_summary(summary: object) -> None:
        nonlocal apply_calls
        apply_calls += 1

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    monkeypatch.setattr(engine, "_apply_ids_alert_summary", count_summary)
    with pytest.raises(OSError, match="artifact manifest failed"):
        engine.generate()
    engine.generate()

    assert apply_calls == 1
    assert manifest_calls == 2
    assert close_calls == 1


def test_generation_partial_emitter_close_retries_only_failed_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    successful_close_calls = 0
    retry_close_calls = 0

    class NonIdempotentEmitter:
        def close(self) -> None:
            nonlocal successful_close_calls
            successful_close_calls += 1
            if successful_close_calls > 1:
                raise AssertionError("successful emitter close was retried")

    class RetryEmitter:
        def close(self) -> None:
            nonlocal retry_close_calls
            retry_close_calls += 1
            if retry_close_calls == 1:
                raise OSError("one emitter close failed")

    retry_emitter = RetryEmitter()

    def focused_baseline(**_kwargs: object) -> None:
        engine.emitters["windows_event_security"].emit_event(
            _event(engine.start_time + timedelta(seconds=10), "once")
        )
        engine.emitters["non_idempotent"] = NonIdempotentEmitter()
        engine.emitters["retry"] = retry_emitter

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    with pytest.raises(OSError, match="one emitter close failed"):
        engine.generate()
    coordinator = engine._source_finalization_coordinator
    assert coordinator is not None and coordinator.publication_complete
    assert not coordinator.complete

    engine.emitters["retry"] = RetryEmitter()
    with pytest.raises(RuntimeError, match="changed identity"):
        engine.generate()
    assert retry_close_calls == 1
    assert not coordinator.complete

    engine.emitters["retry"] = retry_emitter
    engine.generate()

    assert successful_close_calls == 1
    assert retry_close_calls == 2
    assert coordinator.complete


def test_generation_failure_after_emitter_initialization_closes_created_emitters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    original_init_emitters = engine._init_emitters

    def initialize_then_fail() -> None:
        original_init_emitters()
        raise OSError("post-emitter initialization failed")

    monkeypatch.setattr(engine, "_init_emitters", initialize_then_fail)
    with pytest.raises(OSError, match="post-emitter initialization failed"):
        engine.generate()

    emitter = engine.emitters["windows_event_security"]
    assert engine._finalization_aborted and engine._finalization_complete
    assert emitter.source_finalization_census().state == "aborted"
    assert not emitter._thread.is_alive()
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        engine.generate()


def test_generation_partial_emitter_construction_failure_closes_prior_emitter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.engine import emitter_setup as emitter_setup_module

    scenario = _scenario().model_copy(
        update={
            "output": OutputSpec(
                logs=[
                    {"format": "windows_event_security"},
                    {"format": "zeek_conn"},
                ],
                destination="./output",
                compression=False,
            )
        }
    )

    def fail_zeek_construction(*args: object, **kwargs: object) -> None:
        raise OSError("second emitter construction failed")

    monkeypatch.setattr(emitter_setup_module, "ZeekEmitter", fail_zeek_construction)
    engine = GenerationEngine(scenario, tmp_path / "output", scenario_root=tmp_path)
    with pytest.raises(OSError, match="second emitter construction failed"):
        engine.generate()

    emitter = engine.emitters["windows_event_security"]
    assert emitter.source_finalization_census().state == "aborted"
    assert not emitter._thread.is_alive()
    assert engine._finalization_aborted and engine._finalization_complete


def test_generation_initialize_progress_failure_still_closes_emitters(
    tmp_path: Path,
) -> None:
    def progress(event_type: str, data: dict[str, object]) -> None:
        if event_type == "phase_end" and data.get("phase") == "initialize":
            raise OSError("initialize progress failed")

    engine = GenerationEngine(
        _scenario(),
        tmp_path / "output",
        scenario_root=tmp_path,
        progress_callback=progress,
    )
    with pytest.raises(OSError, match="initialize progress failed"):
        engine.generate()

    emitter = engine.emitters["windows_event_security"]
    assert emitter.source_finalization_census().state == "aborted"
    assert not emitter._thread.is_alive()
    assert engine._finalization_complete


def test_windows_quiesce_rejects_late_admission_and_unpublished_close(tmp_path: Path) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    emitter.quiesce_source_finalization()

    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "late"))
    with pytest.raises(SourceFinalizationError, match="cannot legacy-render"):
        emitter.close()


def test_threaded_barrier_admission_cannot_race_quiesce_into_dead_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=100,
        threaded=True,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    entered_flush = Event()
    release_flush = Event()
    original_flush = emitter._flush_at_barrier

    def blocking_flush() -> None:
        entered_flush.set()
        if not release_flush.wait(timeout=5):
            raise AssertionError("barrier release timed out")
        original_flush()

    monkeypatch.setattr(emitter, "_flush_at_barrier", blocking_flush)
    barrier_errors: list[BaseException] = []
    finalization_errors: list[BaseException] = []

    def run_barrier() -> None:
        try:
            emitter.barrier_flush()
        except BaseException as error:
            barrier_errors.append(error)

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())

    def run_finalization() -> None:
        try:
            coordinator.finalize()
            emitter.close()
            coordinator.mark_closed()
        except BaseException as error:
            finalization_errors.append(error)

    barrier_thread = Thread(target=run_barrier)
    barrier_thread.start()
    assert entered_flush.wait(timeout=5)
    finalization_thread = Thread(target=run_finalization)
    finalization_thread.start()
    finalization_thread.join(timeout=0.1)
    assert finalization_thread.is_alive()
    with pytest.raises(SourceFinalizationError, match="already has an owner"):
        coordinator.finalize()
    release_flush.set()
    barrier_thread.join(timeout=5)
    finalization_thread.join(timeout=5)

    assert not barrier_thread.is_alive()
    assert not finalization_thread.is_alive()
    assert barrier_errors == []
    assert finalization_errors == []
    assert coordinator.complete


@pytest.mark.parametrize("failure_mode", ["transient", "permanent"])
def test_threaded_spool_failure_with_later_queued_row_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    output_root = tmp_path / "output"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_root,
        buffer_size=1,
        threaded=True,
        source_finalization=True,
    )
    entered_spool = Event()
    release_spool = Event()
    attempts = 0

    def failing_spool() -> None:
        nonlocal attempts
        attempts += 1
        entered_spool.set()
        if not release_spool.wait(timeout=5):
            raise AssertionError("spool failure release timed out")
        if failure_mode == "permanent" or attempts == 1:
            raise OSError(f"{failure_mode} spool failure")

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", failing_spool)
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    assert entered_spool.wait(timeout=5)
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "later-queued"))
    release_spool.set()
    emitter._thread.join(timeout=5)
    assert not emitter._thread.is_alive()

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        coordinator.finalize()
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        coordinator.finalize()
    assert emitter._event_queue.qsize() == 1
    assert len(emitter._event_dicts) == 1
    assert not output_root.exists()
    assert not coordinator.publication_complete


def test_windows_epoch_freezes_target_and_footer_contract(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_dir,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    emitter.quiesce_source_finalization()
    with pytest.raises(SourceFinalizationError, match="cannot change"):
        emitter.configure_output_target(OutputTarget.SPLUNK)
    emitter.output_target = OutputTarget.SPLUNK
    epoch = emitter.seal_source_finalization()
    publisher = ExactChunkPublisher(_authority())
    emitter.publish_source_finalization(epoch, publisher)
    emitter.close()

    path = output_dir / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    content = path.read_text(encoding="utf-8")
    assert content.startswith("<?xml")
    assert content.endswith("</Events>\n")


def test_windows_exact_capability_refusal_is_constructor_failure_neutral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters import windows as windows_module

    monkeypatch.setattr(windows_module, "_NOFOLLOW", 0)
    with pytest.raises(ExactPublicationError, match="requires POSIX"):
        WindowsEventEmitter(
            load_format("windows_event_security"),
            tmp_path / "output",
            source_finalization=True,
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("capacity_kwargs", "expected_message"),
    [
        ({"finalization_row_capacity": 1}, "row capacity"),
        ({"finalization_byte_capacity": 16}, "byte capacity"),
    ],
)
def test_windows_candidate_caps_refuse_without_partial_admission(
    tmp_path: Path,
    capacity_kwargs: dict[str, int],
    expected_message: str,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
        **capacity_kwargs,
    )
    if "finalization_row_capacity" in capacity_kwargs:
        emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
        rejected = _event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "second")
        expected_buffered = 1
    else:
        rejected = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first")
        expected_buffered = 0
    before = emitter.source_finalization_census()
    with pytest.raises(SourceFinalizationError, match=expected_message):
        emitter.emit_event(rejected)
    after = emitter.source_finalization_census()

    assert emitter._spool_sequence == 0
    assert len(emitter._event_dicts) == expected_buffered
    assert (after.candidate_rows, after.candidate_bytes) == (
        before.candidate_rows,
        before.candidate_bytes,
    )
    assert after.high_water_rows <= after.row_capacity
    assert after.high_water_bytes <= after.byte_capacity
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("capacity_delta", [-1, 0, 1])
def test_windows_candidate_byte_admission_boundary_is_exact_and_neutral(
    tmp_path: Path,
    capacity_delta: int,
) -> None:
    event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "boundary")
    exact_bytes = len(_spool_encode(event).encode("utf-8"))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
        finalization_byte_capacity=exact_bytes + capacity_delta,
    )

    if capacity_delta < 0:
        with pytest.raises(SourceFinalizationError, match="byte capacity"):
            emitter.emit_event(event)
        expected = (0, 0)
    else:
        emitter.emit_event(event)
        expected = (1, exact_bytes)
        with pytest.raises(SourceFinalizationError, match="byte capacity"):
            emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "extra"))

    census = emitter.source_finalization_census()
    assert (census.candidate_rows, census.candidate_bytes) == expected
    assert (census.high_water_rows, census.high_water_bytes) == expected


def test_windows_exact_admission_detaches_nested_caller_payload(tmp_path: Path) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
    )
    event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "detached")
    event["NestedProbe"] = {"members": ["original"]}
    emitter.emit_event(event)
    event["NestedProbe"]["members"][0] = "mutated"

    emitter.quiesce_source_finalization()
    with emitter._file_lock:
        retained = tuple(emitter._iter_spooled_events_unlocked())
    assert retained[0]["NestedProbe"] == {"members": ["original"]}


def test_windows_nonthreaded_spool_failure_rolls_back_current_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=2,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "retained"))
    original_spool = emitter._spool_event_dicts_unlocked

    def fail_spool() -> None:
        raise OSError("spool failed before durable adoption")

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", fail_spool)
    before = emitter.source_finalization_census()
    with pytest.raises(OSError, match="spool failed"):
        emitter.emit_event(_event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "rejected"))
    after = emitter.source_finalization_census()
    assert (after.candidate_rows, after.candidate_bytes) == (
        before.candidate_rows,
        before.candidate_bytes,
    )
    assert [event["TargetUserName"] for event in emitter._event_dicts] == ["retained"]

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", original_spool)
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    path = tmp_path / "output" / "WIN-TEST-01.corp.local" / "windows_event_security.xml"
    content = path.read_text(encoding="utf-8")
    assert "retained" in content
    assert "rejected" not in content


def test_windows_route_cap_rolls_back_unsealed_final_strings(tmp_path: Path) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
        finalization_route_capacity=1,
    )
    first = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first")
    second = _event(datetime(2024, 1, 15, 10, 31, tzinfo=UTC), "second")
    second["Computer"] = "WIN-TEST-02.corp.local"
    emitter.emit_event(first)
    emitter.emit_event(second)
    emitter.quiesce_source_finalization()
    with pytest.raises(SourceFinalizationError, match="route capacity"):
        emitter.seal_source_finalization()

    with emitter._file_lock:
        state = emitter._journal_state_unlocked()
        final_rows = emitter._spool_conn.execute(
            "SELECT COUNT(*) FROM events WHERE phase = ?", ("final",)
        ).fetchone()
    assert state[0] == "candidate"
    assert final_rows == (0,)
    assert not (tmp_path / "output").exists()
    assert emitter._host_writers == {}
    assert emitter._snare_writers == {}
    assert emitter._source_finalization_routes == {}
    assert emitter._source_finalization_route_ids == {}


def test_windows_final_render_growth_respects_byte_cap(tmp_path: Path) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once"))
    emitter.quiesce_source_finalization()
    with emitter._file_lock:
        candidate_bytes = int(emitter._journal_state_unlocked()[2])
    emitter._finalization_byte_capacity = candidate_bytes
    with pytest.raises(SourceFinalizationError, match="byte capacity"):
        emitter.seal_source_finalization()
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("missing_host", [False, True])
def test_windows_empty_or_unrouted_cohort_has_no_public_output(
    tmp_path: Path,
    missing_host: bool,
) -> None:
    output_root = tmp_path / "output"
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_root,
        source_finalization=True,
    )
    if missing_host:
        event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once")
        event["Computer"] = ""
        emitter.emit_event(event)
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    assert not output_root.exists()
    assert emitter.source_finalization_census().final_rows == 0
    emitter.close()
    coordinator.mark_closed()
    assert coordinator.complete


def test_windows_multi_chunk_publication_has_bounded_and_zero_terminal_census(
    tmp_path: Path,
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=50,
        source_finalization=True,
    )
    start = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
    for index in range(513):
        emitter.emit_event(_event(start + timedelta(seconds=index), f"user-{index}"))
    authority = _authority()
    coordinator = SourceFinalizationCoordinator((emitter,), authority)
    coordinator.finalize()
    publisher_census = coordinator.publisher.census()
    authority_census = authority.census()

    assert publisher_census.active_child == 0
    assert publisher_census.high_water_rows <= 512
    assert publisher_census.high_water_bytes <= publisher_census.byte_capacity
    assert publisher_census.high_water_routes <= publisher_census.route_capacity
    assert authority_census.high_water_batches == 1
    assert authority_census.high_water_rows <= 512
    assert (
        authority_census.active_batches,
        authority_census.prepared_batches,
        authority_census.retained_rows,
        authority_census.retained_bytes,
    ) == (0, 0, 0, 0)
    emitter.close()
    coordinator.mark_closed()
    census = emitter.source_finalization_census()
    assert (
        census.candidate_rows,
        census.candidate_bytes,
        census.final_rows,
        census.final_bytes,
        census.routes,
        census.published_rows,
    ) == (0, 0, 0, 0, 0, 0)
    assert 0 < census.high_water_rows <= census.row_capacity
    assert 0 < census.high_water_bytes <= census.byte_capacity
    assert 0 < census.high_water_routes <= census.route_capacity


def test_windows_private_leaf_cleanup_retries_rmdir_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool_root = tmp_path / "spool-root"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    SourceFinalizationCoordinator((emitter,), _authority()).finalize()

    original_rmdir = os.rmdir
    lost_return = True

    def rmdir_then_raise(path: str | bytes, *, dir_fd: int | None = None) -> None:
        nonlocal lost_return
        original_rmdir(path, dir_fd=dir_fd)
        if lost_return and dir_fd is not None:
            lost_return = False
            raise OSError("rmdir return lost")

    monkeypatch.setattr(os, "rmdir", rmdir_then_raise)
    with pytest.raises(OSError, match="rmdir return lost"):
        emitter.close()
    emitter.close()

    assert list(spool_root.iterdir()) == []
    assert emitter.source_finalization_census().state == "closed"


def test_windows_private_root_fsync_lost_return_retries_without_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool_root = tmp_path / "spool-root"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "first"))
    SourceFinalizationCoordinator((emitter,), _authority()).finalize()
    root_descriptor = emitter._spool_root_descriptor
    assert root_descriptor is not None
    original_fsync = os.fsync
    lost_return = True

    def fsync_then_raise(descriptor: int) -> None:
        nonlocal lost_return
        original_fsync(descriptor)
        if lost_return and descriptor == root_descriptor:
            lost_return = False
            raise OSError("root fsync return lost")

    monkeypatch.setattr(os, "fsync", fsync_then_raise)
    with pytest.raises(OSError, match="root fsync return lost"):
        emitter.close()
    emitter.close()

    assert list(spool_root.iterdir()) == []
    assert emitter.source_finalization_census().state == "closed"


def test_windows_private_leaf_mkdir_lost_return_is_adopted_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters import windows as windows_module

    private_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(private_root))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    original_mkdir = windows_module.os.mkdir
    lost_return = True

    def mkdir_then_raise(path: str, *args: object, **kwargs: object) -> None:
        nonlocal lost_return
        original_mkdir(path, *args, **kwargs)
        if lost_return and str(path).startswith("evidenceforge-windows-spool-"):
            lost_return = False
            raise OSError("leaf mkdir return lost")

    monkeypatch.setattr(windows_module.os, "mkdir", mkdir_then_raise)
    event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once")
    with pytest.raises(OSError, match="leaf mkdir return lost"):
        emitter.emit_event(event)
    assert emitter._spool_initialization_pending
    assert len(list(private_root.iterdir())) == 1

    emitter.emit_event(event)
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    assert list(private_root.iterdir()) == []


def test_windows_private_journal_open_lost_return_is_adopted_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters import windows as windows_module

    private_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(private_root))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    original_open = windows_module.os.open
    lost_return = True

    def open_then_raise(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal lost_return
        descriptor = original_open(path, flags, *args, **kwargs)
        if lost_return and flags & os.O_CREAT and str(path).startswith(".windows_event_spool_"):
            lost_return = False
            os.close(descriptor)
            raise OSError("journal open return lost")
        return descriptor

    monkeypatch.setattr(windows_module.os, "open", open_then_raise)
    event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once")
    with pytest.raises(OSError, match="journal open return lost"):
        emitter.emit_event(event)
    assert emitter._spool_file_initialization_pending
    assert emitter._spool_file_identity is not None

    emitter.emit_event(event)
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    assert list(private_root.iterdir()) == []


def test_windows_private_journal_schema_lost_return_is_adopted_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "private-spool"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(private_root))
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    original_initialize = emitter._initialize_spool_schema_unlocked
    lost_return = True

    def schema_then_raise(connection: object) -> None:
        nonlocal lost_return
        original_initialize(connection)
        if lost_return:
            lost_return = False
            raise OSError("schema initialization return lost")

    monkeypatch.setattr(emitter, "_initialize_spool_schema_unlocked", schema_then_raise)
    event = _event(datetime(2024, 1, 15, 10, 30, tzinfo=UTC), "once")
    with pytest.raises(OSError, match="schema initialization return lost"):
        emitter.emit_event(event)
    assert emitter._spool_file_initialization_pending
    assert emitter._spool_conn is not None

    emitter.emit_event(event)
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    assert list(private_root.iterdir()) == []
