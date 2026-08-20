# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact sorted-publication coverage for Linux Syslog output."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import syslog as syslog_module
from evidenceforge.generation.emitters.base import ExactPublicationAuthority, ExactPublicationError
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from tests.unit.test_syslog_family_renderer import _samba_event

_HOST = "linux01.example.test"
_START = datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC)
_PARENT_HASHES = {
    "default": "5de2cd128d108294f112c27adc8e20d4b4ca1430efeee10b154d21e1295bc993",
    "splunk": "5de2cd128d108294f112c27adc8e20d4b4ca1430efeee10b154d21e1295bc993",
    "sof-elk": "98f0e3fc962c32df9624ac3e706f3c27eb309a915724c339187ed516083da692",
}


def _event(offset: int, message: str) -> dict[str, object]:
    return {
        "timestamp": _START + timedelta(seconds=offset),
        "hostname": "linux01",
        "app_name": "sshd",
        "pid": 1234,
        "facility": 10,
        "severity": 6,
        "message": message,
        "_host_fqdn": _HOST,
    }


def _logind_event(hostname: str, offset: int) -> dict[str, object]:
    return {
        "timestamp": _START + timedelta(seconds=offset),
        "hostname": hostname,
        "app_name": "systemd-logind",
        "pid": 777,
        "facility": 3,
        "severity": 6,
        "message": "New session 2 of user alice.",
        "_host_fqdn": f"{hostname}.example.test",
    }


def _output_path(root: Path, target: str) -> Path:
    if target == "sof-elk":
        return root / _HOST / "2026" / "syslog.log"
    return root / _HOST / "syslog.log"


def _descriptor_has_identity(
    descriptor: int | None,
    identity: tuple[int, int] | None,
) -> bool:
    if descriptor is None or identity is None:
        return False
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        return False
    return (int(metadata.st_dev), int(metadata.st_ino)) == identity


def _stream_has_identity(stream: Any | None, identity: tuple[int, int] | None) -> bool:
    if stream is None or stream.closed:
        return False
    return _descriptor_has_identity(stream.fileno(), identity)


def _retained_storage_descriptor_count(
    storage: Any | None,
    identity: tuple[int, int] | None,
) -> int:
    if type(storage) is syslog_module._SyslogDescriptorOwner:
        return _owner_descriptor_count(storage, identity)
    return int(_stream_has_identity(storage, identity))


def _owner_descriptor_count(owner: Any | None, identity: tuple[int, int] | None) -> int:
    if owner is None or owner.closed:
        return 0
    return sum(
        _descriptor_has_identity(descriptor, identity)
        for descriptor in (owner.descriptor, owner.guard_descriptor)
    )


def _owned_descriptor_census(emitter: SyslogEmitter) -> dict[str, int]:
    """Count only descriptors still bound to each retained Syslog owner class."""

    return {
        "private_journal": _retained_storage_descriptor_count(
            emitter._spool_stream,
            emitter._spool_identity,
        ),
        "private_snapshot": int(
            _stream_has_identity(emitter._spool_snapshot, emitter._spool_snapshot_identity)
        ),
        "final_candidate": sum(
            _stream_has_identity(candidate.stream, candidate.candidate_identity)
            for candidate in emitter._final_candidates.values()
        ),
        "public_file": sum(
            _owner_descriptor_count(append.descriptor_owner, append.file_identity)
            for append in emitter._public_appends.values()
        ),
        "public_parent": sum(
            _owner_descriptor_count(append.parent_owner, append.parent_identity)
            for append in emitter._public_appends.values()
        ),
    }


def _no_owned_descriptors() -> dict[str, int]:
    return {
        "private_journal": 0,
        "private_snapshot": 0,
        "final_candidate": 0,
        "public_file": 0,
        "public_parent": 0,
    }


def _render_ordinary(root: Path, target: str) -> bytes:
    emitter = SyslogEmitter(load_format("syslog"), root, buffer_size=1)
    emitter.configure_output_target(target)
    emitter.emit_event(_event(2, "third"))
    emitter.emit_event(_event(0, "first"))
    emitter.emit_event(_event(1, "second"))
    emitter.close()
    return _output_path(root, target).read_bytes()


def _render_exact(root: Path, target: str, *, threaded: bool) -> bytes:
    emitter = SyslogEmitter(
        load_format("syslog"),
        root,
        buffer_size=1,
        threaded=threaded,
    )
    emitter.configure_output_target(target)
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit_event(_event(2, "third")),
            emitter.emit_event(_event(0, "first")),
            emitter.emit_event(_event(1, "second")),
        )
    )
    prepared = emitter.exact_candidate_census()
    assert prepared.reserved_rows == 3 and prepared.admitted_rows == 0
    assert emitter._writers == {}
    assert not _output_path(root, target).exists()
    batch.commit()
    batch.release_no_fail()
    emitter.close()
    assert authority.census().active_batches == 0
    return _output_path(root, target).read_bytes()


@pytest.mark.parametrize("target", ("default", "splunk", "sof-elk"))
@pytest.mark.parametrize("threaded", (False, True))
def test_syslog_exact_sorted_rows_match_ordinary_bytes(
    tmp_path: Path,
    target: str,
    threaded: bool,
) -> None:
    """Exact admission preserves target rendering and terminal timestamp order."""

    ordinary = _render_ordinary(tmp_path / "ordinary", target)
    exact = _render_exact(tmp_path / "exact", target, threaded=threaded)
    assert exact == ordinary
    assert hashlib.sha256(exact).hexdigest() == _PARENT_HASHES[target]
    assert exact.find(b"first") < exact.find(b"second") < exact.find(b"third")


@pytest.mark.parametrize("hash_seed", ("1", "777"))
def test_syslog_exact_fresh_process_hash_seed_parity(
    tmp_path: Path,
    hash_seed: str,
) -> None:
    """Fresh interpreters preserve exact bytes for every target and hash seed."""

    repository = Path(__file__).resolve().parents[2]
    child_root = tmp_path / f"seed-{hash_seed}"
    program = "\n".join(
        (
            "import hashlib",
            "import json",
            "import sys",
            "from pathlib import Path",
            "from tests.unit.test_syslog_exact_publication import _render_exact",
            "root = Path(sys.argv[1])",
            'targets = ("default", "splunk", "sof-elk")',
            "digests = {",
            "    target: hashlib.sha256(",
            "        _render_exact(root / target, target, threaded=True)",
            "    ).hexdigest()",
            "    for target in targets",
            "}",
            "print(json.dumps(digests, sort_keys=True))",
        )
    )
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = hash_seed
    import_roots = (str(repository / "src"), str(repository))
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        (*import_roots, existing_pythonpath) if existing_pythonpath else import_roots
    )
    completed = subprocess.run(
        (sys.executable, "-c", program, str(child_root)),
        cwd=repository,
        env=environment,
        capture_output=True,
        check=True,
        text=True,
    )

    assert json.loads(completed.stdout) == _PARENT_HASHES


def test_syslog_exact_sorted_commit_and_release_lost_returns_are_exact_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sorted journal reconciles admission and receipt-release lost returns."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.configure_output_target("default")
    original_commit = emitter._commit_exact_candidate
    original_release = emitter._release_exact_candidate
    fail_commit = True
    fail_release = True

    def commit_then_raise(key: object, digest: str, frozen: object) -> None:
        nonlocal fail_commit
        original_commit(key, digest, frozen)
        if fail_commit:
            fail_commit = False
            raise OSError("injected sorted commit lost return")

    def release_then_raise(key: object) -> None:
        nonlocal fail_release
        original_release(key)
        if fail_release:
            fail_release = False
            raise OSError("injected sorted release lost return")

    monkeypatch.setattr(emitter, "_commit_exact_candidate", commit_then_raise)
    monkeypatch.setattr(emitter, "_release_exact_candidate", release_then_raise)

    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(0, "one exact row")))
    with pytest.raises(OSError, match="commit lost return"):
        batch.commit()
    batch.commit()
    with pytest.raises(OSError, match="release lost return"):
        batch.release_no_fail()
    batch.release_no_fail()
    before_close = emitter.exact_candidate_census()
    assert before_close.admitted_rows == before_close.released_rows == 1
    emitter.close()

    payload = _output_path(tmp_path, "default").read_text(encoding="utf-8")
    assert payload.count("one exact row") == 1
    assert authority.census().active_batches == 0
    closed = emitter.exact_candidate_census()
    assert closed.admitted_rows == closed.admitted_bytes == 0


def test_syslog_barrier_never_exports_pre_normalization_exact_rows(tmp_path: Path) -> None:
    """A generation barrier spills privately and leaves exact rows for terminal close."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.configure_output_target("default")
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(0, "barrier row")))
    batch.commit()
    batch.release_no_fail()

    emitter.flush(force=True)
    assert not _output_path(tmp_path, "default").exists()
    census = emitter.exact_candidate_census()
    assert census.admitted_rows == census.released_rows == 1

    emitter.close()
    assert _output_path(tmp_path, "default").read_text(encoding="utf-8").count("barrier row") == 1


def test_syslog_terminal_normalization_lost_return_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-replace close failure retries from the durable normalized destination."""

    expected = _render_ordinary(tmp_path / "ordinary", "default")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path / "exact", buffer_size=1)
    emitter.configure_output_target("default")
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit_event(_event(2, "third")),
            emitter.emit_event(_event(0, "first")),
            emitter.emit_event(_event(1, "second")),
        )
    )
    batch.commit()
    batch.release_no_fail()

    original_publish = SyslogEmitter._publish_final_candidate
    fail_after_replace = True

    def publish_then_raise(instance: SyslogEmitter, retained: object) -> None:
        nonlocal fail_after_replace
        original_publish(instance, retained)
        if fail_after_replace:
            fail_after_replace = False
            raise OSError("injected syslog normalization lost return")

    monkeypatch.setattr(
        SyslogEmitter,
        "_publish_final_candidate",
        publish_then_raise,
    )
    with pytest.raises(OSError, match="normalization lost return"):
        emitter.close()
    late = _event(3, "late row")
    late["_host_fqdn"] = "late.example.test"
    with pytest.raises(RuntimeError, match="terminal close retry"):
        emitter.emit_event(late)
    with pytest.raises(RuntimeError, match="terminal close retry"):
        emitter.flush(force=True)
    emitter.close()

    actual = _output_path(tmp_path / "exact", "default").read_bytes()
    assert actual == expected
    assert actual.count(b"first") == 1
    assert actual.count(b"second") == 1
    assert actual.count(b"third") == 1


def test_syslog_terminal_retry_rejects_or_restores_tampered_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A close retry cannot adopt changed public bytes after a lost return."""

    expected = _render_ordinary(tmp_path / "ordinary", "default")
    exact_root = tmp_path / "exact"
    emitter = SyslogEmitter(load_format("syslog"), exact_root, buffer_size=1)
    emitter.configure_output_target("default")
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit_event(_event(2, "third")),
            emitter.emit_event(_event(0, "first")),
            emitter.emit_event(_event(1, "second")),
        )
    )
    batch.commit()
    batch.release_no_fail()

    original_publish = SyslogEmitter._publish_final_candidate
    fail_after_replace = True

    def publish_then_raise(instance: SyslogEmitter, retained: object) -> None:
        nonlocal fail_after_replace
        original_publish(instance, retained)
        if fail_after_replace:
            fail_after_replace = False
            raise OSError("injected syslog normalization lost return")

    monkeypatch.setattr(
        SyslogEmitter,
        "_publish_final_candidate",
        publish_then_raise,
    )
    with pytest.raises(OSError, match="normalization lost return"):
        emitter.close()

    output = _output_path(exact_root, "default")
    changed = output.read_bytes().replace(b"third", b"thard")
    assert changed != expected and len(changed) == len(expected)
    output.write_bytes(changed)

    with pytest.raises(ExactPublicationError, match="output (?:prefix )?changed"):
        emitter.close()
    assert output.read_bytes() == changed
    output.write_bytes(expected)
    emitter.close()
    assert output.read_bytes() == expected


@pytest.mark.parametrize("threaded", (False, True))
def test_syslog_exact_record_framing_preserves_embedded_crlf(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Exact record framing never splits or reorders an embedded physical line."""

    message = "field=value\r\nforged-entry=value"
    ordinary = SyslogEmitter(load_format("syslog"), tmp_path / "ordinary", buffer_size=1)
    ordinary.emit_event(_event(0, message))
    ordinary.flush(force=True)
    ordinary.close()

    exact = SyslogEmitter(
        load_format("syslog"),
        tmp_path / "exact",
        buffer_size=1,
        threaded=threaded,
    )
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    batch.prepare(lambda: exact.emit_event(_event(0, message)))
    batch.commit()
    batch.release_no_fail()
    exact.flush(force=True)
    exact.close()

    expected = _output_path(tmp_path / "ordinary", "default").read_bytes()
    actual = _output_path(tmp_path / "exact", "default").read_bytes()
    assert actual == expected
    assert b"field=value\r\nforged-entry=value" in actual


def test_syslog_direct_file_uses_one_physical_writer_for_multiple_hosts(tmp_path: Path) -> None:
    """Direct-file compatibility cannot let route writers overwrite each other."""

    def render(path: Path, *, exact: bool) -> bytes:
        emitter = SyslogEmitter(load_format("syslog"), path, buffer_size=1)
        first = _event(0, "host-a")
        second = _event(1, "host-b")
        first["_host_fqdn"] = "a.example.test"
        second["_host_fqdn"] = "b.example.test"
        if exact:
            batch = ExactPublicationAuthority(capacity=1).issue_batch()
            batch.prepare(lambda: (emitter.emit_event(first), emitter.emit_event(second)))
            batch.commit()
            batch.release_no_fail()
        else:
            emitter.emit_event(first)
            emitter.emit_event(second)
        emitter.close()
        return path.read_bytes()

    ordinary = render(tmp_path / "ordinary.log", exact=False)
    exact = render(tmp_path / "exact.log", exact=True)
    assert exact == ordinary
    assert exact.count(b"host-a") == exact.count(b"host-b") == 1


def test_syslog_direct_file_normalizes_each_logical_host_independently(tmp_path: Path) -> None:
    """One physical compatibility file cannot merge source-local normalization state."""

    def render(path: Path, *, exact: bool) -> bytes:
        emitter = SyslogEmitter(load_format("syslog"), path, buffer_size=1)
        events = (_logind_event("hosta", 0), _logind_event("hostb", 1))
        if exact:
            batch = ExactPublicationAuthority(capacity=1).issue_batch()
            batch.prepare(lambda: tuple(emitter.emit_event(event) for event in events))
            batch.commit()
            batch.release_no_fail()
        else:
            for event in events:
                emitter.emit_event(event)
        emitter.close()
        return path.read_bytes()

    ordinary = render(tmp_path / "ordinary.log", exact=False)
    exact = render(tmp_path / "exact.log", exact=True)
    assert exact == ordinary
    new_sessions = [line for line in exact.splitlines() if b"New session" in line]
    assert len(new_sessions) == 2
    assert all(b"New session 2 of user alice" in line for line in new_sessions)


@pytest.mark.parametrize("target", ("default", "splunk", "sof-elk"))
def test_syslog_direct_file_normalization_matches_merged_routed_bytes(
    tmp_path: Path,
    target: str,
) -> None:
    """A shared physical sink preserves independently normalized routed-host bytes."""

    events = tuple(
        event
        for host_index in range(8)
        for event in (
            _logind_event(f"host{host_index}", host_index * 2),
            _logind_event(f"host{host_index}", (host_index * 2) + 1),
        )
    )
    routed_root = tmp_path / "routed"
    routed = SyslogEmitter(load_format("syslog"), routed_root, buffer_size=4)
    routed.configure_output_target(target)
    direct_path = tmp_path / f"direct-{target}.log"
    direct = SyslogEmitter(load_format("syslog"), direct_path, buffer_size=4)
    direct.configure_output_target(target)
    for event in reversed(events):
        routed.emit_event(dict(event))
        direct.emit_event(dict(event))
    routed.close()
    direct.close()

    routed_lines = [
        line.decode("utf-8")
        for path in routed_root.rglob("syslog.log")
        for line in path.read_bytes().splitlines(keepends=True)
    ]
    expected = b"".join(
        SyslogEmitter._line_payload(line.rstrip("\n"))
        for line in sorted(
            routed_lines,
            key=(
                syslog_module._syslog_sort_key
                if target == "sof-elk"
                else syslog_module._rfc5424_syslog_sort_key
            ),
        )
    )
    assert direct_path.read_bytes() == expected
    assert direct_path.read_bytes().count(b"New session") == len(events)


@pytest.mark.parametrize("host_count", (8, 16, 32, 64))
def test_syslog_direct_file_route_decode_is_linear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host_count: int,
) -> None:
    """Each shared-route raw row is decoded once regardless of logical-host count."""

    output = tmp_path / f"direct-{host_count}.log"
    emitter = SyslogEmitter(
        load_format("syslog"),
        output,
        buffer_size=host_count,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=host_count,
        terminal_merge_fan_in=4,
    )
    for host_index in range(host_count):
        event = _event(host_index, f"linear-decode-{host_index}")
        event["hostname"] = f"host{host_index:02d}"
        event["_host_fqdn"] = f"host{host_index:02d}.example.test"
        emitter.emit_event(event)
    emitter.flush(force=True)
    original_decode = emitter._decode_spool_record
    decoded_rows = 0

    def observed_decode(
        encoded: str,
        route_key: str,
        matched: set[object] | None,
    ) -> object:
        nonlocal decoded_rows
        decoded_rows += 1
        return original_decode(encoded, route_key, matched)

    monkeypatch.setattr(emitter, "_decode_spool_record", observed_decode)
    emitter.close()

    assert decoded_rows == host_count
    payload = output.read_text(encoding="utf-8")
    assert all(f"linear-decode-{host_index}" in payload for host_index in range(host_count))


def test_syslog_direct_partition_authenticates_before_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-length partition mutation fails before any public output."""

    output = tmp_path / "direct-partition.log"
    emitter = SyslogEmitter(load_format("syslog"), output, buffer_size=4)
    for host_index in range(4):
        event = _event(host_index, f"partition-auth-{host_index}")
        event["_host_fqdn"] = f"host{host_index}.example.test"
        emitter.emit_event(event)
    emitter.flush(force=True)
    original_normalize = emitter._direct_normalized_route_run
    tampered = False

    def tamper_partition(partition: object) -> object:
        nonlocal tampered
        descriptor = partition.stream.fileno()
        payload = os.pread(descriptor, partition.payload_bytes, 0)
        changed = payload.replace(b"partition-auth-0", b"partition-autx-0")
        assert changed != payload and len(changed) == len(payload)
        assert os.pwrite(descriptor, changed, 0) == len(changed)
        tampered = True
        return original_normalize(partition)

    monkeypatch.setattr(emitter, "_direct_normalized_route_run", tamper_partition)
    with pytest.raises(ExactPublicationError, match="merge run content changed"):
        emitter.close()
    assert tampered
    assert not output.exists()
    assert _owned_descriptor_census(emitter) == {
        "private_journal": 2,
        "private_snapshot": 1,
        "final_candidate": 0,
        "public_file": 0,
        "public_parent": 0,
    }

    monkeypatch.setattr(emitter, "_direct_normalized_route_run", original_normalize)
    emitter.close()
    assert output.read_bytes().count(b"partition-auth") == 4


def test_syslog_exact_admission_freezes_output_target_and_reclaims_capacity(
    tmp_path: Path,
) -> None:
    """Target/layout ownership and bounded reservation capacity are fail-closed."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        exact_candidate_row_capacity=1,
    )
    first = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="row capacity"):
        first.prepare(
            lambda: (
                emitter.emit_event(_event(0, "first")),
                emitter.emit_event(_event(1, "second")),
            )
        )
    with pytest.raises(RuntimeError, match="target is frozen"):
        emitter.configure_output_target("sof-elk")
    first.cancel()
    second = ExactPublicationAuthority(capacity=1).issue_batch()
    second.prepare(lambda: emitter.emit_event(_event(1, "second")))
    second.cancel()
    census = emitter.exact_candidate_census()
    assert census.reserved_rows == census.reserved_bytes == 0
    assert census.admitted_rows == census.admitted_bytes == 0
    emitter.close()


def _journal_bytes(emitter: SyslogEmitter) -> bytes:
    stream = emitter._spool_stream
    assert stream is not None and not stream.closed
    descriptor = stream.descriptor
    assert type(descriptor) is int
    size = int(os.fstat(descriptor).st_size)
    return os.pread(descriptor, size, 0)


def _restore_journal(emitter: SyslogEmitter, payload: bytes) -> None:
    stream = emitter._spool_stream
    assert stream is not None and not stream.closed
    descriptor = stream.descriptor
    assert type(descriptor) is int
    os.ftruncate(descriptor, len(payload))
    assert os.pwrite(descriptor, payload, 0) == len(payload)


def test_syslog_close_authenticates_spooled_exact_record(tmp_path: Path) -> None:
    """Terminal normalization rejects changed bytes in the anonymous journal."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(0, "original")))
    batch.commit()
    batch.release_no_fail()
    emitter.flush(force=True)

    original = _journal_bytes(emitter)
    changed = original.replace(b"original", b"origina1")
    assert changed != original and len(changed) == len(original)
    _restore_journal(emitter, changed)
    with pytest.raises(ExactPublicationError, match="journal prefix changed"):
        emitter.close()
    assert emitter.exact_candidate_census().admitted_rows == 1

    _restore_journal(emitter, original)
    emitter.close()
    assert _output_path(tmp_path, "default").read_text(encoding="utf-8").count("original") == 1


def test_syslog_spool_append_lost_return_reconciles_without_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable anonymous append resumes its exact suffix and releases once."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "spool-once"))
    original_fsync = syslog_module._secure_fsync
    fail_after_fsync = True

    def fsync_then_raise(descriptor: int) -> None:
        nonlocal fail_after_fsync
        original_fsync(descriptor)
        stream = emitter._spool_stream
        if fail_after_fsync and stream is not None and descriptor == stream.descriptor:
            fail_after_fsync = False
            raise OSError("injected Syslog spool append lost return")

    monkeypatch.setattr(syslog_module, "_secure_fsync", fsync_then_raise)
    with pytest.raises(OSError, match="spool append lost return"):
        emitter.flush(force=True)
    assert len(emitter._spool_appends) == 1
    assert emitter._spool_bytes == 0
    assert _journal_bytes(emitter)

    monkeypatch.setattr(syslog_module, "_secure_fsync", original_fsync)
    emitter.flush(force=True)
    assert emitter._spool_appends == {}
    assert next(iter(emitter._writers.values())).buffer == []
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"spool-once") == 1


@pytest.mark.parametrize(
    ("original_token", "replacement", "expected_error"),
    (
        (b"completed-prefix", b"completed-prefiy", "journal prefix changed"),
        (b"durable-suffix", b"durable-suffiy", "append found conflicting bytes"),
    ),
)
def test_syslog_later_spool_append_lost_return_reconciles_authenticated_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    original_token: bytes,
    replacement: bytes,
    expected_error: str,
) -> None:
    """A later durable suffix authenticates both its receipt prefix and suffix."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "completed-prefix"))
    emitter.flush(force=True)
    prior_bytes = emitter._spool_bytes
    emitter.emit_event(_event(1, "durable-suffix"))
    original_fsync = syslog_module._secure_fsync
    fail_after_fsync = True

    def fsync_then_raise(descriptor: int) -> None:
        nonlocal fail_after_fsync
        original_fsync(descriptor)
        stream = emitter._spool_stream
        if fail_after_fsync and stream is not None and descriptor == stream.descriptor:
            fail_after_fsync = False
            raise OSError("injected later Syslog spool append lost return")

    monkeypatch.setattr(syslog_module, "_secure_fsync", fsync_then_raise)
    with pytest.raises(OSError, match="later Syslog spool append lost return"):
        emitter.flush(force=True)

    pending = next(iter(emitter._spool_appends.values()))
    writer = next(iter(emitter._writers.values()))
    original = _journal_bytes(emitter)
    assert pending.offset == prior_bytes < len(original)
    changed = original.replace(original_token, replacement)
    assert changed != original and len(changed) == len(original)
    _restore_journal(emitter, changed)

    monkeypatch.setattr(syslog_module, "_secure_fsync", original_fsync)
    with pytest.raises(ExactPublicationError, match=expected_error):
        emitter.flush(force=True)
    assert writer.buffer and emitter._spool_appends

    _restore_journal(emitter, original)
    emitter.flush(force=True)
    emitter.close()
    payload = _output_path(tmp_path, "default").read_text(encoding="utf-8")
    assert payload.count("completed-prefix") == payload.count("durable-suffix") == 1


def test_syslog_private_storage_is_anonymous_and_ignores_hostile_spellings(
    tmp_path: Path,
) -> None:
    """Raw truth has no pathname for a symlink or regular replacement to capture."""

    victim = tmp_path / "private-victim"
    victim.write_bytes(b"victim")
    hostile = tmp_path / "evidenceforge-syslog-spool-predictable"
    hostile.symlink_to(victim)
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "anonymous-private"))
    emitter.flush(force=True)

    stream = emitter._spool_stream
    assert stream is not None
    assert type(stream.descriptor) is int and type(stream.guard_descriptor) is int
    for descriptor in (stream.descriptor, stream.guard_descriptor):
        metadata = os.fstat(descriptor)
        assert metadata.st_nlink == 0
        assert not os.get_inheritable(descriptor)
    assert hostile.is_symlink()
    assert victim.read_bytes() == b"victim"

    emitter.close()
    assert hostile.is_symlink()
    assert victim.read_bytes() == b"victim"


def test_syslog_private_storage_never_pathname_chmods_a_swapped_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anonymous storage creation never performs a pathname chmod."""

    victim = tmp_path / "chmod-victim"
    victim.mkdir(mode=0o755)
    victim_mode = victim.stat().st_mode
    original_chmod = Path.chmod
    calls = 0

    def counted_chmod(path: Path, mode: int, *args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", counted_chmod)
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "no-pathname-chmod"))
    emitter.close()

    assert calls == 0
    assert victim.stat().st_mode == victim_mode
    assert _output_path(tmp_path, "default").read_bytes().count(b"no-pathname-chmod") == 1


def test_syslog_parent_swap_after_preflight_never_writes_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A route-parent swap after all-route preflight fails before public creation."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "PARENT-RACE-SECRET"))
    output_parent = _output_path(tmp_path, "default").parent
    victim = tmp_path / "parent-swap-victim"
    victim.mkdir()
    authentic_parent = output_parent.with_name(f"{output_parent.name}.authentic")
    original_prepare = emitter._prepare_final_candidate
    swapped = False

    def prepare_then_swap(
        route_key: str,
        writer: object,
        line_factory: object,
    ) -> object:
        nonlocal swapped
        retained = original_prepare(route_key, writer, line_factory)
        if not swapped:
            swapped = True
            output_parent.rename(authentic_parent)
            output_parent.symlink_to(victim, target_is_directory=True)
        return retained

    monkeypatch.setattr(emitter, "_prepare_final_candidate", prepare_then_swap)
    with pytest.raises(ExactPublicationError, match="output directory"):
        emitter.close()
    assert swapped
    assert list(victim.iterdir()) == []

    monkeypatch.setattr(emitter, "_prepare_final_candidate", original_prepare)
    output_parent.unlink()
    authentic_parent.rename(output_parent)
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"PARENT-RACE-SECRET") == 1


@pytest.mark.parametrize("tamper", ("truncate", "same-length"))
def test_syslog_spool_receipt_retry_authenticates_before_buffer_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    """A receipt lost return keeps source rows until durable bytes reauthenticate."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "receipt-truth"))
    original_prefix_check = emitter._spool_records_match_prefix
    fail_after_receipt = True

    def fail_once(buffer: list[str], records: tuple[str, ...]) -> bool:
        nonlocal fail_after_receipt
        if fail_after_receipt:
            fail_after_receipt = False
            raise OSError("injected receipt lost return")
        return original_prefix_check(buffer, records)

    monkeypatch.setattr(emitter, "_spool_records_match_prefix", fail_once)
    with pytest.raises(OSError, match="receipt lost return"):
        emitter.flush(force=True)

    writer = next(iter(emitter._writers.values()))
    original = _journal_bytes(emitter)
    if tamper == "truncate":
        descriptor = emitter._spool_stream.descriptor
        assert type(descriptor) is int
        os.ftruncate(descriptor, len(original) - 1)
    else:
        changed = original.replace(b"receipt-truth", b"receipt-troth")
        assert changed != original and len(changed) == len(original)
        _restore_journal(emitter, changed)

    monkeypatch.setattr(emitter, "_spool_records_match_prefix", original_prefix_check)
    with pytest.raises(ExactPublicationError, match="journal"):
        emitter.flush(force=True)
    assert writer.buffer and emitter._spool_appends

    _restore_journal(emitter, original)
    emitter.flush(force=True)
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"receipt-truth") == 1


def test_syslog_new_barrier_authenticates_completed_prefix_before_append(tmp_path: Path) -> None:
    """A new extent never appends behind a changed completed journal prefix."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "completed-prefix"))
    emitter.flush(force=True)
    original = _journal_bytes(emitter)
    changed = original.replace(b"completed-prefix", b"completed-prefiy")
    assert changed != original and len(changed) == len(original)
    _restore_journal(emitter, changed)
    emitter.emit_event(_event(1, "later-barrier"))

    with pytest.raises(ExactPublicationError, match="journal prefix changed"):
        emitter.flush(force=True)
    assert next(iter(emitter._writers.values())).buffer

    _restore_journal(emitter, original)
    emitter.flush(force=True)
    emitter.close()
    output = _output_path(tmp_path, "default").read_text(encoding="utf-8")
    assert output.count("completed-prefix") == output.count("later-barrier") == 1


def test_syslog_pending_append_reauthenticates_completed_prefix_before_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained pending extent never trusts its previously completed prefix."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "pending-prefix"))
    emitter.flush(force=True)
    emitter.emit_event(_event(1, "pending-suffix"))
    original_complete = emitter._complete_spool_append
    fail_before_complete = True

    def fail_once(route_key: str, writer: object, pending: object) -> None:
        nonlocal fail_before_complete
        if fail_before_complete:
            fail_before_complete = False
            raise OSError("injected after pending creation")
        original_complete(route_key, writer, pending)

    monkeypatch.setattr(emitter, "_complete_spool_append", fail_once)
    with pytest.raises(OSError, match="after pending creation"):
        emitter.flush(force=True)
    original = _journal_bytes(emitter)
    changed = original.replace(b"pending-prefix", b"pending-prefiy")
    assert changed != original and len(changed) == len(original)
    _restore_journal(emitter, changed)

    monkeypatch.setattr(emitter, "_complete_spool_append", original_complete)
    with pytest.raises(ExactPublicationError, match="journal prefix changed"):
        emitter.flush(force=True)
    assert next(iter(emitter._writers.values())).buffer and emitter._spool_appends

    _restore_journal(emitter, original)
    emitter.flush(force=True)
    emitter.close()


def test_syslog_completed_anonymous_descriptor_disappearance_fails_closed(
    tmp_path: Path,
) -> None:
    """A completed nonempty anonymous journal cannot be silently recreated."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "completed-delete"))
    emitter.flush(force=True)
    assert emitter._spool_stream is not None
    descriptor = emitter._spool_stream.descriptor
    assert type(descriptor) is int
    os.close(descriptor)
    emitter.emit_event(_event(1, "retained-after-delete"))

    with pytest.raises(ExactPublicationError, match="descriptor"):
        emitter.flush(force=True)
    assert next(iter(emitter._writers.values())).buffer
    with pytest.raises(ExactPublicationError, match="descriptor disappeared"):
        SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
    assert emitter._spool_stream.closed
    emitter._spool_stream = None
    emitter._spool_identity = None


def test_syslog_offset_zero_retry_recreates_anonymous_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An offset-zero pending extent can recover in fresh anonymous storage."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "fresh-descriptor-retry"))
    original_complete = emitter._complete_spool_append
    fail_before_write = True

    def fail_once(route_key: str, writer: object, pending: object) -> None:
        nonlocal fail_before_write
        if fail_before_write:
            fail_before_write = False
            raise OSError("injected offset-zero prewrite loss")
        original_complete(route_key, writer, pending)

    monkeypatch.setattr(emitter, "_complete_spool_append", fail_once)
    with pytest.raises(OSError, match="offset-zero prewrite loss"):
        emitter.flush(force=True)
    original_stream = emitter._spool_stream
    assert original_stream is not None and type(original_stream.descriptor) is int
    assert os.fstat(original_stream.descriptor).st_size == 0
    original_identity = emitter._spool_identity
    os.close(original_stream.descriptor)

    monkeypatch.setattr(emitter, "_complete_spool_append", original_complete)
    emitter.flush(force=True)
    assert emitter._spool_stream is not None
    assert emitter._spool_identity != original_identity
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"fresh-descriptor-retry") == 1


def test_syslog_spool_rejects_same_content_descriptor_substitution(tmp_path: Path) -> None:
    """Anonymous journal ownership includes descriptor identity, not only bytes."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "identity-pinned"))
    emitter.flush(force=True)
    original_stream = emitter._spool_stream
    original_identity = emitter._spool_identity
    assert original_stream is not None and original_identity is not None
    payload = _journal_bytes(emitter)
    replacement, _replacement_identity = emitter._new_anonymous_stream(label="test replacement")
    assert os.write(replacement.fileno(), payload) == len(payload)
    emitter._spool_stream = replacement

    with pytest.raises(ExactPublicationError, match="descriptor identity"):
        emitter.close()

    emitter._spool_stream = original_stream
    emitter._spool_identity = original_identity
    replacement.close()
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"identity-pinned") == 1


def test_syslog_exact_publication_has_no_destructive_pathname_primitives() -> None:
    """The anonymous/public protocol contains no pathname cleanup or replacement call."""

    source = Path(syslog_module.__file__).read_text(encoding="utf-8")
    forbidden = (
        "tempfile.mkdtemp(",
        "tempfile.mkstemp(",
        "os.chmod(",
        "os.link(",
        "os.remove(",
        "os.rename(",
        "os.replace(",
        "os.rmdir(",
        "os.unlink(",
        "shutil.",
    )
    assert len(forbidden) == 10
    assert {operation for operation in forbidden if operation in source} == set()


@pytest.mark.parametrize("operation", ("unlink", "rmdir"))
def test_syslog_anonymous_cleanup_never_calls_destructive_path_syscalls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Call-original-then-raise path hooks stay uncalled during anonymous cleanup."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"cleanup-no-{operation}"))
    foreign = tmp_path / f"foreign-{operation}"
    if operation == "unlink":
        foreign.write_bytes(b"foreign")
    else:
        foreign.mkdir()
    original_cleanup = emitter._cleanup_terminal_sources
    original_operation = getattr(syslog_module.os, operation)
    calls = 0

    def cleanup_with_guard() -> None:
        nonlocal calls

        def call_original_then_raise(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            original_operation(*args, **kwargs)
            raise OSError(f"injected cleanup {operation} lost return")

        monkeypatch.setattr(syslog_module.os, operation, call_original_then_raise)
        original_cleanup()

    monkeypatch.setattr(emitter, "_cleanup_terminal_sources", cleanup_with_guard)
    emitter.close()
    assert calls == 0
    assert foreign.exists()


@pytest.mark.parametrize("kind", ("regular", "directory", "symlink"))
def test_syslog_cleanup_leaves_hostile_private_spellings_unchanged(
    tmp_path: Path,
    kind: str,
) -> None:
    """Foreign spool/candidate spellings are outside anonymous cleanup authority."""

    foreign = tmp_path / f".evidenceforge-syslog-{kind}.candidate"
    victim = tmp_path / "foreign-symlink-victim"
    victim.write_bytes(b"victim")
    if kind == "regular":
        foreign.write_bytes(b"foreign")
    elif kind == "directory":
        foreign.mkdir()
    else:
        foreign.symlink_to(victim)
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "foreign-cleanup-safe"))
    emitter.close()

    if kind == "regular":
        assert foreign.read_bytes() == b"foreign"
    elif kind == "directory":
        assert foreign.is_dir()
    else:
        assert foreign.is_symlink() and foreign.readlink() == victim
    assert victim.read_bytes() == b"victim"


def test_syslog_close_rejects_added_ordinary_journal_record(tmp_path: Path) -> None:
    """Extra bytes cannot hide as an ordinary record behind the journal receipt."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "exact-row"))
    emitter.emit_event(_event(1, "ordinary-row"))
    emitter.flush(force=True)
    original = _journal_bytes(emitter)
    forged = original + json.dumps("forged ordinary row").encode() + b"\n"
    _restore_journal(emitter, forged)

    with pytest.raises(ExactPublicationError, match="journal size"):
        emitter.close()
    _restore_journal(emitter, original)
    emitter.close()
    payload = _output_path(tmp_path, "default").read_text(encoding="utf-8")
    assert payload.count("exact-row") == payload.count("ordinary-row") == 1
    assert "forged ordinary row" not in payload


@pytest.mark.parametrize("tamper", ("extended", "same-length-invalid"))
def test_syslog_spool_authenticates_size_and_digest_before_json_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    """Unauthenticated journal bytes never reach header or record JSON parsing."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "predecode-auth"))
    emitter.flush(force=True)
    original = _journal_bytes(emitter)
    if tamper == "extended":
        _restore_journal(emitter, original + b'"' + (b"x" * 4096) + b'"\n')
        expected = "size"
    else:
        changed = b"!" + original[1:]
        assert len(changed) == len(original)
        _restore_journal(emitter, changed)
        expected = "prefix"
    decode_calls = 0
    original_loads = syslog_module._secure_json_loads

    def counted_loads(payload: object) -> object:
        nonlocal decode_calls
        decode_calls += 1
        return original_loads(payload)

    monkeypatch.setattr(syslog_module, "_secure_json_loads", counted_loads)
    with pytest.raises(ExactPublicationError, match=f"journal {expected}"):
        emitter.close()
    assert decode_calls == 0

    monkeypatch.setattr(syslog_module, "_secure_json_loads", original_loads)
    _restore_journal(emitter, original)
    emitter.close()


@pytest.mark.parametrize("field", ("payload_bytes", "record_count", "extent_count"))
def test_syslog_route_receipt_bounds_fail_before_record_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """Route receipt byte, row, and chain bounds are enforced before record decode."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "receipt-bounds"))
    emitter.flush(force=True)
    route_key, receipt = next(iter(emitter._spool_receipts.items()))
    values = {
        "head_offset": receipt.head_offset,
        "payload_bytes": receipt.payload_bytes,
        "record_count": receipt.record_count,
        "extent_count": receipt.extent_count,
    }
    values[field] += (
        emitter._spool_route_byte_capacity + 1
        if field == "payload_bytes"
        else emitter._spool_route_row_capacity + 1
        if field == "record_count"
        else emitter._spool_extent_count + 1
    )
    emitter._spool_receipts[route_key] = type(receipt)(**values)
    decode_calls = 0
    original_decode = emitter._decode_spool_record

    def counted_decode(*args: object, **kwargs: object) -> object:
        nonlocal decode_calls
        decode_calls += 1
        return original_decode(*args, **kwargs)

    monkeypatch.setattr(emitter, "_decode_spool_record", counted_decode)
    with pytest.raises(ExactPublicationError, match="route (?:capacity|receipt) changed"):
        emitter.close()
    assert decode_calls == 0

    emitter._spool_receipts[route_key] = receipt
    monkeypatch.setattr(emitter, "_decode_spool_record", original_decode)
    emitter.close()


def test_syslog_spool_decode_uses_authenticated_snapshot_then_reauthenticates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live-journal mutation during decode cannot alter its anonymous snapshot."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.emit_event(_event(0, "snapshot-auth"))
    emitter.flush(force=True)
    original = _journal_bytes(emitter)
    changed = original.replace(b"snapshot-auth", b"snapshot-autx")
    assert changed != original and len(changed) == len(original)
    original_loads = syslog_module._secure_json_loads
    tampered = False

    def tamper_source_then_decode(payload: object) -> object:
        nonlocal tampered
        if not tampered:
            tampered = True
            _restore_journal(emitter, changed)
        return original_loads(payload)

    monkeypatch.setattr(syslog_module, "_secure_json_loads", tamper_source_then_decode)
    with pytest.raises(ExactPublicationError, match="journal prefix changed"):
        emitter.close()
    assert tampered
    assert not _output_path(tmp_path, "default").exists()

    monkeypatch.setattr(syslog_module, "_secure_json_loads", original_loads)
    _restore_journal(emitter, original)
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"snapshot-auth") == 1


@pytest.mark.parametrize(
    ("capacity_name", "capacity_value", "events", "message"),
    (
        ("spool_record_byte_capacity", 128, 1, "x" * 512),
        ("spool_route_byte_capacity", 512, 3, "x" * 160),
        ("spool_route_row_capacity", 1, 2, "bounded-row"),
    ),
)
def test_syslog_spool_capacity_fails_before_buffer_release(
    tmp_path: Path,
    capacity_name: str,
    capacity_value: int,
    events: int,
    message: str,
) -> None:
    """Record, route-byte, and route-row limits retain source buffers."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        buffer_size=10,
        **{capacity_name: capacity_value},
    )
    for offset in range(events):
        emitter.emit_event(_event(offset, f"{message}-{offset}"))
    writer = next(iter(emitter._writers.values()))
    with pytest.raises(ExactPublicationError, match="spool.*capacity"):
        emitter.flush(force=True)
    assert len(writer.buffer) == events
    if emitter._spool_stream is not None:
        try:
            SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
        except ExactPublicationError:
            pass
        emitter._spool_stream = None


def test_syslog_total_spool_capacity_bounds_the_whole_corpus(tmp_path: Path) -> None:
    """Global journal capacity is derived from configured route and host caps."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        buffer_size=10,
        spool_route_row_capacity=2,
        terminal_host_capacity=1,
    )
    emitter.emit_event(_logind_event("host-a", 0))
    emitter.emit_event(_logind_event("host-b", 1))
    emitter.flush(force=True)
    emitter.emit_event(_logind_event("host-c", 2))
    with pytest.raises(ExactPublicationError, match="total private spool row capacity"):
        emitter.flush(force=True)
    assert any(writer.buffer for writer in emitter._writers.values())
    if emitter._spool_stream is not None:
        try:
            SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
        except ExactPublicationError:
            pass
        emitter._spool_stream = None


def test_syslog_cleanup_lost_return_retains_public_output_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Final private cleanup cannot erase the proof needed by a close retry."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(0, "first")))
    batch.commit()
    batch.release_no_fail()

    original_cleanup = emitter._cleanup_final_candidates
    fail_after_cleanup = True

    def cleanup_then_raise() -> None:
        nonlocal fail_after_cleanup
        original_cleanup()
        if fail_after_cleanup:
            fail_after_cleanup = False
            raise OSError("injected Syslog cleanup lost return")

    monkeypatch.setattr(emitter, "_cleanup_final_candidates", cleanup_then_raise)
    with pytest.raises(OSError, match="cleanup lost return"):
        emitter.close()

    output = _output_path(tmp_path, "default")
    expected = output.read_bytes()
    changed = expected.replace(b"first", b"f1rst")
    assert changed != expected and len(changed) == len(expected)
    output.write_bytes(changed)
    with pytest.raises(ExactPublicationError, match="output changed"):
        emitter.close()
    output.write_bytes(expected)
    emitter.close()
    assert output.read_bytes() == expected


def test_syslog_public_verification_rejects_symlink_after_private_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proof-only retry never follows a substituted public symlink."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "public-nofollow"))
    original_cleanup = emitter._cleanup_final_candidates
    fail_after_cleanup = True

    def cleanup_then_raise() -> None:
        nonlocal fail_after_cleanup
        original_cleanup()
        if fail_after_cleanup:
            fail_after_cleanup = False
            raise OSError("injected post-private-cleanup lost return")

    monkeypatch.setattr(emitter, "_cleanup_final_candidates", cleanup_then_raise)
    with pytest.raises(OSError, match="post-private-cleanup lost return"):
        emitter.close()

    output = _output_path(tmp_path, "default")
    expected = output.read_bytes()
    backup = output.with_suffix(".original")
    output.rename(backup)
    victim = tmp_path / "public-victim.log"
    victim.write_bytes(expected)
    output.symlink_to(victim)
    with pytest.raises(ExactPublicationError, match="disappeared|directory entry"):
        emitter.close()
    assert victim.read_bytes() == expected

    output.unlink()
    backup.rename(output)
    emitter.close()
    assert output.read_bytes() == expected


@pytest.mark.parametrize("replacement_kind", ("regular", "symlink"))
def test_syslog_public_entry_substitution_preserves_foreign_output_and_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """A post-create entry swap never writes or deletes the foreign replacement."""

    output = _output_path(tmp_path, "default")
    output.parent.mkdir(parents=True)
    foreign_pending = output.parent / ".foreign.publishing"
    foreign_pending.write_bytes(b"foreign-pending")
    victim = tmp_path / "foreign-output-victim.log"
    victim.write_bytes(b"foreign-victim")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "descriptor-published"))
    original_prefix = emitter._public_prefix_size
    authentic: Path | None = None
    swapped = False

    def swap_then_authenticate(retained: object, append: object) -> int:
        nonlocal authentic, swapped
        if not swapped:
            swapped = True
            authentic = output.with_suffix(".authentic")
            output.rename(authentic)
            if replacement_kind == "regular":
                output.write_bytes(b"FORGED-PUBLIC\n")
            else:
                output.symlink_to(victim)
        return original_prefix(retained, append)

    monkeypatch.setattr(emitter, "_public_prefix_size", swap_then_authenticate)
    with pytest.raises(ExactPublicationError, match="directory entry changed"):
        emitter.close()
    assert swapped and authentic is not None and authentic.exists()
    if replacement_kind == "regular":
        assert output.read_bytes() == b"FORGED-PUBLIC\n"
    else:
        assert output.is_symlink() and output.readlink() == victim
    assert foreign_pending.read_bytes() == b"foreign-pending"
    assert victim.read_bytes() == b"foreign-victim"

    monkeypatch.setattr(emitter, "_public_prefix_size", original_prefix)
    output.unlink()
    authentic.rename(output)
    emitter.close()
    assert output.read_bytes().count(b"descriptor-published") == 1
    assert foreign_pending.read_bytes() == b"foreign-pending"


def test_syslog_preexisting_public_file_is_never_adopted_or_overwritten(tmp_path: Path) -> None:
    """All-route preflight rejects a foreign final entry before any public create."""

    output = _output_path(tmp_path, "default")
    output.parent.mkdir(parents=True)
    output.write_bytes(b"foreign-public")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "must-not-overwrite"))

    with pytest.raises(ExactPublicationError, match="already exists"):
        emitter.close()
    assert output.read_bytes() == b"foreign-public"
    assert emitter._public_proofs == {}
    if emitter._spool_snapshot is not None:
        emitter._spool_snapshot.close()
        emitter._spool_snapshot = None
    if emitter._spool_stream is not None:
        SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
        emitter._spool_stream = None


def test_syslog_public_fsync_lost_return_rejects_same_length_prefix_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable final-file suffix is resumed only after exact prefix authentication."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "PUBLIC-FSYNC-TRUTH"))
    original_fsync = syslog_module._secure_fsync
    failed = False

    def fsync_then_raise(descriptor: int) -> None:
        nonlocal failed
        original_fsync(descriptor)
        append_descriptors = {
            append.descriptor_owner.descriptor
            for append in emitter._public_appends.values()
            if not append.descriptor_owner.closed
        }
        if not failed and descriptor in append_descriptors:
            failed = True
            raise OSError("injected public fsync lost return")

    monkeypatch.setattr(syslog_module, "_secure_fsync", fsync_then_raise)
    with pytest.raises(OSError, match="public fsync lost return"):
        emitter.close()
    output = _output_path(tmp_path, "default")
    original = output.read_bytes()
    changed = original.replace(b"PUBLIC-FSYNC-TRUTH", b"PUBLIC-FSYNC-TROTH")
    assert changed != original and len(changed) == len(original)
    output.write_bytes(changed)

    monkeypatch.setattr(syslog_module, "_secure_fsync", original_fsync)
    with pytest.raises(ExactPublicationError, match="prefix changed"):
        emitter.close()
    output.write_bytes(original)
    emitter.close()
    assert output.read_bytes().count(b"PUBLIC-FSYNC-TRUTH") == 1


def test_syslog_public_partial_write_retries_from_authenticated_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial final-file write resumes without truncation or duplicate bytes."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "public-prefix"))
    original_write = SyslogEmitter._write_descriptor
    failed = False

    def write_then_raise(descriptor: int, payload: bytes) -> None:
        nonlocal failed
        public_descriptors = {
            append.descriptor_owner.descriptor
            for append in emitter._public_appends.values()
            if not append.descriptor_owner.closed
        }
        if not failed and descriptor in public_descriptors:
            failed = True
            split = max(1, len(payload) // 2)
            assert os.write(descriptor, payload[:split]) == split
            raise OSError("injected public partial write")
        original_write(descriptor, payload)

    monkeypatch.setattr(SyslogEmitter, "_write_descriptor", staticmethod(write_then_raise))
    with pytest.raises(OSError, match="public partial write"):
        emitter.close()
    partial = _output_path(tmp_path, "default").read_bytes()
    assert partial and b"public-prefix" not in partial

    monkeypatch.setattr(SyslogEmitter, "_write_descriptor", staticmethod(original_write))
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"public-prefix") == 1


def test_syslog_final_candidate_stream_rejects_post_preflight_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The anonymous candidate is reauthenticated immediately before publication."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "ORIGINAL"))
    original_publish = emitter._publish_final_candidate
    candidate_bytes: bytes | None = None
    tampered = False

    def tamper_then_publish(retained: object) -> None:
        nonlocal candidate_bytes, tampered
        stream = retained.stream
        descriptor = stream.fileno()
        candidate_bytes = os.pread(descriptor, retained.payload_bytes, 0)
        changed = candidate_bytes.replace(b"ORIGINAL", b"FORGED__")
        assert changed != candidate_bytes and len(changed) == len(candidate_bytes)
        assert os.pwrite(descriptor, changed, 0) == len(changed)
        tampered = True
        original_publish(retained)

    monkeypatch.setattr(emitter, "_publish_final_candidate", tamper_then_publish)
    with pytest.raises(ExactPublicationError, match="candidate content changed"):
        emitter.close()
    assert tampered
    output = _output_path(tmp_path, "default")
    assert not output.exists()

    retained = next(iter(emitter._final_candidates.values()))
    assert candidate_bytes is not None
    assert os.pwrite(retained.stream.fileno(), candidate_bytes, 0) == len(candidate_bytes)
    monkeypatch.setattr(emitter, "_publish_final_candidate", original_publish)
    emitter.close()
    assert output.read_bytes().count(b"ORIGINAL") == 1


def test_syslog_final_candidate_retry_rejects_same_content_descriptor_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry keeps anonymous candidate descriptor identity pinned."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "candidate-identity"))
    original_publish = SyslogEmitter._publish_final_candidate
    fail_after_publish = True

    def publish_then_raise(instance: SyslogEmitter, retained: object) -> None:
        nonlocal fail_after_publish
        original_publish(instance, retained)
        if fail_after_publish:
            fail_after_publish = False
            raise OSError("injected final-candidate lost return")

    monkeypatch.setattr(SyslogEmitter, "_publish_final_candidate", publish_then_raise)
    with pytest.raises(OSError, match="final-candidate lost return"):
        emitter.close()

    retained = next(iter(emitter._final_candidates.values()))
    original_stream = retained.stream
    payload = os.pread(original_stream.fileno(), retained.payload_bytes, 0)
    replacement, _identity = emitter._new_anonymous_stream(label="test candidate replacement")
    assert os.write(replacement.fileno(), payload) == len(payload)
    retained.stream = replacement
    with pytest.raises(ExactPublicationError, match="candidate.*identity"):
        emitter.close()

    retained.stream = original_stream
    replacement.close()
    emitter.close()
    assert _output_path(tmp_path, "default").read_bytes().count(b"candidate-identity") == 1


@pytest.mark.parametrize("descriptor_kind", ("file", "parent"))
@pytest.mark.parametrize("timing", ("before", "after"))
def test_syslog_public_descriptor_retirement_lost_returns_are_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_kind: str,
    timing: str,
) -> None:
    """Public file and parent fds retain an idempotent close phase."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"public-close-{descriptor_kind}-{timing}"))
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    original_close = emitter._close_public_owner
    failed = False

    def close_then_maybe_raise(owner: object, *, label: str) -> None:
        nonlocal failed
        targets = tuple(
            append.descriptor_owner if descriptor_kind == "file" else append.parent_owner
            for append in emitter._public_appends.values()
        )
        if not failed and any(owner is target for target in targets):
            failed = True
            if timing == "after":
                original_close(owner, label=label)
            raise OSError(f"injected public {descriptor_kind} close {timing}")
        original_close(owner, label=label)

    monkeypatch.setattr(emitter, "_close_public_owner", close_then_maybe_raise)
    with pytest.raises(OSError, match=f"public {descriptor_kind} close {timing}"):
        emitter.close()
    assert failed
    assert emitter._public_appends
    assert emitter._public_proofs
    assert _owned_descriptor_census(emitter) == {
        "private_journal": 2,
        "private_snapshot": 1,
        "final_candidate": 1,
        "public_file": 2 * int(descriptor_kind == "file" and timing == "before"),
        "public_parent": 2 * int(descriptor_kind == "file" or timing == "before"),
    }

    monkeypatch.setattr(emitter, "_close_public_owner", original_close)
    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    output = _output_path(tmp_path, "default").read_bytes()
    assert output.count(f"public-close-{descriptor_kind}-{timing}".encode()) == 1


@pytest.mark.parametrize("descriptor_kind", ("file", "parent"))
def test_syslog_public_descriptor_cannot_disappear_before_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_kind: str,
) -> None:
    """A foreign close is not mistaken for a completed owned-close phase."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"unexpected-public-close-{descriptor_kind}"))
    original_retire = emitter._retire_public_append
    failed = False

    def fail_before_retirement(route_key: str, append: object) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("injected pause before public retirement")
        original_retire(route_key, append)

    monkeypatch.setattr(emitter, "_retire_public_append", fail_before_retirement)
    with pytest.raises(OSError, match="pause before public retirement"):
        emitter.close()
    monkeypatch.setattr(emitter, "_retire_public_append", original_retire)
    append = next(iter(emitter._public_appends.values()))
    assert _owned_descriptor_census(emitter) == {
        "private_journal": 2,
        "private_snapshot": 1,
        "final_candidate": 1,
        "public_file": 2,
        "public_parent": 2,
    }

    owner = append.descriptor_owner if descriptor_kind == "file" else append.parent_owner
    assert owner is not None
    descriptor = owner.descriptor
    assert descriptor is not None
    os.close(descriptor)
    with pytest.raises(
        ExactPublicationError, match=f"public {descriptor_kind} descriptor disappeared"
    ):
        emitter.close()
    assert owner.closed

    output = _output_path(tmp_path, "default")
    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    assert output.read_bytes().count(f"unexpected-public-close-{descriptor_kind}".encode()) == 1


@pytest.mark.parametrize("timing", ("before", "after"))
def test_syslog_public_descriptor_acquisition_lost_return_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timing: str,
) -> None:
    """The O_EXCL acquisition boundary retains every acquired fd before returning."""

    output = _output_path(tmp_path, "default")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"public-acquisition-{timing}"))
    fd_root = Path("/dev/fd") if Path("/dev/fd").exists() else Path("/proc/self/fd")
    baseline_fds = len(list(fd_root.iterdir())) if fd_root.exists() else None
    original_acquire = emitter._acquire_public_descriptor
    failed = False

    def acquire_then_maybe_raise(append: object) -> None:
        nonlocal failed
        if not failed:
            failed = True
            if timing == "after":
                original_acquire(append)
            raise OSError(f"injected public acquisition {timing}")
        original_acquire(append)

    monkeypatch.setattr(emitter, "_acquire_public_descriptor", acquire_then_maybe_raise)
    with pytest.raises(OSError, match=f"public acquisition {timing}"):
        emitter.close()
    assert failed
    assert output.exists() is (timing == "after")
    if output.exists():
        assert output.read_bytes() == b""
    expected_census = {
        "private_journal": 2,
        "private_snapshot": 1,
        "final_candidate": 1,
        "public_file": 2 * int(timing == "after"),
        "public_parent": 2,
    }
    assert _owned_descriptor_census(emitter) == expected_census
    if baseline_fds is not None:
        assert len(list(fd_root.iterdir())) == baseline_fds + sum(expected_census.values())

    if timing == "before":
        output.write_bytes(b"foreign-preexisting-entry")
        monkeypatch.setattr(emitter, "_acquire_public_descriptor", original_acquire)
        with pytest.raises(ExactPublicationError, match="already exists"):
            emitter.close()
        assert output.read_bytes() == b"foreign-preexisting-entry"
        output.unlink()

    monkeypatch.setattr(emitter, "_acquire_public_descriptor", original_acquire)
    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    if baseline_fds is not None:
        assert len(list(fd_root.iterdir())) == baseline_fds
    assert output.read_bytes().count(f"public-acquisition-{timing}".encode()) == 1


@pytest.mark.parametrize("timing", ("before", "after"))
def test_syslog_final_candidate_retirement_lost_return_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timing: str,
) -> None:
    """Anonymous final-candidate close never loses its retained phase."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"candidate-close-{timing}"))
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    original_close = emitter._close_retained_stream
    failed = False

    def close_then_raise(stream: object, *, close_started: bool, label: str) -> None:
        nonlocal failed
        if not failed and label == "final candidate":
            failed = True
            if timing == "after":
                original_close(stream, close_started=close_started, label=label)
            raise OSError(f"injected candidate close {timing}")
        original_close(stream, close_started=close_started, label=label)

    monkeypatch.setattr(emitter, "_close_retained_stream", close_then_raise)
    with pytest.raises(OSError, match=f"candidate close {timing}"):
        emitter.close()
    retained = next(iter(emitter._final_candidates.values()))
    assert retained.close_started
    assert retained.stream.closed is (timing == "after")
    assert _owned_descriptor_census(emitter) == {
        "private_journal": 2,
        "private_snapshot": 1,
        "final_candidate": int(timing == "before"),
        "public_file": 0,
        "public_parent": 0,
    }

    monkeypatch.setattr(emitter, "_close_retained_stream", original_close)
    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    assert (
        _output_path(tmp_path, "default").read_bytes().count(f"candidate-close-{timing}".encode())
        == 1
    )


@pytest.mark.parametrize("owner", ("private spool snapshot", "private spool"))
@pytest.mark.parametrize("timing", ("before", "after"))
def test_syslog_raw_descriptor_retirement_lost_returns_are_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner: str,
    timing: str,
) -> None:
    """Raw snapshot and journal close phases survive fail-before and lost return."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"raw-close-{owner}-{timing}"))
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    original_close = emitter._close_retained_stream
    failed = False

    def close_then_raise(stream: object, *, close_started: bool, label: str) -> None:
        nonlocal failed
        if not failed and label == owner:
            failed = True
            if timing == "after":
                original_close(stream, close_started=close_started, label=label)
            raise OSError(f"injected raw close {timing}")
        original_close(stream, close_started=close_started, label=label)

    monkeypatch.setattr(emitter, "_close_retained_stream", close_then_raise)
    with pytest.raises(OSError, match=f"raw close {timing}"):
        emitter.close()
    assert failed
    retained_stream = (
        emitter._spool_snapshot if owner.endswith("snapshot") else emitter._spool_stream
    )
    assert retained_stream is not None
    assert retained_stream.closed is (timing == "after")
    assert _owned_descriptor_census(emitter) == {
        "private_journal": 2 * int(owner.endswith("snapshot") or timing == "before"),
        "private_snapshot": int(owner.endswith("snapshot") and timing == "before"),
        "final_candidate": 0,
        "public_file": 0,
        "public_parent": 0,
    }

    monkeypatch.setattr(emitter, "_close_retained_stream", original_close)
    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    assert (
        _output_path(tmp_path, "default").read_bytes().count(f"raw-close-{owner}-{timing}".encode())
        == 1
    )


@pytest.mark.parametrize("checkpoint", ("raw_cleanup", "finish"))
def test_syslog_terminal_cleanup_and_finish_lost_returns_are_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    """Every post-publication terminal checkpoint retains enough proof for retry."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: emitter.emit_event(_event(0, checkpoint)))
    batch.commit()
    batch.release_no_fail()

    attribute = "_cleanup_terminal_sources" if checkpoint == "raw_cleanup" else "_finish_close"
    original = getattr(emitter, attribute)
    fail_after_checkpoint = True

    def checkpoint_then_raise() -> None:
        nonlocal fail_after_checkpoint
        original()
        if fail_after_checkpoint:
            fail_after_checkpoint = False
            raise OSError(f"injected {checkpoint} lost return")

    monkeypatch.setattr(emitter, attribute, checkpoint_then_raise)
    with pytest.raises(OSError, match="lost return"):
        emitter.close()
    with pytest.raises(RuntimeError, match="terminal close retry"):
        emitter.emit_event(_event(1, "late"))
    emitter.close()
    assert _output_path(tmp_path, "default").read_text(encoding="utf-8").count(checkpoint) == 1


def test_syslog_multi_route_partial_publication_retries_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost return after one physical route cannot skip or duplicate another route."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    first = _event(0, "first-route")
    second = _event(1, "second-route")
    second["hostname"] = "linux02"
    second["_host_fqdn"] = "linux02.example.test"
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: (emitter.emit_event(first), emitter.emit_event(second)))
    batch.commit()
    batch.release_no_fail()

    original_publish = SyslogEmitter._publish_final_candidate
    fail_after_first_route = True

    def publish_then_raise(instance: SyslogEmitter, retained: object) -> None:
        nonlocal fail_after_first_route
        original_publish(instance, retained)
        if fail_after_first_route:
            fail_after_first_route = False
            raise OSError("injected first-route publication lost return")

    monkeypatch.setattr(
        SyslogEmitter,
        "_publish_final_candidate",
        publish_then_raise,
    )
    with pytest.raises(OSError, match="first-route publication lost return"):
        emitter.close()
    emitter.close()

    first_output = tmp_path / _HOST / "syslog.log"
    second_output = tmp_path / "linux02.example.test" / "syslog.log"
    assert first_output.read_text(encoding="utf-8").count("first-route") == 1
    assert second_output.read_text(encoding="utf-8").count("second-route") == 1


def test_syslog_route_candidate_retirement_lost_return_keeps_public_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retired first route remains authenticated before a later route publishes."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    first = _event(0, "retired-first-route")
    second = _event(1, "unpublished-second-route")
    second["hostname"] = "linux02"
    second["_host_fqdn"] = "linux02.example.test"
    emitter.emit_event(first)
    emitter.emit_event(second)
    original_retire = emitter._retire_final_candidate
    fail_after_retire = True

    def retire_then_raise(route_key: str, retained: object) -> None:
        nonlocal fail_after_retire
        original_retire(route_key, retained)
        if fail_after_retire:
            fail_after_retire = False
            raise OSError("injected route retirement lost return")

    monkeypatch.setattr(emitter, "_retire_final_candidate", retire_then_raise)
    with pytest.raises(OSError, match="route retirement lost return"):
        emitter.close()

    first_output = tmp_path / _HOST / "syslog.log"
    second_output = tmp_path / "linux02.example.test" / "syslog.log"
    expected = first_output.read_bytes()
    changed = expected.replace(b"retired-first-route", b"retired-f1rst-route")
    assert changed != expected and len(changed) == len(expected)
    first_output.write_bytes(changed)
    with pytest.raises(ExactPublicationError, match="output changed"):
        emitter.close()
    assert not second_output.exists()

    first_output.write_bytes(expected)
    emitter.close()
    assert first_output.read_bytes() == expected
    assert second_output.read_text(encoding="utf-8").count("unpublished-second-route") == 1


def test_syslog_threaded_close_rejects_target_flush_and_event_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A terminal publisher never deadlocks or admits work while close owns the sink."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, threaded=True)
    emitter.emit_event(_event(0, "threaded-close"))
    entered = Event()
    release = Event()
    original_publish = SyslogEmitter._publish_final_candidate

    def blocked_publish(instance: SyslogEmitter, retained: object) -> None:
        entered.set()
        assert release.wait(timeout=5)
        original_publish(instance, retained)

    monkeypatch.setattr(
        SyslogEmitter,
        "_publish_final_candidate",
        blocked_publish,
    )
    failures: list[BaseException] = []

    def close_emitter() -> None:
        try:
            emitter.close()
        except BaseException as error:
            failures.append(error)

    closer = Thread(target=close_emitter)
    closer.start()
    assert entered.wait(timeout=5)
    with pytest.raises(RuntimeError, match="frozen|terminal close"):
        emitter.configure_output_target("sof-elk")
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_event(1, "late"))
    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.flush(force=True)
    release.set()
    closer.join(timeout=5)
    assert not closer.is_alive()
    assert failures == []
    assert emitter.output_target.value == "default"


def test_syslog_exact_byte_capacity_is_reclaimed_after_failed_prepare(tmp_path: Path) -> None:
    """Byte admission fails before a writer mutation and cancel reclaims every reservation."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        exact_candidate_byte_capacity=128,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="byte capacity"):
        batch.prepare(lambda: emitter.emit_event(_event(0, "capacity")))
    batch.cancel()
    census = emitter.exact_candidate_census()
    assert census.reserved_rows == census.reserved_bytes == 0
    assert census.admitted_rows == census.admitted_bytes == 0
    assert emitter._writers == {}
    emitter.close()


def test_syslog_barrier_state_and_file_descriptors_remain_bounded(tmp_path: Path) -> None:
    """Repeated multi-host barriers retain no buffers, pending appends, or open files."""

    fd_root = Path("/dev/fd") if Path("/dev/fd").exists() else Path("/proc/self/fd")
    baseline_fds = len(list(fd_root.iterdir())) if fd_root.exists() else None
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=2)
    for barrier in range(3):
        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        events = []
        for host_index in range(24):
            event = _event(barrier, f"barrier-{barrier}-host-{host_index}")
            event["hostname"] = f"linux{host_index:02d}"
            event["_host_fqdn"] = f"linux{host_index:02d}.example.test"
            events.append(event)
        batch.prepare(lambda events=tuple(events): tuple(emitter.emit_event(e) for e in events))
        batch.commit()
        batch.release_no_fail()
        emitter.flush(force=True)
        assert emitter._spool_appends == {}
        assert all(writer.buffer == [] for writer in emitter._writers.values())
        if baseline_fds is not None:
            assert len(list(fd_root.iterdir())) <= baseline_fds + 4

    assert len(emitter._spool_receipts) == 24
    emitter.close()
    assert emitter._spool_appends == emitter._spool_receipts == {}
    assert emitter.exact_candidate_census().admitted_rows == 0
    if baseline_fds is not None:
        assert len(list(fd_root.iterdir())) <= baseline_fds + 4


@pytest.mark.parametrize("direct_file", (False, True))
def test_syslog_terminal_memory_is_bounded_per_logical_host_and_candidate(
    tmp_path: Path,
    direct_file: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal close holds one logical host and one physical candidate at a time."""

    output = tmp_path / "direct.log" if direct_file else tmp_path / "routed"
    emitter = SyslogEmitter(
        load_format("syslog"),
        output,
        buffer_size=2,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=64,
        terminal_merge_fan_in=2,
    )
    authority = ExactPublicationAuthority(capacity=1)
    batch = authority.issue_batch()
    events = []
    for host_index in range(32):
        event = _event(host_index, f"bounded-terminal-{host_index}")
        event["hostname"] = f"host{host_index:02d}"
        event["_host_fqdn"] = f"host{host_index:02d}.example.test"
        events.append(event)
    batch.prepare(lambda: tuple(emitter.emit_event(event) for event in events))
    batch.commit()
    batch.release_no_fail()
    fd_root = Path("/dev/fd") if Path("/dev/fd").exists() else Path("/proc/self/fd")
    baseline_fds = len(list(fd_root.iterdir())) if fd_root.exists() else None
    peak_fds = baseline_fds
    merge_widths: list[int] = []
    original_run = emitter._new_terminal_run
    original_merge = emitter._merge_terminal_runs
    original_acquire_parent = emitter._acquire_public_parent
    original_acquire_descriptor = emitter._acquire_public_descriptor

    def observe_fds() -> None:
        nonlocal peak_fds
        if fd_root.exists():
            current = len(list(fd_root.iterdir()))
            peak_fds = current if peak_fds is None else max(peak_fds, current)

    def observed_run(lines: object) -> object:
        retained = original_run(lines)
        observe_fds()
        return retained

    def observed_merge(
        runs: tuple[object, ...],
        *,
        sort_key: object | None = None,
    ) -> object:
        merge_widths.append(len(runs))
        return original_merge(runs, sort_key=sort_key)

    def observed_acquire_parent(append: object) -> None:
        original_acquire_parent(append)
        observe_fds()

    def observed_acquire_descriptor(append: object) -> None:
        original_acquire_descriptor(append)
        observe_fds()

    monkeypatch.setattr(emitter, "_new_terminal_run", observed_run)
    monkeypatch.setattr(emitter, "_merge_terminal_runs", observed_merge)
    monkeypatch.setattr(emitter, "_acquire_public_parent", observed_acquire_parent)
    monkeypatch.setattr(emitter, "_acquire_public_descriptor", observed_acquire_descriptor)
    emitter.close()

    census = emitter.exact_candidate_census()
    assert census.terminal_high_water_rows == 1
    assert census.terminal_high_water_bytes <= 4096
    assert census.final_candidate_high_water == 1
    if baseline_fds is not None:
        merge_levels = 0
        covered_runs = 1
        while covered_runs < len(events):
            covered_runs *= emitter._terminal_merge_fan_in
            merge_levels += 1
        tier_descriptor_bound = (emitter._terminal_merge_fan_in - 1) * merge_levels + 5
        assert peak_fds is not None and peak_fds <= baseline_fds + tier_descriptor_bound
    if direct_file:
        assert merge_widths and set(merge_widths) == {2}
        payload = output.read_text(encoding="utf-8")
        assert all(f"bounded-terminal-{index}" in payload for index in range(32))
    else:
        assert merge_widths == []
        assert len(list(output.rglob("syslog.log"))) == 32


def test_syslog_terminal_merge_honors_configured_fan_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct-file external merging consumes no more than the configured run fan-in."""

    reference_path = tmp_path / "reference.log"
    reference = SyslogEmitter(
        load_format("syslog"),
        reference_path,
        buffer_size=2,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=16,
        terminal_merge_fan_in=2,
    )
    for host_index in range(7):
        event = _event(host_index, f"fan-in-{host_index}")
        event["hostname"] = f"host{host_index}"
        event["_host_fqdn"] = f"host{host_index}.example.test"
        reference.emit_event(event)
    reference.close()

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path / "direct.log",
        buffer_size=2,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=16,
        terminal_merge_fan_in=3,
    )
    for host_index in range(7):
        event = _event(host_index, f"fan-in-{host_index}")
        event["hostname"] = f"host{host_index}"
        event["_host_fqdn"] = f"host{host_index}.example.test"
        emitter.emit_event(event)

    widths: list[int] = []
    original_merge = emitter._merge_terminal_runs

    def observed_merge(
        runs: tuple[object, ...],
        *,
        sort_key: object | None = None,
    ) -> object:
        widths.append(len(runs))
        return original_merge(runs, sort_key=sort_key)

    monkeypatch.setattr(emitter, "_merge_terminal_runs", observed_merge)
    emitter.close()
    assert widths == [3, 3, 3, 3, 3, 3]
    direct_path = tmp_path / "direct.log"
    assert direct_path.read_bytes() == reference_path.read_bytes()
    payload = direct_path.read_text(encoding="utf-8")
    assert all(f"fan-in-{index}" in payload for index in range(7))


def test_syslog_terminal_single_host_capacity_fails_before_publication(tmp_path: Path) -> None:
    """One oversized logical host fails closed without publishing partial output."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        buffer_size=10,
        terminal_host_row_capacity=1,
    )
    emitter.emit_event(_event(0, "host-capacity-first"))
    emitter.emit_event(_event(1, "host-capacity-second"))
    with pytest.raises(ExactPublicationError, match="terminal host row capacity"):
        emitter.close()
    assert not _output_path(tmp_path, "default").exists()
    assert emitter._spool_receipts
    if emitter._spool_snapshot is not None:
        emitter._spool_snapshot.close()
        emitter._spool_snapshot = None
    if emitter._spool_stream is not None:
        SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
        emitter._spool_stream = None


@pytest.mark.parametrize(
    ("capacity", "value", "expected_error"),
    (
        ("spool_route_row_capacity", 1, "terminal merge row capacity"),
        ("spool_route_byte_capacity", 180, "terminal merge byte capacity"),
    ),
)
def test_syslog_all_physical_route_capacities_preflight_before_publication(
    tmp_path: Path,
    capacity: str,
    value: int,
    expected_error: str,
) -> None:
    """A later route's inserted-row overflow cannot follow an earlier public write."""

    emitter = SyslogEmitter(
        load_format("syslog"),
        tmp_path,
        buffer_size=10,
        **{capacity: value},
    )
    first = _event(0, "route-a-within-capacity")
    first["hostname"] = "hosta"
    first["_host_fqdn"] = "hosta.example.test"
    emitter.emit_event(first)
    emitter.emit_event(_logind_event("hostb", 1))

    with pytest.raises(ExactPublicationError, match=expected_error):
        emitter.close()
    assert emitter._public_proofs == {}
    assert not any(tmp_path.rglob("syslog.log"))
    if emitter._spool_snapshot is not None:
        emitter._spool_snapshot.close()
        emitter._spool_snapshot = None
    if emitter._spool_stream is not None:
        SyslogEmitter._close_public_owner(emitter._spool_stream, label="private spool")
        emitter._spool_stream = None


def test_syslog_exact_samba_prepare_cancel_is_renderer_state_neutral(tmp_path: Path) -> None:
    """Canceled Samba preparation cannot consume renderer-local session state."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path)
    tree = _samba_event(
        "smb_tree_connect",
        _START + timedelta(milliseconds=40),
        phase="tree_connect",
    )
    for _ in range(8):
        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        batch.prepare(lambda: emitter.emit(tree))
        batch.cancel()
        assert not hasattr(emitter, "_samba_sessions")
        census = emitter.exact_candidate_census()
        assert census.admitted_rows == census.reserved_rows == 0
        assert census.admitted_bytes == census.reserved_bytes == 0
    emitter.close()


def test_syslog_exact_samba_requires_frozen_logoff_context_before_mutation(
    tmp_path: Path,
) -> None:
    """An exact Samba logoff without source context fails without retained residue."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path)
    logoff = _samba_event("logoff", _START + timedelta(seconds=2))
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(ExactPublicationError, match="immutable SMB source context"):
        batch.prepare(lambda: emitter.emit(logoff))
    assert not hasattr(emitter, "_samba_sessions")
    assert emitter._writers == {}
    census = emitter.exact_candidate_census()
    assert census.admitted_rows == census.reserved_rows == 0
    batch.cancel()
    emitter.close()


def test_syslog_exact_samba_group_matches_ordinary_bytes_after_failed_prepare(
    tmp_path: Path,
) -> None:
    """A later preparation failure leaves a deterministic exact Samba retry."""

    logon = _samba_event("logon", _START)
    tree = _samba_event(
        "smb_tree_connect",
        _START + timedelta(milliseconds=40),
        phase="tree_connect",
    )
    logoff = _samba_event("logoff", _START + timedelta(seconds=2))
    logoff.smb = tree.smb
    logoff.network = tree.network

    ordinary = SyslogEmitter(load_format("syslog"), tmp_path / "ordinary")
    for event in (logon, tree, logoff):
        ordinary.emit(event)
    ordinary.close()

    exact = SyslogEmitter(load_format("syslog"), tmp_path / "exact")
    failed = ExactPublicationAuthority(capacity=1).issue_batch()

    def fail_after_tree() -> None:
        exact.emit(logon)
        exact.emit(tree)
        raise OSError("injected later-target preparation failure")

    with pytest.raises(OSError, match="later-target preparation failure"):
        failed.prepare(fail_after_tree)
    failed.cancel()
    assert not hasattr(exact, "_samba_sessions")
    assert exact.exact_candidate_census().reserved_rows == 0

    retry = ExactPublicationAuthority(capacity=1).issue_batch()
    retry.prepare(lambda: tuple(exact.emit(event) for event in (logon, tree, logoff)))
    retry.commit()
    retry.release_no_fail()
    exact.close()

    relative = Path("samba-01.example.test/syslog.log")
    assert (tmp_path / "exact" / relative).read_bytes() == (
        tmp_path / "ordinary" / relative
    ).read_bytes()


def test_syslog_exact_missing_route_matches_ordinary_no_output(tmp_path: Path) -> None:
    """Exact preparation preserves the legacy no-host routing omission."""

    event = _event(0, "unrouted")
    event["_host_fqdn"] = ""
    ordinary = SyslogEmitter(load_format("syslog"), tmp_path / "ordinary")
    ordinary.emit_event(event)
    ordinary.close()

    exact = SyslogEmitter(load_format("syslog"), tmp_path / "exact")
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: exact.emit_event(event))
    batch.commit()
    batch.release_no_fail()
    exact.close()

    assert not any((tmp_path / "ordinary").rglob("syslog.log"))
    assert not any((tmp_path / "exact").rglob("syslog.log"))
    assert exact.exact_candidate_census().high_water_rows == 0


@pytest.mark.parametrize("timing", ("before", "after"))
def test_syslog_raw_public_open_lost_return_fails_before_public_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timing: str,
) -> None:
    """A replaced raw O_EXCL opener cannot run before or hide public acquisition."""

    output = _output_path(tmp_path, "default")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"raw-public-open-lost-return-{timing}"))
    fd_root = Path("/dev/fd") if Path("/dev/fd").exists() else Path("/proc/self/fd")
    baseline_fds = len(list(fd_root.iterdir())) if fd_root.exists() else None
    original_open = syslog_module.os.open
    hidden_descriptors: list[int] = []
    public_create_calls = 0

    def open_then_hide_descriptor(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal public_create_calls
        is_public_create = (
            os.fspath(path) == output.name and flags & os.O_CREAT and flags & os.O_EXCL
        )
        if is_public_create:
            public_create_calls += 1
            if timing == "before":
                raise OSError("injected raw public open fail before")
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            hidden_descriptors.append(descriptor)
            raise OSError("injected raw public open lost return")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(syslog_module.os, "open", open_then_hide_descriptor)
    try:
        with pytest.raises(
            (ExactPublicationError, OSError),
            match="(?:security boundary|raw public open lost return)",
        ):
            emitter.close()
        assert public_create_calls == 0
        assert hidden_descriptors == []
        assert not output.exists()
        if baseline_fds is not None:
            assert len(list(fd_root.iterdir())) == baseline_fds + sum(
                _owned_descriptor_census(emitter).values()
            )
    finally:
        monkeypatch.setattr(syslog_module.os, "open", original_open)
        for descriptor in hidden_descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if output.exists() and output.stat().st_size == 0:
            output.unlink()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"foreign-preexisting-entry")
    with pytest.raises(ExactPublicationError, match="already exists"):
        emitter.close()
    assert output.read_bytes() == b"foreign-preexisting-entry"
    output.unlink()

    emitter.close()
    assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
    assert output.read_bytes().count(f"raw-public-open-lost-return-{timing}".encode()) == 1
    if baseline_fds is not None:
        assert len(list(fd_root.iterdir())) == baseline_fds


@pytest.mark.parametrize("host_count", (16, 32, 64, 128))
def test_syslog_terminal_merge_work_is_logarithmic_in_every_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host_count: int,
) -> None:
    """Partition, final, and ordinary runs use balanced configured-fan-in merging."""

    fan_in = 4
    merge_levels = 0
    covered_rows = 1
    while covered_rows < host_count:
        covered_rows *= fan_in
        merge_levels += 1
    work_bound = host_count * merge_levels

    def populate(emitter: SyslogEmitter) -> None:
        for host_index in range(host_count):
            event = _event(host_index, f"balanced-merge-{host_index}")
            event["hostname"] = f"host{host_index:03d}"
            event["_host_fqdn"] = f"host{host_index:03d}.example.test"
            emitter.emit_event(event)

    direct_path = tmp_path / f"direct-{host_count}.log"
    direct = SyslogEmitter(
        load_format("syslog"),
        direct_path,
        buffer_size=host_count,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=host_count,
        terminal_merge_fan_in=fan_in,
    )
    populate(direct)
    direct_work = {"partition": 0, "final": 0}
    original_direct_merge = direct._merge_terminal_runs

    def observed_direct_merge(
        runs: tuple[object, ...],
        *,
        sort_key: object | None = None,
    ) -> object:
        lane = "partition" if sort_key is not None else "final"
        direct_work[lane] += sum(int(run.record_count) for run in runs)
        return original_direct_merge(runs, sort_key=sort_key)

    monkeypatch.setattr(direct, "_merge_terminal_runs", observed_direct_merge)
    direct.close()
    assert 0 < direct_work["partition"] <= work_bound
    assert 0 < direct_work["final"] <= work_bound

    ordinary_path = tmp_path / f"ordinary-{host_count}.log"
    ordinary = SyslogEmitter(
        load_format("syslog"),
        ordinary_path,
        buffer_size=host_count,
        terminal_host_row_capacity=1,
        terminal_host_byte_capacity=4096,
        terminal_host_capacity=host_count,
        terminal_merge_fan_in=fan_in,
    )
    populate(ordinary)
    ordinary.flush(force=True)
    ordinary._ensure_spool_snapshot()
    route_key, writer = next(iter(ordinary._writers.items()))
    host_keys = tuple(f"host{host_index:03d}.example.test" for host_index in range(host_count))
    host_routes = {host_key: (route_key,) for host_key in host_keys}
    ordinary_work = 0
    original_ordinary_merge = ordinary._merge_terminal_runs

    def observed_ordinary_merge(
        runs: tuple[object, ...],
        *,
        sort_key: object | None = None,
    ) -> object:
        nonlocal ordinary_work
        assert sort_key is None
        ordinary_work += sum(int(run.record_count) for run in runs)
        return original_ordinary_merge(runs, sort_key=sort_key)

    monkeypatch.setattr(ordinary, "_merge_terminal_runs", observed_ordinary_merge)
    retained = ordinary._terminal_route_run(
        route_key,
        host_keys,
        host_routes,
        {route_key: writer},
    )
    try:
        ordinary_lane_bytes = b"".join(
            ordinary._line_payload(line) for line in ordinary._iter_terminal_run(retained)
        )
    finally:
        ordinary._close_terminal_run(retained)
    assert 0 < ordinary_work <= work_bound

    monkeypatch.setattr(ordinary, "_merge_terminal_runs", original_ordinary_merge)
    ordinary.close()
    assert ordinary_lane_bytes == ordinary_path.read_bytes()
    assert ordinary_path.read_bytes() == direct_path.read_bytes()


@pytest.mark.parametrize("descriptor_kind", ("file", "parent"))
def test_syslog_public_owner_close_is_safe_from_same_inode_same_fd_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_kind: str,
) -> None:
    """A close lost return cannot make retry close a reused foreign descriptor."""

    output = _output_path(tmp_path, "default")
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"public-owner-aba-{descriptor_kind}"))
    original_retire = emitter._retire_public_append
    paused = False

    def pause_before_retirement(route_key: str, append: object) -> None:
        nonlocal paused
        if not paused:
            paused = True
            raise OSError("injected pause before owner retirement")
        original_retire(route_key, append)

    monkeypatch.setattr(emitter, "_retire_public_append", pause_before_retirement)
    with pytest.raises(OSError, match="pause before owner retirement"):
        emitter.close()
    monkeypatch.setattr(emitter, "_retire_public_append", original_retire)

    append = next(iter(emitter._public_appends.values()))
    owner = append.descriptor_owner if descriptor_kind == "file" else append.parent_owner
    original_close_owner = emitter._close_public_owner
    replacement_descriptor: int | None = None
    replacement_identity: tuple[int, int] | None = None
    injected = False

    def close_reopen_then_raise(owner_to_close: object, *, label: str) -> None:
        nonlocal injected, replacement_descriptor, replacement_identity
        if owner_to_close is owner and not injected:
            injected = True
            previous_descriptor = owner_to_close.descriptor
            owned_identity = owner_to_close.identity
            assert previous_descriptor is not None and owned_identity is not None
            original_close_owner(owner_to_close, label=label)
            if descriptor_kind == "file":
                replacement_descriptor = os.open(
                    output,
                    os.O_RDONLY | syslog_module._NOFOLLOW,
                )
            else:
                replacement_descriptor = os.open(
                    output.parent,
                    os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
                )
            assert replacement_descriptor == previous_descriptor
            metadata = os.fstat(replacement_descriptor)
            replacement_identity = (int(metadata.st_dev), int(metadata.st_ino))
            assert replacement_identity == owned_identity
            raise OSError(f"injected public {descriptor_kind} owner close ABA")
        original_close_owner(owner_to_close, label=label)

    monkeypatch.setattr(emitter, "_close_public_owner", close_reopen_then_raise)
    try:
        with pytest.raises(OSError, match=f"public {descriptor_kind} owner close ABA"):
            emitter.close()
        assert injected
        assert owner.closed
        assert replacement_descriptor is not None

        monkeypatch.setattr(emitter, "_close_public_owner", original_close_owner)
        emitter.close()
        assert replacement_identity is not None
        metadata = os.fstat(replacement_descriptor)
        assert (int(metadata.st_dev), int(metadata.st_ino)) == replacement_identity
        assert output.read_bytes().count(f"public-owner-aba-{descriptor_kind}".encode()) == 1
    finally:
        monkeypatch.setattr(emitter, "_retire_public_append", original_retire)
        if hasattr(emitter, "_close_public_owner"):
            monkeypatch.setattr(emitter, "_close_public_owner", original_close_owner)
        if replacement_descriptor is not None:
            os.close(replacement_descriptor)
        if emitter._close_state != "closed":
            try:
                emitter.close()
            except (ExactPublicationError, OSError):
                pass


def test_syslog_descriptor_open_capability_replacement_is_rejected_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed live or captured opener is rejected before its first call."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path / "output", buffer_size=1)
    victim = tmp_path / "victim" / "nested"
    foreign_calls = 0
    original_open = syslog_module.os.open

    def foreign_open(*args: object, **kwargs: object) -> int:
        nonlocal foreign_calls
        foreign_calls += 1
        return os.open(*args, **kwargs)

    open_defaults = syslog_module._secure_open.__kwdefaults__
    assert open_defaults is not None
    captured_open = open_defaults["_operation"]
    open_defaults["_operation"] = foreign_open
    try:
        with pytest.raises(ExactPublicationError, match="secure open capability"):
            emitter._walk_output_directory(victim, create=True)
    finally:
        open_defaults["_operation"] = captured_open
    assert foreign_calls == 0
    assert not victim.exists()

    monkeypatch.setattr(syslog_module.os, "open", foreign_open)
    with pytest.raises(ExactPublicationError, match="security boundary"):
        emitter._walk_output_directory(victim, create=True)
    assert foreign_calls == 0
    assert not victim.exists()
    monkeypatch.setattr(syslog_module.os, "open", original_open)

    descriptor, _identity = emitter._walk_output_directory(victim, create=True)
    os.close(descriptor)
    assert victim.is_dir()
    emitter.close()


def test_syslog_public_acquisition_captured_open_replacement_is_zero_call(
    tmp_path: Path,
) -> None:
    """The true O_EXCL phase rejects its changed captured opener before mutation."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "captured-public-open"))
    output = _output_path(tmp_path, "default")
    acquire = SyslogEmitter._acquire_public_descriptor.__func__
    defaults = acquire.__kwdefaults__
    assert defaults is not None
    original_open = defaults["_open"]
    calls = 0

    def foreign_open(*args: object, **kwargs: object) -> int:
        nonlocal calls
        calls += 1
        return original_open(*args, **kwargs)

    defaults["_open"] = foreign_open
    try:
        with pytest.raises(ExactPublicationError, match="public acquisition capability"):
            emitter.close()
        assert calls == 0
        assert not output.exists()
    finally:
        defaults["_open"] = original_open
    emitter.close()
    assert output.read_bytes().count(b"captured-public-open") == 1


@pytest.mark.parametrize(
    "replacement",
    (
        "module-close",
        "secure-close",
        "captured-fstat",
        "captured-close",
        "owner-namespace",
    ),
)
def test_syslog_descriptor_close_capability_replacement_is_rejected_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    """A foreign close callable cannot reach a retained descriptor owner."""

    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    owner = syslog_module._new_descriptor_owner(
        descriptor,
        (int(metadata.st_dev), int(metadata.st_ino)),
    )
    foreign_calls = 0
    original_close = syslog_module.os.close

    def foreign_descriptor_close(descriptor_to_close: int) -> None:
        nonlocal foreign_calls
        foreign_calls += 1
        original_close(descriptor_to_close)

    try:
        if replacement == "module-close":
            monkeypatch.setattr(syslog_module.os, "close", foreign_descriptor_close)
            with pytest.raises(ExactPublicationError, match="security boundary"):
                SyslogEmitter._close_public_owner(owner, label="test owner")
            monkeypatch.setattr(syslog_module.os, "close", original_close)
        elif replacement == "secure-close":
            close_defaults = syslog_module._secure_close.__kwdefaults__
            assert close_defaults is not None
            captured_close = close_defaults["_operation"]
            close_defaults["_operation"] = foreign_descriptor_close
            try:
                with pytest.raises(ExactPublicationError, match="secure close capability"):
                    syslog_module._secure_close(descriptor)
            finally:
                close_defaults["_operation"] = captured_close
        elif replacement in {"captured-fstat", "captured-close"}:
            helper_defaults = syslog_module._retire_descriptor_owner.__kwdefaults__
            assert helper_defaults is not None
            field = "_fstat" if replacement == "captured-fstat" else "_close"
            captured_capability = helper_defaults[field]
            helper_defaults[field] = foreign_descriptor_close
            try:
                with pytest.raises(ExactPublicationError, match="owner capability"):
                    SyslogEmitter._close_public_owner(owner, label="test owner")
            finally:
                helper_defaults[field] = captured_capability
        else:
            monkeypatch.setattr(
                syslog_module._SyslogDescriptorOwner,
                "close",
                foreign_descriptor_close,
                raising=False,
            )
            with pytest.raises(ExactPublicationError, match="security boundary"):
                SyslogEmitter._close_public_owner(owner, label="test owner")
            monkeypatch.undo()
        assert foreign_calls == 0
        assert os.fstat(descriptor).st_ino == metadata.st_ino
        SyslogEmitter._close_public_owner(owner, label="test owner")
        assert owner.closed
        assert owner.descriptor is owner.identity is None
    finally:
        if not owner.closed:
            os.close(descriptor)


@pytest.mark.parametrize(
    "label",
    ("final candidate", "private spool snapshot"),
)
def test_syslog_anonymous_stream_close_is_safe_from_same_inode_same_fd_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
) -> None:
    """A closed stream object cannot transfer retirement ownership to a reused fd."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, f"anonymous-stream-aba-{label}"))
    original_close = emitter._close_retained_stream
    replacement_descriptor: int | None = None
    replacement_identity: tuple[int, int] | None = None
    injected = False

    def close_reopen_then_raise(stream: object, *, close_started: bool, label: str) -> None:
        nonlocal injected, replacement_descriptor, replacement_identity
        if not injected and label == target_label:
            injected = True
            previous_descriptor = stream.fileno()
            keeper = os.dup(previous_descriptor)
            try:
                original_close(stream, close_started=close_started, label=label)
                replacement_descriptor = os.dup2(
                    keeper,
                    previous_descriptor,
                    inheritable=False,
                )
                assert replacement_descriptor == previous_descriptor
                metadata = os.fstat(replacement_descriptor)
                replacement_identity = (int(metadata.st_dev), int(metadata.st_ino))
            finally:
                os.close(keeper)
            raise OSError(f"injected anonymous stream close ABA: {label}")
        original_close(stream, close_started=close_started, label=label)

    target_label = label
    monkeypatch.setattr(emitter, "_close_retained_stream", close_reopen_then_raise)
    try:
        with pytest.raises(OSError, match="anonymous stream close ABA"):
            emitter.close()
        assert injected
        assert replacement_descriptor is not None
        assert replacement_identity is not None

        monkeypatch.setattr(emitter, "_close_retained_stream", original_close)
        emitter.close()
        metadata = os.fstat(replacement_descriptor)
        assert (int(metadata.st_dev), int(metadata.st_ino)) == replacement_identity
        assert (
            _output_path(tmp_path, "default")
            .read_bytes()
            .count(f"anonymous-stream-aba-{label}".encode())
            == 1
        )
    finally:
        monkeypatch.setattr(emitter, "_close_retained_stream", original_close)
        if replacement_descriptor is not None:
            os.close(replacement_descriptor)
        if emitter._close_state != "closed":
            try:
                emitter.close()
            except (ExactPublicationError, OSError):
                pass


def test_syslog_public_owner_rejects_stateful_two_descriptor_fileno(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even an exact owner's added stateful fileno is rejected and never invoked."""

    owned_descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    foreign_descriptor = os.dup(owned_descriptor)
    metadata = os.fstat(owned_descriptor)

    owner = syslog_module._new_descriptor_owner(
        owned_descriptor,
        (int(metadata.st_dev), int(metadata.st_ino)),
    )
    calls = 0

    def stateful_fileno(_owner: object) -> int:
        nonlocal calls
        calls += 1
        return owned_descriptor if calls == 1 else foreign_descriptor

    monkeypatch.setattr(
        syslog_module._SyslogDescriptorOwner,
        "fileno",
        stateful_fileno,
        raising=False,
    )
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._close_public_owner(owner, label="stateful public owner")
        assert calls == 0
        assert not owner.closed
        assert os.fstat(owned_descriptor).st_ino == metadata.st_ino
        assert os.fstat(foreign_descriptor).st_ino == metadata.st_ino
    finally:
        monkeypatch.undo()
        for descriptor in (owned_descriptor, foreign_descriptor):
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_syslog_hostile_temporary_file_factory_is_rejected_before_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anonymous storage cannot originate from a replaced duck-typed factory."""

    original_factory = syslog_module.tempfile.TemporaryFile
    created_streams: list[object] = []
    factory_calls = 0

    class ForwardingStream:
        def __init__(self, stream: object) -> None:
            self._stream = stream

        @property
        def closed(self) -> bool:
            return bool(self._stream.closed)

        def fileno(self) -> int:
            return int(self._stream.fileno())

        def flush(self) -> None:
            self._stream.flush()

        def close(self) -> None:
            self._stream.close()

    def hostile_factory(*args: object, **kwargs: object) -> object:
        nonlocal factory_calls
        factory_calls += 1
        authentic = original_factory(*args, **kwargs)
        created_streams.append(authentic)
        return ForwardingStream(authentic)

    monkeypatch.setattr(syslog_module.tempfile, "TemporaryFile", hostile_factory)
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._new_anonymous_stream(label="hostile factory test")
        assert factory_calls == 0
        assert created_streams == []
    finally:
        monkeypatch.setattr(syslog_module.tempfile, "TemporaryFile", original_factory)
        for stream in created_streams:
            stream.close()


def test_syslog_captured_temporary_file_factory_replacement_is_zero_call() -> None:
    """Changing the helper default cannot redirect anonymous storage creation."""

    defaults = syslog_module._new_temporary_stream.__kwdefaults__
    assert defaults is not None
    original_factory = defaults["_factory"]
    calls = 0

    def foreign_factory(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original_factory(*args, **kwargs)

    defaults["_factory"] = foreign_factory
    try:
        with pytest.raises(ExactPublicationError, match="temporary-file capability"):
            SyslogEmitter._new_anonymous_stream(label="captured hostile factory")
        assert calls == 0
    finally:
        defaults["_factory"] = original_factory


def test_syslog_forwarding_fstat_is_rejected_before_descriptor_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forwarding filesystem wrapper cannot observe or alter owner retirement."""

    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    original_fstat = syslog_module.os.fstat
    metadata = original_fstat(descriptor)
    owner = syslog_module._new_descriptor_owner(
        descriptor,
        (int(metadata.st_dev), int(metadata.st_ino)),
    )
    fstat_calls = 0

    def forwarding_fstat(descriptor_to_stat: int) -> os.stat_result:
        nonlocal fstat_calls
        fstat_calls += 1
        return original_fstat(descriptor_to_stat)

    monkeypatch.setattr(syslog_module.os, "fstat", forwarding_fstat)
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._close_public_owner(owner, label="forwarding fstat owner")
        assert fstat_calls == 0
        assert not owner.closed
        assert original_fstat(descriptor).st_ino == metadata.st_ino
    finally:
        monkeypatch.setattr(syslog_module.os, "fstat", original_fstat)
        if not owner.closed:
            os.close(descriptor)


def test_syslog_captured_stream_fileno_replacement_is_zero_call() -> None:
    """A replaced helper default cannot observe an authentic retained stream."""

    stream, identity = SyslogEmitter._new_anonymous_stream(label="captured fileno test")
    defaults = syslog_module._stream_descriptor.__kwdefaults__
    assert defaults is not None
    original_fileno = defaults["_fileno"]
    calls = 0

    def foreign_fileno(retained: object) -> int:
        nonlocal calls
        calls += 1
        return original_fileno(retained)

    defaults["_fileno"] = foreign_fileno
    try:
        with pytest.raises(ExactPublicationError, match="stream capability"):
            SyslogEmitter._verify_anonymous_stream(
                stream,
                identity,
                label="captured fileno test",
            )
        assert calls == 0
    finally:
        defaults["_fileno"] = original_fileno
        syslog_module._stream_close(stream)


@pytest.mark.parametrize(
    "alias",
    (
        "tempfile.TemporaryFile",
        "os.open",
        "os.close",
        "os.fstat",
        "os.stat",
        "os.mkdir",
        "os.pread",
        "os.read",
        "os.write",
        "os.lseek",
        "os.fsync",
        "os.get_inheritable",
        "os.geteuid",
        "os.path.abspath",
        "stat.S_ISREG",
        "stat.S_ISDIR",
        "stat.S_ISLNK",
        "stat.S_IMODE",
        "hashlib.sha256",
        "json.loads",
        "json.dumps",
    ),
)
def test_syslog_security_registry_rejects_forwarding_callable_aliases_zero_call(
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    """Every captured external callable is rejected before a forwarding alias runs."""

    namespace_name, attribute = alias.rsplit(".", maxsplit=1)
    namespace: object = syslog_module
    for component in namespace_name.split("."):
        namespace = getattr(namespace, component)
    if not hasattr(namespace, attribute):
        pytest.skip(f"{alias} is unavailable on this platform")
    original = getattr(namespace, attribute)
    calls = 0

    def forwarding(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(namespace, attribute, forwarding)
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label=f"forwarding {alias}")
    assert calls == 0


@pytest.mark.parametrize(
    "set_name",
    ("supports_dir_fd", "supports_fd", "supports_follow_symlinks"),
)
def test_syslog_security_registry_rejects_rebound_capability_sets(
    monkeypatch: pytest.MonkeyPatch,
    set_name: str,
) -> None:
    """An equal-content replacement support set is still a foreign capability."""

    original = getattr(syslog_module.os, set_name)
    replacement = set(original)
    assert replacement == original and replacement is not original
    monkeypatch.setattr(syslog_module.os, set_name, replacement)
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label=f"rebound {set_name}")


@pytest.mark.parametrize(
    "set_name",
    ("supports_dir_fd", "supports_fd", "supports_follow_symlinks"),
)
def test_syslog_security_registry_rejects_mutated_capability_set_contents(
    set_name: str,
) -> None:
    """The frozen support-set census detects in-place content mutation."""

    capability_set = getattr(syslog_module.os, set_name)
    sentinel = object()
    capability_set.add(sentinel)
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._new_anonymous_stream(label=f"mutated {set_name}")
    finally:
        capability_set.remove(sentinel)


@pytest.mark.parametrize(
    "constant",
    (
        "os.O_NOFOLLOW",
        "os.O_DIRECTORY",
        "os.O_RDONLY",
        "os.O_RDWR",
        "os.O_CREAT",
        "os.O_EXCL",
        "os.SEEK_SET",
        "os.sep",
        "_NOFOLLOW",
        "_DIRECTORY",
        "_PRIVATE_DIRECTORY_MODE",
        "_PRIVATE_FILE_MODE",
    ),
)
def test_syslog_security_registry_rejects_changed_constants(
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
) -> None:
    """Exact flag, mode, and separator values are part of the closed boundary."""

    if "." in constant:
        namespace_name, attribute = constant.split(".", maxsplit=1)
        namespace = getattr(syslog_module, namespace_name)
    else:
        namespace = syslog_module
        attribute = constant
    if not hasattr(namespace, attribute):
        pytest.skip(f"{constant} is unavailable on this platform")
    original = getattr(namespace, attribute)
    replacement = "!" if type(original) is str else int(original) + 1
    monkeypatch.setattr(namespace, attribute, replacement)
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label=f"changed {constant}")


@pytest.mark.parametrize("module_name", ("os", "stat", "tempfile", "hashlib", "json"))
def test_syslog_security_registry_rejects_replaced_module_alias(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
) -> None:
    """Replacing one imported module alias cannot redirect a captured capability."""

    monkeypatch.setattr(syslog_module, module_name, object())
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label=f"replaced {module_name} module")


@pytest.mark.parametrize(
    "alias",
    (
        "_SyslogSecurityRegistry",
        "_SYSLOG_SECURITY_REGISTRY",
        "_SYSLOG_SECURITY_ATTESTATION",
    ),
)
def test_syslog_security_registry_rejects_replaced_registry_alias(
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    """The closed defaults detect a one-alias registry or attester replacement."""

    monkeypatch.setattr(syslog_module, alias, object())
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label=f"replaced {alias}")


@pytest.mark.parametrize(
    "field_name",
    ("temporary_file", "os_fstat", "stream_fileno", "owner_descriptor_slot", "nofollow"),
)
def test_syslog_security_registry_rejects_frozen_instance_field_rewrite(
    field_name: str,
) -> None:
    """Even object-level writes to the frozen registry fail before the replacement runs."""

    registry = syslog_module._SYSLOG_SECURITY_REGISTRY
    original = getattr(registry, field_name)
    calls = 0

    def forwarding(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    replacement = int(original) + 1 if type(original) is int else forwarding
    object.__setattr__(registry, field_name, replacement)
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._new_anonymous_stream(label=f"rewritten {field_name}")
        assert calls == 0
    finally:
        object.__setattr__(registry, field_name, original)


def test_syslog_secure_leaf_defaults_ignore_replaced_boundary_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaf helpers use their closed defaults, never a later global boundary alias."""

    calls = 0

    def foreign_boundary() -> object:
        nonlocal calls
        calls += 1
        return syslog_module._SYSLOG_SECURITY_REGISTRY

    monkeypatch.setattr(syslog_module, "_security_boundary", foreign_boundary)
    stream, _identity = SyslogEmitter._new_anonymous_stream(label="closed leaf boundary")
    try:
        assert calls == 0
    finally:
        syslog_module._stream_close(stream)
    assert calls == 0


def test_syslog_temporary_file_in_place_code_mutation_is_zero_call() -> None:
    """An authentic factory object with foreign bytecode is rejected before execution."""

    factory = syslog_module.tempfile.TemporaryFile
    original_code = factory.__code__
    calls: list[object] = []

    def hostile_factory(*args: object, **kwargs: object) -> object:
        globals()["_syslog_mutated_factory_calls"].append((args, kwargs))
        raise RuntimeError("mutated factory executed")

    vars(syslog_module.tempfile)["_syslog_mutated_factory_calls"] = calls
    factory.__code__ = hostile_factory.__code__
    try:
        with pytest.raises(ExactPublicationError, match="security boundary"):
            SyslogEmitter._new_anonymous_stream(label="mutated factory code")
        assert calls == []
    finally:
        factory.__code__ = original_code
        del vars(syslog_module.tempfile)["_syslog_mutated_factory_calls"]


def test_syslog_temporary_file_dependency_replacement_is_zero_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replaced private factory dependency is rejected before it can run."""

    original = syslog_module.tempfile._mkstemp_inner
    calls = 0

    def forwarding(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(syslog_module.tempfile, "_mkstemp_inner", forwarding)
    with pytest.raises(ExactPublicationError, match="security boundary"):
        SyslogEmitter._new_anonymous_stream(label="mutated factory dependency")
    assert calls == 0


def test_syslog_public_owner_rejects_pre_retirement_same_inode_fd_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retirement never closes a same-inode foreign open description at the owned fd."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=1)
    emitter.emit_event(_event(0, "pre-retirement-public-aba"))
    original_retire = emitter._retire_public_append
    paused = False

    def pause_before_retirement(route_key: str, append: object) -> None:
        nonlocal paused
        if not paused:
            paused = True
            raise OSError("pause before public retirement")
        original_retire(route_key, append)

    monkeypatch.setattr(emitter, "_retire_public_append", pause_before_retirement)
    with pytest.raises(OSError, match="pause before public retirement"):
        emitter.close()
    monkeypatch.setattr(emitter, "_retire_public_append", original_retire)

    append = next(iter(emitter._public_appends.values()))
    owner = append.descriptor_owner
    owned_descriptor = owner.descriptor
    assert type(owned_descriptor) is int
    assert type(owner.guard_descriptor) is int
    assert owner.guard_descriptor != owned_descriptor
    foreign_source = os.open(
        append.output_path,
        os.O_RDWR | syslog_module._NOFOLLOW,
    )
    os.close(owned_descriptor)
    foreign_descriptor = os.dup2(
        foreign_source,
        owned_descriptor,
        inheritable=False,
    )
    assert foreign_descriptor == owned_descriptor
    os.close(foreign_source)
    try:
        with pytest.raises(ExactPublicationError, match="open-description ownership"):
            emitter.close()
        os.fstat(foreign_descriptor)
        assert owner.closed
        emitter.close()
        assert _owned_descriptor_census(emitter) == _no_owned_descriptors()
        assert append.output_path.read_bytes().count(b"pre-retirement-public-aba") == 1
    finally:
        os.close(foreign_descriptor)
        if emitter._close_state != "closed":
            try:
                emitter.close()
            except ExactPublicationError:
                pass


def test_syslog_public_owner_primary_disappearance_retires_guard_without_leak(
    tmp_path: Path,
) -> None:
    """A missing primary is reported after the private guard is retired exactly once."""

    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    owner = syslog_module._new_descriptor_owner(
        descriptor,
        (int(metadata.st_dev), int(metadata.st_ino)),
    )
    guard_descriptor = owner.guard_descriptor
    assert type(guard_descriptor) is int

    os.close(descriptor)
    with pytest.raises(ExactPublicationError, match="descriptor disappeared"):
        SyslogEmitter._close_public_owner(owner, label="missing-primary")

    assert owner.closed
    assert owner.descriptor is owner.guard_descriptor is owner.identity is None
    for retired in (descriptor, guard_descriptor):
        with pytest.raises(OSError):
            os.fstat(retired)

    SyslogEmitter._close_public_owner(owner, label="missing-primary")


def test_syslog_public_owner_rejects_duplicate_primary_guard_lease(tmp_path: Path) -> None:
    """One numeric descriptor cannot occupy both exact owner lease roles."""

    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    owner = syslog_module._SyslogDescriptorOwner(
        descriptor=descriptor,
        guard_descriptor=descriptor,
        identity=(int(metadata.st_dev), int(metadata.st_ino)),
    )
    try:
        with pytest.raises(ExactPublicationError, match="duplicate descriptor lease"):
            SyslogEmitter._close_public_owner(owner, label="duplicate-lease")
        os.fstat(descriptor)
        assert not owner.closed
    finally:
        os.close(descriptor)


def test_syslog_public_owner_concurrent_retirement_is_exact_once(tmp_path: Path) -> None:
    """Concurrent retirement calls serialize one primary-and-guard close."""

    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | syslog_module._DIRECTORY | syslog_module._NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    owner = syslog_module._new_descriptor_owner(
        descriptor,
        (int(metadata.st_dev), int(metadata.st_ino)),
    )
    guard_descriptor = owner.guard_descriptor
    assert type(guard_descriptor) is int
    start = Event()
    failures: list[BaseException] = []

    def retire() -> None:
        start.wait(timeout=5)
        try:
            SyslogEmitter._close_public_owner(owner, label="concurrent-retirement")
        except BaseException as error:
            failures.append(error)

    workers = [Thread(target=retire) for _ in range(8)]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(timeout=5)

    assert all(not worker.is_alive() for worker in workers)
    assert failures == []
    assert owner.closed
    assert owner.descriptor is owner.guard_descriptor is owner.identity is None
    for retired in (descriptor, guard_descriptor):
        with pytest.raises(OSError):
            os.fstat(retired)


def test_syslog_offset_zero_recovery_never_closes_reused_foreign_fd(tmp_path: Path) -> None:
    """Discarding broken empty storage cannot transfer destructor ownership to a foreign fd."""

    emitter = SyslogEmitter(load_format("syslog"), tmp_path / "output", buffer_size=1)
    descriptor = emitter._ensure_spool_stream(allow_zero_recovery=True)
    foreign_path = tmp_path / "foreign.bin"
    os.close(descriptor)
    foreign_descriptor = os.open(foreign_path, os.O_RDWR | os.O_CREAT, 0o600)
    assert foreign_descriptor == descriptor
    try:
        replacement = emitter._ensure_spool_stream(allow_zero_recovery=True)
        assert replacement != foreign_descriptor
        os.fstat(foreign_descriptor)
        assert os.write(foreign_descriptor, b"foreign") == len(b"foreign")
    finally:
        try:
            os.close(foreign_descriptor)
        except OSError:
            pass
        if emitter._close_state != "closed":
            try:
                emitter.close()
            except ExactPublicationError:
                pass
