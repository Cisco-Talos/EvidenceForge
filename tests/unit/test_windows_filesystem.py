"""Native NTFS storage contracts; POSIX retains its existing implementation/tests."""

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows handle and ACL contracts")


def test_private_binary_file_and_handle_relative_publication(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    try:
        filesystem.mkdir_child(parent, "private")
        private = filesystem.open_child(parent, "private", os.O_RDONLY, directory=True)
        try:
            filesystem.require_private(private)
            descriptor = filesystem.open_child(
                private, "pending", os.O_RDWR | os.O_CREAT | os.O_EXCL
            )
            try:
                filesystem.require_private(descriptor)
                payload = bytes(range(256)) + b"\r\n\n\x1a"
                os.write(descriptor, payload)
                filesystem.flush_file(descriptor)
                identity = os.fstat(descriptor).st_ino
            finally:
                os.close(descriptor)
            filesystem.replace_child(private, "pending", private, "finished")
            assert filesystem.list_directory(private) == ["finished"]
            assert filesystem.child_stat(private, "finished").st_ino == identity
            assert (tmp_path / "private" / "finished").read_bytes() == payload
            filesystem.remove_child(private, "finished")
        finally:
            os.close(private)
        filesystem.remove_child(parent, "private", directory=True)
        assert not (tmp_path / "private").exists()
    finally:
        os.close(parent)


@pytest.mark.parametrize("truncate", [False, True])
def test_exclusive_create_and_nonreplacing_rename_preserve_existing_bytes(
    tmp_path: Path, truncate: bool
) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    try:
        for name in ("source", "target"):
            descriptor = filesystem.open_child(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
            try:
                os.write(descriptor, name.encode())
            finally:
                os.close(descriptor)
        with pytest.raises(FileExistsError):
            filesystem.open_child(
                parent,
                "target",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | (os.O_TRUNC if truncate else 0),
            )
        with pytest.raises(FileExistsError):
            filesystem.replace_child(parent, "source", parent, "target", replace=False)
        assert (tmp_path / "source").read_bytes() == b"source"
        assert (tmp_path / "target").read_bytes() == b"target"
    finally:
        os.close(parent)


def test_native_identity_distinguishes_duplicate_and_independently_opened_file(
    tmp_path: Path,
) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    first = duplicate = reopened = None
    try:
        first = filesystem.open_child(parent, "file", os.O_RDWR | os.O_CREAT | os.O_EXCL)
        duplicate = os.dup(first)
        reopened = filesystem.open_child(parent, "file", os.O_RDWR)
        assert filesystem.same_open_file(first, duplicate)
        assert not filesystem.same_open_file(first, reopened)
    finally:
        for descriptor in (reopened, duplicate, first, parent):
            if descriptor is not None:
                os.close(descriptor)


def test_pinned_directory_cannot_be_replaced(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    path = tmp_path / "pinned"
    path.mkdir()
    descriptor = filesystem.open_directory(path)
    try:
        with pytest.raises(PermissionError):
            path.rename(tmp_path / "replacement")
        assert path.is_dir()
    finally:
        os.close(descriptor)


def test_native_directory_open_rejects_junction_without_following_target(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    try:
        with pytest.raises(PermissionError, match="reparse"):
            filesystem.open_directory(junction)
        assert not list(target.iterdir())
    finally:
        junction.rmdir()


@pytest.mark.parametrize("rights", ["W", "R"])
def test_private_directory_rejects_external_access_acl(tmp_path: Path, rights: str) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    descriptor = None
    try:
        filesystem.mkdir_child(parent, "private")
        descriptor = filesystem.open_child(parent, "private", os.O_RDONLY, directory=True)
        filesystem.require_private(descriptor)
        subprocess.run(
            ["icacls", str(tmp_path / "private"), "/grant", f"*S-1-1-0:({rights})"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        with pytest.raises(PermissionError, match="another principal"):
            filesystem.require_private(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def test_handle_relative_unicode_names_preserve_bytes(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    try:
        name = "evidence-é-東京.json"
        descriptor = filesystem.open_child(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        try:
            os.write(descriptor, b"evidence")
        finally:
            os.close(descriptor)
        assert filesystem.list_directory(parent) == [name]
        assert (tmp_path / name).read_bytes() == b"evidence"
    finally:
        os.close(parent)


@pytest.mark.parametrize("name", ["../escape", "other\\file", "file:stream", "NUL", "trailing."])
def test_native_child_open_rejects_ambiguous_names(tmp_path: Path, name: str) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    try:
        with pytest.raises(ValueError):
            filesystem.open_child(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        assert not list(tmp_path.iterdir())
    finally:
        os.close(parent)


@pytest.mark.parametrize("provider", ["windows", "sysmon"])
def test_native_source_journal_keeps_schema_and_removes_private_workspace(
    tmp_path: Path, provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
    from evidenceforge.generation.emitters.windows import WindowsEventEmitter

    spool = tmp_path / "spools"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool))
    emitter_type = WindowsEventEmitter if provider == "windows" else SysmonEventEmitter
    format_name = "windows_event_security" if provider == "windows" else "windows_event_sysmon"
    emitter = emitter_type(load_format(format_name), tmp_path / "output", source_finalization=True)
    try:
        connection = emitter._get_spool_conn_unlocked()
        directory = emitter._spool_dir
        assert directory is not None and directory.is_dir()
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert connection.execute("PRAGMA temp_store").fetchone() == (2,)
        emitter._validate_spool_file_unlocked()
        emitter._cleanup_spool_unlocked()
        assert not directory.exists()
        assert list(spool.iterdir()) == []
    finally:
        emitter.close()


def test_native_temporary_storage_survives_duplication_and_positioned_reads() -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    descriptor = filesystem.temporary_descriptor()
    duplicate = None
    try:
        filesystem.require_temporary(descriptor)
        os.write(descriptor, b"first\r\nsecond\n\x1a\x00\xff")
        duplicate = os.dup(descriptor)
        os.close(descriptor)
        descriptor = None
        filesystem.require_temporary(duplicate)
        os.lseek(duplicate, 3, os.SEEK_SET)
        assert filesystem.pread(duplicate, 7, 0) == b"first\r\n"
        assert os.lseek(duplicate, 0, os.SEEK_CUR) == 3
        assert os.read(duplicate, 2) == b"st"
        assert filesystem.pread(duplicate, 8, 4096) == b""
    finally:
        for retained in (duplicate, descriptor):
            if retained is not None:
                os.close(retained)


def test_native_directory_publication_is_exclusive(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    (source / "evidence").write_bytes(b"original")
    filesystem.publish_new_directory(source, target)
    assert not source.exists()
    assert (target / "evidence").read_bytes() == b"original"
    source.mkdir()
    (source / "other").write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        filesystem.publish_new_directory(source, target)
    assert (target / "evidence").read_bytes() == b"original"
    assert (source / "other").read_bytes() == b"preserve"


def test_native_directory_pin_prevents_ancestor_rename(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    ancestor = tmp_path / "ancestor"
    leaf = ancestor / "parent" / "leaf"
    leaf.mkdir(parents=True)
    descriptor = filesystem.open_directory(leaf)
    try:
        with pytest.raises(PermissionError):
            ancestor.rename(tmp_path / "moved")
        assert leaf.is_dir()
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("provider", ["bash_history", "snort_alert", "syslog"])
def test_native_exact_journals_match_ordinary_evidence_and_clean_up(
    tmp_path: Path, provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime

    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.emitters.base import ExactPublicationAuthority
    from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
    from evidenceforge.generation.emitters.snort import SnortEmitter
    from evidenceforge.generation.emitters.syslog import SyslogEmitter

    spool = tmp_path / "spools"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", str(spool))
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    event: dict[str, object]
    if provider == "bash_history":
        emitter_type = BashHistoryEmitter
        event = {
            "timestamp": timestamp,
            "username": "alice",
            "hostname": "linux01",
            "host_fqdn": "linux01.example.test",
            "command": "echo native-evidence",
        }
    elif provider == "snort_alert":
        emitter_type = SnortEmitter
        event = {
            "timestamp": timestamp,
            "gid": 1,
            "sid": 1001,
            "rev": 1,
            "message": "native-evidence",
            "classification": "misc-activity",
            "priority": 2,
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_ip": "10.0.0.2",
            "dst_port": 443,
            "_ids_origin": "raw",
        }
    else:
        emitter_type = SyslogEmitter
        event = {
            "timestamp": timestamp,
            "hostname": "linux01",
            "_host_fqdn": "linux01.example.test",
            "app_name": "sshd",
            "pid": 1234,
            "facility": 10,
            "severity": 6,
            "message": "native-evidence",
        }
    bundles: list[dict[str, bytes]] = []
    for exact in (False, True):
        output = tmp_path / ("exact" if exact else "ordinary")
        target = output / "snort.log" if provider == "snort_alert" else output
        emitter = emitter_type(load_format(provider), target, buffer_size=1)
        try:
            if exact:
                authority = ExactPublicationAuthority(capacity=1)
                batch = authority.issue_batch()
                batch.publish(lambda emitter=emitter: emitter.emit_event(event))
                batch.release_no_fail()
            else:
                emitter.emit_event(event)
        finally:
            emitter.close()
        files = {
            path.relative_to(output).as_posix(): path.read_bytes()
            for path in output.rglob("*")
            if path.is_file()
        }
        assert any(b"native-evidence" in payload for payload in files.values())
        bundles.append(files)
    assert bundles[0] == bundles[1]
    if spool.exists():
        assert list(spool.iterdir()) == []


def test_native_metadata_distinguishes_independent_files_and_directories(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    try:
        identities: set[tuple[int, int]] = set()
        for name, directory in (("one", False), ("two", False), ("directory", True)):
            descriptor = filesystem.open_child(
                parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL, directory=directory
            )
            try:
                metadata = os.fstat(descriptor)
                assert metadata.st_ino != 0
                identity = (int(metadata.st_dev), int(metadata.st_ino))
                assert identity not in identities
                identities.add(identity)
                inspected = filesystem.child_stat(parent, name, directory=directory)
                assert (int(inspected.st_dev), int(inspected.st_ino)) == identity
            finally:
                os.close(descriptor)
    finally:
        os.close(parent)


def test_native_open_rejects_unsupported_flags_without_mutation(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    path = tmp_path / "retained"
    path.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="Unsupported"):
        filesystem.open_file(path, os.O_WRONLY | os.O_APPEND)
    assert path.read_bytes() == b"preserve"
