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


def test_exclusive_create_and_nonreplacing_rename_preserve_existing_bytes(tmp_path: Path) -> None:
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
            filesystem.open_child(parent, "target", os.O_RDWR | os.O_CREAT | os.O_EXCL)
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


def test_private_directory_rejects_external_write_acl(tmp_path: Path) -> None:
    from evidenceforge.utils import windows_filesystem as filesystem

    parent = filesystem.open_directory(tmp_path)
    descriptor = None
    try:
        filesystem.mkdir_child(parent, "private")
        descriptor = filesystem.open_child(parent, "private", os.O_RDONLY, directory=True)
        filesystem.require_private(descriptor)
        subprocess.run(
            ["icacls", str(tmp_path / "private"), "/grant", "*S-1-1-0:(W)"],
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
