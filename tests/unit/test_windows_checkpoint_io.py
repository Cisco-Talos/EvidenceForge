"""Native Windows checkpoint barriers and publication failure contracts."""

import ctypes
import errno
import hashlib
import os
from ctypes import wintypes
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows checkpoint I/O")


def _mode(handle: int) -> int:
    from evidenceforge.utils import windows_filesystem as filesystem

    query = filesystem._bind(
        filesystem._ntdll,
        "NtQueryInformationFile",
        ctypes.c_int32,
        [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_int],
    )
    status = filesystem._IoStatusBlock()
    mode = wintypes.ULONG()
    result = query(handle, ctypes.byref(status), ctypes.byref(mode), ctypes.sizeof(mode), 16)
    assert result >= 0, result
    return mode.value


@pytest.mark.parametrize("payload", [b"", bytes(range(256)) + b"\r\n\x1a"])
def test_native_checkpoint_writes_and_renames_use_write_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO
    from evidenceforge.utils import windows_filesystem as filesystem

    modes: list[int] = []
    flushed: list[int] = []
    rename = filesystem._nt_set_information
    flush = filesystem._flush

    def observe_rename(handle: int, *arguments: object) -> int:
        modes.append(_mode(handle))
        return rename(handle, *arguments)

    def observe_flush(handle: int) -> int:
        flushed.append(_mode(handle))
        return flush(handle)

    monkeypatch.setattr(filesystem, "_nt_set_information", observe_rename)
    monkeypatch.setattr(filesystem, "_flush", observe_flush)
    operations = WindowsCheckpointIO()
    directory = tmp_path / "new" / "récovery"
    operations.mkdir(directory, parents=True)
    path = directory / "数据.bin"
    operations.write_new(path, payload)
    assert path.read_bytes() == payload
    operations.write_atomic(path, (payload, b"replacement"))
    assert path.read_bytes() == payload + b"replacement"
    assert len(modes) >= 4  # two directories, initial file, replacement
    assert all(mode & 0x2 for mode in modes)
    assert len(flushed) == 4  # data before and metadata after each file rename
    assert all(mode & 0x2 for mode in flushed)
    descriptor = filesystem.open_file(path, os.O_RDWR)
    try:
        assert not _mode(filesystem._handle(descriptor)) & 0x2
    finally:
        os.close(descriptor)
    operations.remove_tree(tmp_path / "new")
    assert not (tmp_path / "new").exists()


def test_native_checkpoint_short_writes_and_exclusive_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

    operations = WindowsCheckpointIO()
    write = operations._write
    monkeypatch.setattr(operations, "_write", lambda descriptor, data: write(descriptor, data[:7]))
    path = tmp_path / "request"
    payload = bytes(range(256)) * 2
    operations.write_new(path, payload)
    with pytest.raises(FileExistsError):
        operations.write_new(path, b"replacement")
    assert path.read_bytes() == payload
    assert sorted(item.name for item in tmp_path.iterdir()) == ["request"]


@pytest.mark.parametrize("failure", ["zero-write", "disk-full", "flush", "rename", "after-rename"])
def test_native_checkpoint_failure_never_acknowledges_or_destroys_previous_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointFilesystemError
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

    operations = WindowsCheckpointIO()
    path = tmp_path / "CURRENT.json"
    operations.write_new(path, b"old")
    rename = operations._rename

    def fail(*arguments: object, **keywords: object) -> None:
        if failure == "after-rename":
            rename(*arguments, **keywords)
        raise OSError(errno.ENOSPC if failure == "disk-full" else errno.EACCES, failure)

    if failure == "zero-write":
        monkeypatch.setattr(operations, "_write", lambda *_args: 0)
    elif failure == "disk-full":
        monkeypatch.setattr(operations, "_write", fail)
    elif failure == "flush":
        monkeypatch.setattr(operations, "_flush", fail)
    else:
        monkeypatch.setattr(operations, "_rename", fail)
    with pytest.raises(OSError):
        operations.write_atomic(path, (b"new",), commit_point=True)
    assert path.read_bytes() == (b"new" if failure == "after-rename" else b"old")
    if "rename" in failure:
        with pytest.raises(CheckpointFilesystemError, match="fresh process"):
            operations.unlink(path)
        with pytest.raises(CheckpointFilesystemError):
            operations.write_atomic(path, (b"retry",))
    else:
        operations.require_healthy()
        assert list(tmp_path.iterdir()) == [path]


def test_existing_dependencies_are_authenticated_and_republished_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

    path = tmp_path / "object"
    payload = b"existing checkpoint bytes" * 100
    WindowsCheckpointIO().write_new(path, payload)
    operations = WindowsCheckpointIO()
    rename = operations._rename
    published: list[Path] = []

    def observe(source: Path, target: Path, **keywords: object) -> None:
        rename(source, target, **keywords)
        published.append(target)

    monkeypatch.setattr(operations, "_rename", observe)
    digest = hashlib.sha256(payload).hexdigest()
    operations.ensure_file(path, size=len(payload), digest=digest)
    operations.ensure_file(path, size=len(payload), digest=digest)
    assert published == [path]
    assert path.read_bytes() == payload
    with pytest.raises(CheckpointCorruptionError, match="integrity"):
        WindowsCheckpointIO().ensure_file(path, size=len(payload), digest="0" * 64)
    assert path.read_bytes() == payload
    assert list(tmp_path.iterdir()) == [path]
