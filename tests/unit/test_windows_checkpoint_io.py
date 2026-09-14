"""Native Windows checkpoint barriers and publication failure contracts."""

import ctypes
import errno
import hashlib
import os
import subprocess
from ctypes import wintypes
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

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


@pytest.mark.parametrize("payload", [b"", bytes(range(256)) + b"\r\n\x1a"], ids=["empty", "binary"])
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


@pytest.mark.parametrize(
    "failure", ["zero-write", "disk-full", "flush", "rename", "after-rename", "metadata-flush"]
)
def test_native_checkpoint_failure_never_acknowledges_or_destroys_previous_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointFilesystemError
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO
    from evidenceforge.utils import windows_filesystem as filesystem

    operations = WindowsCheckpointIO()
    path = tmp_path / "CURRENT.json"
    operations.write_new(path, b"old")
    rename = operations._rename
    flush = filesystem.flush_file
    flush_count = 0

    def fail(*arguments: object, **keywords: object) -> None:
        if failure == "after-rename":
            rename(*arguments, **keywords)
        raise OSError(errno.ENOSPC if failure == "disk-full" else errno.EACCES, failure)

    def fail_metadata_flush(descriptor: int) -> None:
        nonlocal flush_count
        flush_count += 1
        if flush_count == 2:
            raise OSError(errno.EIO, "metadata flush failed after native rename")
        flush(descriptor)

    if failure == "zero-write":
        monkeypatch.setattr(operations, "_write", lambda *_args: 0)
    elif failure == "disk-full":
        monkeypatch.setattr(operations, "_write", fail)
    elif failure == "flush":
        monkeypatch.setattr(operations, "_flush", fail)
    elif failure == "metadata-flush":
        monkeypatch.setattr(filesystem, "flush_file", fail_metadata_flush)
    else:
        monkeypatch.setattr(operations, "_rename", fail)
    with pytest.raises(OSError):
        operations.write_atomic(path, (b"new",), commit_point=True)
    assert path.read_bytes() == (
        b"new" if failure in {"after-rename", "metadata-flush"} else b"old"
    )
    if "rename" in failure or failure == "metadata-flush":
        with pytest.raises(CheckpointFilesystemError, match="fresh process"):
            operations.unlink(path)
        with pytest.raises(CheckpointFilesystemError):
            operations.write_atomic(path, (b"retry",))
    else:
        operations.require_healthy()
        assert list(tmp_path.iterdir()) == [path]


def test_write_through_checkpoint_boundary_preserves_acl_and_reparse_rejection(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

    operations = WindowsCheckpointIO()
    private = tmp_path / "private"
    operations.mkdir(private)
    subprocess.run(
        ["icacls", str(private), "/grant", "*S-1-1-0:(R)"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    with pytest.raises(PermissionError, match="another principal"):
        operations.mkdir(private, exist_ok=True)
    target = tmp_path / "target"
    operations.mkdir(target)
    junction = tmp_path / "junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    try:
        with pytest.raises(PermissionError, match="reparse"):
            operations.write_new(junction / "escape.bin", b"not published")
        assert not list(target.iterdir())
    finally:
        junction.rmdir()


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


def test_gc_invalidates_durability_proofs_before_the_same_digest_is_reused(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

    operations = WindowsCheckpointIO()
    payload = b"original"
    digest = hashlib.sha256(payload).hexdigest()
    path = tmp_path / f"{digest}.json"
    operations.write_new(path, payload)
    operations.ensure_file(path, size=len(payload), digest=digest)
    operations.durable_catalogs.add(digest)
    operations.unlink(path)
    assert path not in operations._durable
    assert digest not in operations.durable_catalogs
    operations.write_new(path, b"tampered")
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    with pytest.raises(CheckpointCorruptionError):
        operations.ensure_file(path, size=len(payload), digest=digest)


def test_native_sharing_violation_keeps_the_old_index_and_closes_publication_handles(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO
    from evidenceforge.utils import windows_filesystem as filesystem

    operations = WindowsCheckpointIO()
    path = tmp_path / "CURRENT.json"
    operations.write_new(path, b"old")
    descriptor = filesystem.open_file(path, os.O_RDONLY)
    try:
        with pytest.raises(PermissionError):
            operations.write_atomic(path, (b"new",), commit_point=True)
        assert path.read_bytes() == b"old"
    finally:
        os.close(descriptor)
    WindowsCheckpointIO().write_atomic(path, (b"retry in a fresh store",))
    assert path.read_bytes() == b"retry in a fresh store"


def _commit_small(
    store: IncrementalCheckpointStore, sequence: int, *, resolved_scenario: bytes = b"resolved"
) -> None:
    from evidenceforge.generation.checkpoints.models import CheckpointCursor
    from evidenceforge.generation.checkpoints.store import HeadDraft

    store.commit(
        sequence=sequence,
        run_id="native-regression",
        run_fingerprint="a" * 64,
        checkpoint_hours=1,
        cursor=CheckpointCursor(
            phase="collection",
            completed_simulated_hours=sequence + 1,
            next_hour=f"2026-01-01T0{sequence + 1}:00:00+00:00",
        ),
        resolved_scenario=resolved_scenario,
        inherited_catalogs=(),
        new_segments=(),
        heads=(HeadDraft(owner="engine", schema_version="1", payload=b"head"),),
    )


def test_rotation_preserves_indexed_points_when_a_newer_unindexed_directory_exists(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit_small(store, 0)
    _commit_small(store, 1)
    unindexed = store.recovery / "00000000000000000002"
    store._windows_io.mkdir(unindexed)
    store._rotate_recoveries()
    assert not unindexed.exists()
    assert (store.recovery / "00000000000000000000").exists()
    assert store.recover(read_only=True).manifest.sequence == 1


def test_fresh_store_preserves_recovery_after_repeated_uncertain_index_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit_small(store, 0, resolved_scenario=b"original acknowledged input")
    original = store.recover(read_only=True)
    dependency = store.workspace / original.manifest.resolved_scenario_relative_path
    recovery_directory = store.workspace / original.checkpoint_directory

    def interrupted_commit(sequence: int) -> None:
        candidate = IncrementalCheckpointStore(store.output_root)
        rename = candidate._windows_io._rename

        def fail_after_index(source: Path, target: Path, **kwargs: object) -> None:
            rename(source, target, **kwargs)
            if target == candidate.index_path:
                raise OSError("index completion is indeterminate")

        monkeypatch.setattr(candidate._windows_io, "_rename", fail_after_index)
        with pytest.raises(OSError, match="indeterminate"):
            _commit_small(candidate, sequence)

    for sequence in (1, 2):
        interrupted_commit(sequence)
    # CURRENT's cached bytes no longer mention the last acknowledged point.
    # Neither a read nor an inspection can authorize deleting that point.
    restarted = IncrementalCheckpointStore(store.output_root)
    assert restarted.recover(read_only=True).manifest.sequence == 2
    restarted._rotate_recoveries()
    restarted.collect_garbage()
    assert recovery_directory.exists()
    assert dependency.exists()
    _commit_small(restarted, 3)
    restarted.collect_garbage()
    assert not recovery_directory.exists()
    assert not dependency.exists()
    assert restarted.recover(read_only=True).manifest.sequence == 3


def test_uncertain_index_blocks_store_commit_gc_and_workspace_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointFilesystemError
    from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit_small(store, 0)
    rename = store._windows_io._rename

    def fail_after_index(source: Path, target: Path, **kwargs: object) -> None:
        rename(source, target, **kwargs)
        if target == store.index_path:
            raise OSError("index publication completion is indeterminate")

    monkeypatch.setattr(store._windows_io, "_rename", fail_after_index)
    with pytest.raises(OSError, match="indeterminate"):
        _commit_small(store, 1)
    with pytest.raises(CheckpointFilesystemError):
        _commit_small(store, 1)
    with pytest.raises(CheckpointFilesystemError):
        store.collect_garbage()
    with pytest.raises(CheckpointFilesystemError):
        store.remove_workspace()
    assert (store.recovery / "00000000000000000000").exists()
    assert store.recover(read_only=True).manifest.sequence == 1
