"""Generated-file acquisition retries must not replay any publication mutation."""

from __future__ import annotations

import builtins
import errno
import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import pytest

from evidenceforge._windows_paths import filesystem_path
from evidenceforge.generation import file_io


@pytest.mark.parametrize("native", [None, 5, 32, 33])
def test_transient_windows_open_preserves_encoding_and_newlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: int | None
) -> None:
    output = tmp_path / "generated ü.txt"
    denied = PermissionError(errno.EACCES, "temporarily inaccessible", str(output))
    if native is not None:
        denied.winerror = native
    attempts = 0
    waits: list[float] = []

    def acquire(path: Path, mode: str, **kwargs: Any) -> IO[Any]:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise denied
        return builtins.open(path, mode, **kwargs)

    monkeypatch.setattr(file_io, "_WINDOWS", True)
    monkeypatch.setattr(file_io, "open", acquire, raising=False)
    monkeypatch.setattr(file_io, "sleep", waits.append)
    with file_io.open_generated_file(output, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("漢字\n")
    assert output.read_bytes() == "漢字\n".encode()
    assert attempts == 3 and waits == list(file_io._OPEN_RETRY_DELAYS[:2])


@pytest.mark.parametrize("exists", [False, True])
def test_persistent_denial_preserves_error_bytes_and_attributes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exists: bool
) -> None:
    output = tmp_path / "generated.txt"
    if exists:
        output.write_bytes(b"retain this output")
    mode_before = output.stat().st_mode if exists else None
    denied = PermissionError(errno.EACCES, "still inaccessible", str(output))
    attempts = 0
    waits: list[float] = []

    def acquire(*args: Any, **kwargs: Any) -> IO[Any]:
        nonlocal attempts
        attempts += 1
        raise denied

    monkeypatch.setattr(file_io, "_WINDOWS", True)
    monkeypatch.setattr(file_io, "open", acquire, raising=False)
    monkeypatch.setattr(file_io, "sleep", waits.append)
    with pytest.raises(PermissionError) as caught:
        file_io.open_generated_file(output, "r+b")
    assert caught.value is denied
    assert attempts == len(file_io._OPEN_RETRY_DELAYS) + 1
    assert waits == list(file_io._OPEN_RETRY_DELAYS)
    assert "Generated file stayed inaccessible" in denied.__notes__[0]
    if exists:
        assert "attributes=" in denied.__notes__[0]
        assert output.read_bytes() == b"retain this output"
        assert output.stat().st_mode == mode_before
    else:
        assert "metadata unavailable" in denied.__notes__[0]
        assert not output.exists()


@pytest.mark.parametrize(
    ("windows", "error_number", "native"),
    [
        (False, errno.EACCES, None),
        (True, errno.ENOSPC, None),
        (True, errno.ENOENT, None),
        (True, errno.EACCES, 2),
        (True, errno.EIO, 1117),
    ],
)
def test_posix_and_unrelated_errors_are_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows: bool,
    error_number: int,
    native: int | None,
) -> None:
    denied = OSError(error_number, "unrelated error")
    if native is not None:
        denied.winerror = native
    attempts = 0
    waits: list[float] = []

    def acquire(*args: Any, **kwargs: Any) -> IO[Any]:
        nonlocal attempts
        attempts += 1
        raise denied

    monkeypatch.setattr(file_io, "_WINDOWS", windows)
    monkeypatch.setattr(file_io, "open", acquire, raising=False)
    monkeypatch.setattr(file_io, "sleep", waits.append)
    with pytest.raises(OSError) as caught:
        file_io.open_generated_file(tmp_path / "output", "wb")
    assert caught.value is denied
    assert attempts == 1 and not waits


def test_failure_after_write_is_never_automatically_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    retained: list[bytes] = []
    waits: list[float] = []

    class FailingWrite(io.BytesIO):
        def write(self, data: bytes) -> int:
            retained.append(data)
            raise PermissionError(errno.EACCES, "write happened before lost return")

    monkeypatch.setattr(file_io, "_WINDOWS", True)
    monkeypatch.setattr(file_io, "open", lambda *args, **kwargs: FailingWrite(), raising=False)
    monkeypatch.setattr(file_io, "sleep", waits.append)
    with pytest.raises(PermissionError, match="lost return"):
        with file_io.open_generated_file(tmp_path / "output", "wb") as stream:
            stream.write(b"one exact row")
    assert retained == [b"one exact row"] and not waits


def _deny_write_access(path: Path) -> Callable[[], None]:
    """Hold a real Windows read handle whose sharing mode denies writes."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(str(filesystem_path(path)), 0x80000000, 0x1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    def release() -> None:
        nonlocal handle
        if handle is not None:
            assert close(handle)
            handle = None

    return release


@pytest.mark.parametrize(
    "native",
    [
        False,
        pytest.param(
            True, marks=pytest.mark.skipif(os.name != "nt", reason="Real Windows file sharing")
        ),
    ],
)
@pytest.mark.parametrize("kind", ["host", "direct", "sensor"])
@pytest.mark.parametrize("persistent", [False, True])
def test_exact_publication_retries_open_before_committing_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, persistent: bool, native: bool
) -> None:
    from evidenceforge.formats import load_format
    from evidenceforge.generation.emitters.base import ExactPublicationAuthority, LogEmitter
    from evidenceforge.generation.emitters.host_base import _SingleHostWriter
    from evidenceforge.generation.emitters.zeek_base import _SingleZeekWriter

    class RowEmitter(LogEmitter):
        def emit_event(self, event_data: dict[str, Any]) -> None:
            self._buffer_event(self._render_event(event_data))

        def _render_event(self, event_data: dict[str, Any]) -> str:
            return event_data["row"]

    def new_writer(path: Path) -> Any:
        if kind == "host":
            writer = _SingleHostWriter(path, buffer_size=1)
            writer.write_header("<Events>")
            return writer
        if kind == "sensor":
            return _SingleZeekWriter(path, buffer_size=1)
        return RowEmitter(load_format("windows_event_security"), path, buffer_size=1)

    def write(writer: Any, text: str) -> None:
        if kind == "direct":
            writer.emit_event({"row": text})
        else:
            writer.write(text)

    def finish(writer: Any) -> None:
        if kind == "host":
            writer.write_footer("</Events>")
        writer.close()

    baseline_path = tmp_path / "uncontended.xml"
    baseline = new_writer(baseline_path)
    write(baseline, "ordinary")
    oracle = ExactPublicationAuthority(capacity=1).issue_batch()
    oracle.publish(lambda: write(baseline, "exact"))
    oracle.release_no_fail()
    finish(baseline)
    expected = baseline_path.read_bytes()

    output = tmp_path / ("workspace ü " + "a" * 100) / ("runs " + "b" * 110) / "generated ü.xml"
    writer = new_writer(output)
    write(writer, "ordinary")
    physical = filesystem_path(output)
    retained = physical.read_bytes()
    locked = True

    def release_model() -> None:
        nonlocal locked
        locked = False

    def acquire(path: Path, mode: str, **kwargs: Any) -> IO[Any]:
        if path == physical and locked:
            raise PermissionError(errno.EACCES, "modeled sharing denial", str(path))
        return builtins.open(path, mode, **kwargs)

    if native:
        assert not physical.stat().st_file_attributes & 0x1
        release = _deny_write_access(output)
    else:
        release = release_model
        monkeypatch.setattr(file_io, "open", acquire, raising=False)
    waits: list[float] = []

    def release_after_denial(delay: float) -> None:
        waits.append(delay)
        if not persistent:
            release()

    monkeypatch.setattr(file_io, "_WINDOWS", True)
    monkeypatch.setattr(file_io, "sleep", release_after_denial)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: write(writer, "exact"))
    try:
        # Negative control exercises the old operation and actual CRT EACCES;
        # no Python PermissionError is injected into the production writer.
        if native:
            with pytest.raises(PermissionError) as blocked:
                builtins.open(physical, "r+b")
            assert blocked.value.errno == errno.EACCES
        if persistent:
            with pytest.raises(PermissionError):
                batch.commit()
            assert waits == list(file_io._OPEN_RETRY_DELAYS)
            assert physical.read_bytes() == retained
            release()
        batch.commit()
        batch.commit()
        batch.release_no_fail()
        finish(writer)
        assert waits
        assert physical.read_bytes() == expected
    finally:
        release()


@pytest.mark.skipif(os.name != "nt", reason="Real Windows file attributes")
def test_native_readonly_output_stays_readonly_after_persistent_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat

    path = tmp_path / "readonly.xml"
    path.write_bytes(b"preserve protected output")
    os.chmod(path, stat.S_IREAD)
    attributes = path.stat().st_file_attributes
    waits: list[float] = []
    monkeypatch.setattr(file_io, "sleep", waits.append)
    try:
        with pytest.raises(PermissionError):
            file_io.open_generated_file(path, "r+b")
        assert waits == list(file_io._OPEN_RETRY_DELAYS)
        assert path.stat().st_file_attributes == attributes
        assert path.read_bytes() == b"preserve protected output"
    finally:
        os.chmod(path, stat.S_IWRITE)


@pytest.mark.parametrize(
    "native",
    [
        False,
        pytest.param(
            True, marks=pytest.mark.skipif(os.name != "nt", reason="Real Windows file sharing")
        ),
    ],
)
@pytest.mark.parametrize("persistent", [False, True])
def test_windows_security_finalization_retries_existing_xml_without_duplicate_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, persistent: bool, native: bool
) -> None:
    from datetime import UTC, datetime
    from xml.etree import ElementTree

    from evidenceforge.formats import load_format
    from evidenceforge.generation.emitters.windows import WindowsEventEmitter
    from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
    from tests.unit.test_windows_source_finalization import _authority, _event

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"), tmp_path, threaded=False, source_finalization=True
    )
    for minute, name in ((15, "first-user"), (16, "second-user")):
        emitter.emit_event(_event(datetime(2024, 1, 15, 10, minute, tzinfo=UTC), name))
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    release: Callable[[], None] | None = None
    waits: list[float] = []
    reopens = 0
    held_path: Path | None = None
    retained = b""
    locked = False

    def release_model() -> None:
        nonlocal locked
        locked = False

    def acquire(path: Path, mode: str, **kwargs: Any) -> IO[Any]:
        nonlocal release, reopens, held_path, retained, locked
        if mode == "r+b" and path.name == "windows_event_security.xml":
            reopens += 1
            if reopens == 2:
                held_path = path
                retained = path.read_bytes()
                if native:
                    assert not path.stat().st_file_attributes & 0x1
                    release = _deny_write_access(path)
                else:
                    locked = True
                    release = release_model
        if locked and path == held_path:
            raise PermissionError(errno.EACCES, "modeled sharing denial", str(path))
        return builtins.open(path, mode, **kwargs)

    def release_after_denial(delay: float) -> None:
        waits.append(delay)
        assert release is not None
        if not persistent:
            release()

    monkeypatch.setattr(file_io, "_WINDOWS", True)
    monkeypatch.setattr(file_io, "open", acquire, raising=False)
    monkeypatch.setattr(file_io, "sleep", release_after_denial)
    try:
        if persistent:
            with pytest.raises(PermissionError) as blocked:
                coordinator.finalize()
            assert blocked.value.errno == errno.EACCES
            assert waits == list(file_io._OPEN_RETRY_DELAYS)
            assert held_path is not None and held_path.read_bytes() == retained
            assert release is not None
            release()
        coordinator.finalize()
        emitter.close()
        coordinator.mark_closed()
        assert held_path is not None and waits
        content = held_path.read_text(encoding="utf-8")
        ElementTree.fromstring(content)
        assert content.count("<EventID>4624</EventID>") == 2
        assert content.count(">first-user<") == content.count(">second-user<") == 1
    finally:
        if release is not None:
            release()
