"""Regressions for Windows' delegated temporary-file interface."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.utils import windows_streams


def test_windows_registry_inspection_does_not_allocate_temporary_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters import syslog

    def forbidden(self: object, **kwargs: object) -> None:
        raise PermissionError("Read-only authoring cannot allocate temporary storage")

    monkeypatch.setattr(syslog, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(windows_streams.WindowsTemporaryStream, "__init__", forbidden)
    registry, _attest = syslog._make_security_registry()
    assert registry.stream_type is windows_streams.WindowsTemporaryStream
    assert registry.temporary_file is windows_streams.temporary_stream


@pytest.mark.skipif(os.name != "nt", reason="Native Windows CLI startup contract")
@pytest.mark.parametrize("arguments", [["version"], ["schema", "--help"], ["validate", "--help"]])
def test_windows_cli_startup_never_allocates_temporary_storage(arguments: list[str]) -> None:
    script = """
import sys
from evidenceforge.utils import windows_filesystem
def forbidden():
    raise PermissionError('Read-only CLI startup attempted temporary storage')
windows_filesystem.temporary_descriptor = forbidden
from evidenceforge.cli.commands import main
main()
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout


def test_temporary_stream_retains_wrapper_owner_and_removes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper = tempfile.NamedTemporaryFile(mode="w+b", dir=tmp_path)
    path = Path(wrapper.name)
    monkeypatch.setattr(windows_streams.tempfile, "TemporaryFile", lambda **kwargs: wrapper)
    monkeypatch.setattr(windows_streams, "os", SimpleNamespace(name="posix"))
    stream = windows_streams.temporary_stream()
    try:
        payload = b"first\r\nsecond\n\x1a\x00\xff"
        os.write(type(stream).fileno(stream), payload)
        type(stream).flush(stream)
        os.lseek(stream.fileno(), 0, os.SEEK_SET)
        assert os.read(stream.fileno(), len(payload)) == payload
        assert not type(stream).closed.__get__(stream, type(stream))
        assert path.exists()
    finally:
        type(stream).close(stream)
    assert stream.closed
    assert not path.exists()


def test_syslog_registry_uses_native_stream_type_on_posix() -> None:
    if os.name != "posix":
        pytest.skip("POSIX stream selection contract")
    from evidenceforge.generation.emitters.syslog import _SYSLOG_SECURITY_REGISTRY

    assert _SYSLOG_SECURITY_REGISTRY.temporary_file is tempfile.TemporaryFile
    with tempfile.TemporaryFile(mode="w+b") as stream:
        assert _SYSLOG_SECURITY_REGISTRY.stream_type is type(stream)
