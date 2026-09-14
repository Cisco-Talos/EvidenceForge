"""Regressions for Windows' delegated temporary-file interface."""

import os
import tempfile
from pathlib import Path

import pytest

from evidenceforge.utils import windows_streams


def test_temporary_stream_retains_wrapper_owner_and_removes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper = tempfile.NamedTemporaryFile(mode="w+b", dir=tmp_path)
    path = Path(wrapper.name)
    monkeypatch.setattr(windows_streams.tempfile, "TemporaryFile", lambda **kwargs: wrapper)
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
