"""Host-platform regressions for checkpoint I/O and process ownership."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import psutil
import pytest

from evidenceforge.generation.checkpoints import store
from evidenceforge.generation.checkpoints.spools import AppendOnlySpoolParticipant
from evidenceforge.utils import files


def test_directory_sync_is_explicitly_unsupported_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("unused")
    fake_os = Mock(name="os")
    fake_os.name = "nt"
    monkeypatch.setattr(files, "os", fake_os)
    files.fsync_directory(path)
    fake_os.open.assert_not_called()


def test_posix_directory_sync_failure_propagates_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("unused")
    fake_os = Mock(name="os", O_RDONLY=0, O_DIRECTORY=0)
    fake_os.name = "posix"
    fake_os.open.return_value = 12
    fake_os.fsync.side_effect = OSError("disk failure")
    monkeypatch.setattr(files, "os", fake_os)
    with pytest.raises(OSError, match="disk failure"):
        files.fsync_directory(path)
    fake_os.close.assert_called_once_with(12)


def test_process_probe_never_signals_live_child(monkeypatch: pytest.MonkeyPatch) -> None:
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]) as child:
        try:
            kill = Mock(side_effect=AssertionError("liveness probes must not signal"))
            with monkeypatch.context() as context:
                context.setattr(os, "kill", kill)
                assert store._process_is_alive(child.pid)
                assert child.poll() is None
                kill.assert_not_called()
        finally:
            child.kill()
            child.wait(timeout=10)
        assert not store._process_is_alive(child.pid)


@pytest.mark.parametrize("error", [psutil.AccessDenied(123), OSError("unknown owner")])
def test_uncertain_process_owner_is_not_reclaimed(
    error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store.psutil, "Process", Mock(side_effect=error))
    assert store._process_is_alive(123)


def test_checkpoint_low_level_io_preserves_binary_bytes(tmp_path: Path) -> None:
    payload = bytes(range(256)) + b"\r\n\n\x1a"
    path = tmp_path / "segment"
    store._write_new_file(path, payload)
    store._sync_file(path)
    assert path.read_bytes() == payload
    AppendOnlySpoolParticipant._replace_file(path, [payload[:31], payload[31:]])
    assert path.read_bytes() == payload
