"""Windows failure diagnostics stay readable even with a legacy console encoding."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import BinaryIO
from unittest.mock import Mock

import pytest
from scripts import check_windows_checkpoint_durability as driver

from evidenceforge import utils


def test_failed_native_gate_prints_unicode_log_and_preserves_child_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    output_bytes = io.BytesIO()
    output = io.TextIOWrapper(output_bytes, encoding="cp1252")
    monkeypatch.setattr(
        driver,
        "sys",
        SimpleNamespace(stdout=output, version=sys.version, executable=sys.executable),
    )
    monkeypatch.setattr(
        driver, "os", SimpleNamespace(name="nt", environ={"RETAINED": "yes"}, close=os.close)
    )

    def open_directory(_path: Path) -> int:
        return os.open(tmp_path / "handle-probe", os.O_CREAT | os.O_RDWR, 0o600)

    def failed_child(
        _command: list[str], *, stdout: BinaryIO, stderr: int, env: dict[str, str]
    ) -> Mock:
        assert env == {"RETAINED": "yes", "PYTHONIOENCODING": "utf-8"}
        stdout.write("Checkpoint failure: \ufffd \u2713\n".encode())
        child = Mock(returncode=7)
        child.poll.return_value = 7
        child.wait.return_value = 7
        return child

    filesystem = ModuleType("evidenceforge.utils.windows_filesystem")
    filesystem.open_directory = open_directory
    monkeypatch.setitem(sys.modules, filesystem.__name__, filesystem)
    monkeypatch.setattr(utils, "windows_filesystem", filesystem, raising=False)
    monkeypatch.setattr(
        driver, "subprocess", SimpleNamespace(Popen=failed_child, STDOUT=driver.subprocess.STDOUT)
    )
    monkeypatch.setattr(
        driver, "print", lambda *args, **kwargs: print(*args, file=output, **kwargs), raising=False
    )
    with pytest.raises(SystemExit) as failure:
        driver.main()
    assert failure.value.code == 7
    output.flush()
    assert "Checkpoint failure: \ufffd \u2713" in output_bytes.getvalue().decode("utf-8")
    output.close()
