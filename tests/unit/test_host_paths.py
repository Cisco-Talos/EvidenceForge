"""Host adaptation must preserve existing POSIX path behavior."""

from pathlib import PurePosixPath, PureWindowsPath
from types import SimpleNamespace

import pytest

from evidenceforge.utils import host_paths


def test_windows_logical_references_use_portable_separators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_paths, "os", SimpleNamespace(name="nt"))
    assert host_paths.logical_path(PureWindowsPath("activity/ids.yaml")) == "activity/ids.yaml"


def test_posix_logical_references_preserve_literal_backslashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_paths, "os", SimpleNamespace(name="posix"))
    path = PurePosixPath("activity") / r"literal\name.yaml"
    assert host_paths.logical_path(path) == str(path)
