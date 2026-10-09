"""Deletion receipt paths remain portable across native filesystems."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path, PurePath, PureWindowsPath

import pytest

from evidenceforge.artifacts.removal import delete_artifact_files, retired_scenario_sources


def test_deletion_receipt_uses_portable_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "scenarios" / "case" / "scenario.yaml"
    source.parent.mkdir(parents=True)
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", source)
    original_relative_to = Path.relative_to

    def windows_relative_to(
        path: Path, *other: str | os.PathLike[str], walk_up: bool = False
    ) -> PurePath:
        relative = original_relative_to(path, *other, walk_up=walk_up)
        if path == source and other == (tmp_path,):
            return PureWindowsPath(relative)
        return relative

    monkeypatch.setattr(Path, "relative_to", windows_relative_to)
    delete_artifact_files(source, source, tmp_path, "scenario")
    record = next((tmp_path / ".eforge/deletions").glob("*.json"))
    assert json.loads(record.read_bytes())["source"] == "scenarios/case/scenario.yaml"
    assert source in retired_scenario_sources(tmp_path)
