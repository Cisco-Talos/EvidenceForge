# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Artifact snapshots never silently drop members, including beyond Windows MAX_PATH."""

import os
import sys
from pathlib import Path

import pytest

from evidenceforge._windows_paths import filesystem_path
from evidenceforge.artifacts.lifecycle import ArtifactError, snapshot_tree


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="POSIX permission semantics; root ignores directory modes",
)
def test_snapshot_fails_instead_of_omitting_an_unreadable_directory(tmp_path: Path) -> None:
    (tmp_path / "source").mkdir()
    (tmp_path / "source" / "scenario.yaml").write_text("name: x\n")
    hidden = tmp_path / "source" / "dependencies"
    hidden.mkdir()
    (hidden / "pack.yaml").write_text("name: p\n")
    hidden.chmod(0)
    try:
        with pytest.raises(ArtifactError, match="could not be read"):
            snapshot_tree(tmp_path)
    finally:
        hidden.chmod(0o700)


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows MAX_PATH behavior")
def test_snapshot_captures_members_beyond_windows_max_path(tmp_path: Path) -> None:
    deep = tmp_path.joinpath(*(["nested-directory-component"] * 12))
    os.makedirs(filesystem_path(deep))
    member = deep / "destination_catalog.yaml"
    filesystem_path(member).write_bytes(b"catalog: true\n")
    (tmp_path / "release.json").write_text("{}")
    assert len(str(member)) > 260

    files = snapshot_tree(tmp_path)

    assert files[member.relative_to(tmp_path).as_posix()] == b"catalog: true\n"
    assert "release.json" in files
