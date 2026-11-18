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

"""SQLite files open through one long-path-safe helper."""

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import evidenceforge
from evidenceforge import _sqlite_files
from evidenceforge._sqlite_files import connect_sqlite, sqlite_target

_SOURCE = Path(evidenceforge.__file__).parent


def test_every_sqlite_file_open_uses_the_shared_helper() -> None:
    raw = re.compile(r"sqlite3\.connect\((?!\s*\"\:memory\:\")")
    offenders = [
        f"{path.relative_to(_SOURCE)}:{number}"
        for path in _SOURCE.rglob("*.py")
        if path.name != "_sqlite_files.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if raw.search(line)
    ]

    assert offenders == [], "open SQLite files with evidenceforge._sqlite_files.connect_sqlite"


def test_posix_targets_keep_existing_spelling(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"

    assert sqlite_target(database) == (str(database), False)
    assert sqlite_target(database, "rw") == (f"{database.as_uri()}?mode=rw", True)
    assert sqlite_target(":memory:", "rw") == (":memory:", False)


def test_windows_targets_use_quoted_extended_length_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_sqlite_files, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        _sqlite_files, "filesystem_path", lambda path: Path("\\\\?\\C:\\deep\\journal.sqlite3")
    )

    target, uri = sqlite_target(Path("C:/deep/journal.sqlite3"), "rw")

    assert uri
    assert target == "file:%5C%5C%3F%5CC%3A%5Cdeep%5Cjournal.sqlite3?mode=rw"


def test_rw_mode_never_creates_a_missing_database(tmp_path: Path) -> None:
    import sqlite3

    with pytest.raises(sqlite3.OperationalError):
        connect_sqlite(tmp_path / "missing.sqlite", mode="rw")
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows MAX_PATH behavior")
def test_connect_opens_a_database_beyond_windows_max_path(tmp_path: Path) -> None:
    from evidenceforge._windows_paths import filesystem_path

    deep = tmp_path.joinpath(*(["nested-directory-component"] * 12))
    os.makedirs(filesystem_path(deep))
    database = deep / "journal.sqlite3"
    assert len(str(database)) > 260

    with connect_sqlite(database) as connection:
        connection.execute("CREATE TABLE probe (value INTEGER)")
    connection.close()
    reopened = connect_sqlite(database, mode="rw")
    assert reopened.execute("SELECT count(*) FROM probe").fetchone() == (0,)
    reopened.close()
