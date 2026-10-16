# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored native-history compatibility and rejection contracts."""

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.evaluation.parsers.zsh_history import ZshHistoryParser
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.zsh_history import ZshHistoryEmitter

_TIME = datetime(2026, 10, 19, 14, tzinfo=UTC)


def _entry(command: str) -> dict[str, object]:
    return {"timestamp": _TIME, "username": "alex", "hostname": "MAC-TEST", "command": command}


def test_zsh_history_preserves_command_whitespace_and_does_not_clear_prior_entries(
    tmp_path: Path,
) -> None:
    emitter = ZshHistoryEmitter(load_format("zsh_history"), tmp_path)
    commands = ["  printf 'example'  ", "history -c", "echo finished"]
    for command in commands:
        emitter.emit_event(_entry(command))
    emitter.close()
    history = tmp_path / "MAC-TEST/zsh_history/alex.zsh_history"
    records = list(ZshHistoryParser().parse_file(history))
    assert [record.fields["command"] for record in records] == commands
    assert all(not record.parse_errors for record in records)


@pytest.mark.parametrize("command", ["", "a\nb", "a\rb", "a\x00b", "echo \\", "echo café"])
def test_zsh_unsupported_commands_fail_before_creating_an_output_route(
    tmp_path: Path, command: str
) -> None:
    emitter = ZshHistoryEmitter(load_format("zsh_history"), tmp_path)
    try:
        with pytest.raises(ValueError, match="zsh_history"):
            emitter.emit_event(_entry(command))
    finally:
        emitter.close()
    assert not list(tmp_path.rglob("*.zsh_history"))


@pytest.mark.parametrize(
    "record",
    [
        "not extended history",
        ": 1792418400:0;",
        ": 1792418400:0;echo \\",
        ": 1792418400:0;echo café",
        ": 1792418400:0;a\x00b",
        ": 999999999999999999999:0;id",
        ": " + "9" * 5000 + ":0;id",
        ": 1792418400:" + "9" * 5000 + ";id",
        ": 1792418400:9223372036854775808;id",
        ": ١٧٩٢٤١٨٤٠٠:0;id",
        ": 1792418400:٠;id",
    ],
)
def test_zsh_parser_reports_unsupported_or_invalid_native_records(
    tmp_path: Path, record: str
) -> None:
    history = tmp_path / "MAC-TEST/zsh_history/alex.zsh_history"
    history.parent.mkdir(parents=True)
    history.write_text(record + "\n")
    parsed = list(ZshHistoryParser().parse_file(history))
    assert len(parsed) == 1 and parsed[0].parse_errors


def test_native_zsh_reads_generated_entries_without_executing_commands(tmp_path: Path) -> None:
    zsh = shutil.which("zsh")
    if zsh is None:
        pytest.skip("Native zsh reader is not installed")
    emitter = ZshHistoryEmitter(load_format("zsh_history"), tmp_path / "output")
    commands = ["echo invented-example", "printf 'synthetic-only'"]
    for command in commands:
        emitter.emit_event(_entry(command))
    emitter.close()
    history = tmp_path / "output/MAC-TEST/zsh_history/alex.zsh_history"
    home = tmp_path / "isolated-home"
    home.mkdir()
    result = subprocess.run(
        [zsh, "-dfc", 'fc -R "$1"; fc -ln -2', "--", str(history)],
        env={"HOME": str(home), "ZDOTDIR": str(home), "LC_ALL": "C"},
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert [line.strip() for line in result.stdout.splitlines()] == commands
