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

"""Tests for the developer-facing external parser script."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console
from scripts import external_parser

from evidenceforge.output_targets import write_output_target_marker


def test_external_parser_script_rejects_missing_output_target_marker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    error_output = _capture_error_console(monkeypatch)

    assert not external_parser._require_sof_elk_output_target(data_dir)

    message = error_output.getvalue()
    assert "requires an explicit `OUTPUT_TARGET.txt` marker set to `sof-elk`" in message
    assert "--target sof-elk" in message


def test_external_parser_script_rejects_default_output_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    write_output_target_marker(tmp_path, "default")
    error_output = _capture_error_console(monkeypatch)

    assert not external_parser._require_sof_elk_output_target(data_dir)

    message = error_output.getvalue()
    assert "says `default`" in message
    assert "requires `sof-elk`" in message


def test_external_parser_script_rejects_invalid_output_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (tmp_path / "OUTPUT_TARGET.txt").write_text("splunk\n", encoding="utf-8")
    error_output = _capture_error_console(monkeypatch)

    assert not external_parser._require_sof_elk_output_target(data_dir)

    message = _normalize_console_text(error_output.getvalue())
    assert "contains unsupported output target 'splunk'" in message
    assert "expected `sof-elk`" in message


def test_external_parser_script_accepts_sof_elk_output_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    write_output_target_marker(tmp_path, "sof-elk")
    error_output = _capture_error_console(monkeypatch)

    assert external_parser._require_sof_elk_output_target(data_dir)
    assert error_output.getvalue() == ""


def _capture_error_console(monkeypatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(
        external_parser,
        "error_console",
        Console(file=output, force_terminal=False, color_system=None, width=120),
    )
    return output


def _normalize_console_text(message: str) -> str:
    return " ".join(message.split())
