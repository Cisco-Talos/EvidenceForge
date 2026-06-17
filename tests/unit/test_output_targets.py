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

"""Tests for target-aware output policy."""

import os
from pathlib import Path

import pytest

from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes
from evidenceforge.output_targets import (
    FORMAT_TARGET_POLICIES,
    MAX_OUTPUT_TARGET_MARKER_BYTES,
    OutputTarget,
    normalize_output_target,
    read_output_target_marker,
    target_dependent_formats,
    write_output_target_marker,
)


def test_output_target_marker_defaults_to_default_for_legacy_data(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    assert read_output_target_marker(data_dir) == OutputTarget.DEFAULT


def test_output_target_marker_round_trips_from_scenario_root_or_data_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    marker = write_output_target_marker(tmp_path, "sof-elk")

    assert marker.read_text(encoding="utf-8") == "sof-elk\n"
    assert read_output_target_marker(tmp_path) == OutputTarget.SOF_ELK
    assert read_output_target_marker(data_dir) == OutputTarget.SOF_ELK


def test_splunk_output_target_marker_round_trips(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    marker = write_output_target_marker(tmp_path, "splunk")

    assert marker.read_text(encoding="utf-8") == "splunk\n"
    assert read_output_target_marker(data_dir) == OutputTarget.SPLUNK


def test_invalid_output_target_raises_clear_error() -> None:
    with pytest.raises(ValueError, match="expected one of: default, sof-elk, splunk"):
        normalize_output_target("not-a-target")


def test_invalid_output_target_error_does_not_echo_input_value() -> None:
    secret = "CI_SECRET_TOKEN=super-secret-value"

    with pytest.raises(ValueError, match="invalid output target value") as exc_info:
        normalize_output_target(secret)

    assert secret not in str(exc_info.value)


def test_output_target_marker_rejects_symlink(tmp_path: Path) -> None:
    marker = tmp_path / "OUTPUT_TARGET.txt"
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("sof-elk", encoding="utf-8")
    marker.symlink_to(secret)

    with pytest.raises(ValueError, match="symlinks are not allowed"):
        read_output_target_marker(tmp_path)


def test_output_target_marker_rejects_non_regular_file(tmp_path: Path) -> None:
    marker = tmp_path / "OUTPUT_TARGET.txt"
    marker.mkdir()

    with pytest.raises(ValueError, match="regular file"):
        read_output_target_marker(tmp_path)


def test_output_target_marker_rejects_fifo_without_reading(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO marker validation is POSIX-only")

    marker = tmp_path / "OUTPUT_TARGET.txt"
    os.mkfifo(marker)

    with pytest.raises(ValueError, match="regular file"):
        read_output_target_marker(tmp_path)


def test_output_target_marker_enforces_size_limit(tmp_path: Path) -> None:
    marker = tmp_path / "OUTPUT_TARGET.txt"
    marker.write_text("a" * (MAX_OUTPUT_TARGET_MARKER_BYTES + 1), encoding="utf-8")

    with pytest.raises(ValueError, match="file is too large"):
        read_output_target_marker(tmp_path)


def test_every_emitted_canonical_format_has_target_policy() -> None:
    assert set(_build_emitter_classes()) == set(FORMAT_TARGET_POLICIES)


def test_target_policy_identifies_v1_target_dependent_formats() -> None:
    assert target_dependent_formats() == {
        "windows_event_security",
        "windows_event_sysmon",
        "syslog",
        "cisco_asa",
        "web_access",
        "proxy_access",
    }
