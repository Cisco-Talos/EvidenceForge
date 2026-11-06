# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical archive-output file sizing."""

import pytest

from evidenceforge.generation.activity.process_output_profiles import (
    LogSizeBounds,
    load_process_output_profiles,
    process_output_size_bytes,
)


@pytest.mark.parametrize(
    ("process_name", "command_line", "profile_key"),
    [
        ("/usr/bin/gzip", "gzip -9 /tmp/report.sql", "gzip"),
        ("/usr/bin/tar", "tar -czf /tmp/report.tar.gz /tmp/report", "tar"),
        ("/usr/bin/zip", "zip -r /tmp/report.zip /tmp/report", "zip"),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Compress-Archive -Path C:\\staging\\* -DestinationPath C:\\cache.zip",
            "powershell_compress_archive",
        ),
    ],
)
def test_archive_output_size_is_positive_bounded_and_repeatable(
    process_name: str,
    command_line: str,
    profile_key: str,
) -> None:
    """Known archive producers must not publish unknown length as an empty file."""
    profiles = load_process_output_profiles()
    bounds = profiles.profiles[profile_key].output_size_log10
    first = process_output_size_bytes(
        process_name=process_name,
        command_line=command_line,
        stable_id="host-01:archive-action-1",
    )
    repeated = process_output_size_bytes(
        process_name=process_name,
        command_line=command_line,
        stable_id="host-01:archive-action-1",
    )

    assert first is not None
    assert first == repeated
    assert 10**bounds.min <= first <= 10**bounds.max


def test_unprofiled_process_output_keeps_unknown_size_unclaimed() -> None:
    """The archive sizing profile must not assign sizes to unrelated commands."""
    assert (
        process_output_size_bytes(
            process_name="/usr/bin/cat",
            command_line="cat /tmp/notes.txt",
            stable_id="host-01:unrelated-action",
        )
        is None
    )


def test_process_output_size_bounds_reject_reversed_ranges() -> None:
    """Configuration bounds fail early when the upper exponent is smaller."""
    with pytest.raises(ValueError, match="max must be greater than or equal to min"):
        LogSizeBounds(min=6, max=4)
