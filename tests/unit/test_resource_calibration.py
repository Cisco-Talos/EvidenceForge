# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the generation-resource calibration harness."""

import json
from pathlib import Path

from scripts.calibrate_generation_resources import _ecar_pid_lifecycle_summary, _write_document

_REPOSITORY_ROOT = Path(__file__).parents[2]


def _assert_measurement_within_forecast(measurement: dict[str, object]) -> None:
    """Require measured resources and strict PID lifecycle checks to pass."""

    peak_rss = int(measurement["peak_rss_bytes"])
    output_bytes = int(measurement["output_bytes"])
    peak_working_disk = int(measurement["peak_working_disk_bytes"])
    memory = measurement["forecast_memory"]
    output = measurement["forecast_final_output"]
    disk = measurement["forecast_disk"]
    lifecycle = measurement["pid_lifecycles"]
    assert isinstance(memory, dict)
    assert isinstance(output, dict)
    assert isinstance(disk, dict)
    assert isinstance(lifecycle, dict)
    assert int(memory["lower_bytes"]) <= peak_rss <= int(memory["upper_bytes"])
    assert int(output["lower_bytes"]) <= output_bytes <= int(output["upper_bytes"])
    assert int(disk["lower_bytes"]) <= peak_working_disk <= int(disk["upper_bytes"])
    assert lifecycle["overlaps"] == 0
    assert lifecycle["stale_terminations"] == 0
    assert lifecycle["unexplained_linux_reversals"] == 0


def test_ecar_pid_calibration_is_host_scoped(tmp_path: Path) -> None:
    """Interleaved Linux PID sequences on different hosts are not reversals."""

    records = [
        {
            "id": "a-create",
            "hostname": "LNX-A",
            "timestamp_ms": 1_000,
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 40_000,
            "objectID": "process-a",
            "properties": {"image_path": "/usr/bin/smbclient"},
        },
        {
            "id": "b-create",
            "hostname": "SAMBA-B",
            "timestamp_ms": 1_001,
            "object": "PROCESS",
            "action": "CREATE",
            "pid": 800,
            "objectID": "process-b",
            "properties": {"image_path": "/usr/sbin/smbd"},
        },
        {
            "id": "a-terminate",
            "hostname": "LNX-A",
            "timestamp_ms": 2_000,
            "object": "PROCESS",
            "action": "TERMINATE",
            "pid": 40_000,
            "objectID": "process-a",
            "properties": {"image_path": "/usr/bin/smbclient"},
        },
        {
            "id": "b-terminate",
            "hostname": "SAMBA-B",
            "timestamp_ms": 2_001,
            "object": "PROCESS",
            "action": "TERMINATE",
            "pid": 800,
            "objectID": "process-b",
            "properties": {"image_path": "/usr/sbin/smbd"},
        },
    ]
    ecar_path = tmp_path / "ecar.json"
    ecar_path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )

    summary = _ecar_pid_lifecycle_summary(tmp_path)

    assert summary["creates"] == 2
    assert summary["terminations"] == 2
    assert summary["unexplained_linux_reversals"] == 0


def test_calibration_document_uses_v4_measurement_schema(tmp_path: Path) -> None:
    """New artifacts distinguish their schema from retained v3 history."""

    output = tmp_path / "calibration.json"
    measurement = {
        "calibration_version": 4,
        "calibration_label": "Cross-platform SMB and Samba empirical working-set model",
    }

    _write_document(output, [measurement], [])

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 4
    assert document["measurements"] == [measurement]


def test_cross_platform_calibration_retains_v3_history_and_adds_v4_artifacts() -> None:
    """The new calibration generation must not rewrite historical SMB measurements."""

    design = _REPOSITORY_ROOT / "docs" / "design"
    historical = (
        design / "resource-forecast-calibration-smb-v3.json",
        design / "resource-forecast-calibration-smb-v3-baseline.json",
        design / "resource-forecast-calibration-smb-v3-long.json",
    )
    current = {
        design / "resource-forecast-calibration-smb-v4.json": {
            ("zeek", 1.0),
            ("ecar", 1.0),
            ("syslog", 1.0),
            ("full", 1.0),
        },
        design / "resource-forecast-calibration-smb-v4-baseline.json": {
            ("zeek", 1.0),
            ("ecar", 1.0),
            ("syslog", 1.0),
        },
        design / "resource-forecast-calibration-smb-v4-long.json": {
            (profile, duration_scale)
            for profile in ("zeek", "syslog", "full")
            for duration_scale in (84.0, 372.0)
        },
    }

    for artifact in historical:
        document = json.loads(artifact.read_text(encoding="utf-8"))
        assert document["schema_version"] == 3
        assert document["measurements"]
    for artifact, expected_cells in current.items():
        document = json.loads(artifact.read_text(encoding="utf-8"))
        assert document["schema_version"] == 4
        assert document["measurements"]
        assert document["failures"] == []
        assert {
            (measurement["profile"], measurement["duration_scale"])
            for measurement in document["measurements"]
        } == expected_cells
        assert all(
            measurement["calibration_version"] == 4 for measurement in document["measurements"]
        )
        assert all(
            measurement["calibration_label"]
            == "Cross-platform SMB and Samba empirical working-set model"
            for measurement in document["measurements"]
        )


def test_cross_platform_long_calibration_covers_exact_strict_holdout_matrix() -> None:
    """The v4 long artifact must be complete, bounded, and lifecycle-clean."""

    artifact = (
        _REPOSITORY_ROOT / "docs" / "design" / "resource-forecast-calibration-smb-v4-long.json"
    )
    document = json.loads(artifact.read_text(encoding="utf-8"))
    expected_cells = {
        (profile, duration_scale)
        for profile in ("zeek", "syslog", "full")
        for duration_scale in (84.0, 372.0)
    }
    measurements = document["measurements"]

    assert document["failures"] == []
    assert len(measurements) == len(expected_cells)
    assert {
        (measurement["profile"], measurement["duration_scale"]) for measurement in measurements
    } == expected_cells
    for measurement in measurements:
        _assert_measurement_within_forecast(measurement)
