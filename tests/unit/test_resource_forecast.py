# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for machine-aware generation resource forecasts."""

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from evidenceforge.cli import commands
from evidenceforge.config import get_formats_directory
from evidenceforge.generation.resource_forecast import (
    ResourceSnapshot,
    build_resource_forecast,
    load_resource_forecast_calibration,
    snapshot_resources,
)
from evidenceforge.generation.workload import estimate_workload
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

_GIB = 1024**3


def _minimal_scenario() -> Scenario:
    fixture = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    return Scenario(**load_yaml(fixture))


def _snapshot(*, memory_and_swap: int, disk: int) -> ResourceSnapshot:
    return ResourceSnapshot(
        total_memory_bytes=max(memory_and_swap, _GIB),
        available_memory_bytes=memory_and_swap,
        free_swap_bytes=0,
        free_disk_bytes=disk,
        disk_path="/forecast-target",
    )


def test_resource_snapshot_honors_container_memory_limit(monkeypatch, tmp_path: Path) -> None:
    """A cgroup ceiling wins over host RAM reported by the operating system."""
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.virtual_memory",
        lambda: SimpleNamespace(total=64 * _GIB, available=40 * _GIB),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.swap_memory",
        lambda: SimpleNamespace(free=2 * _GIB),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.disk_usage",
        lambda _path: SimpleNamespace(free=500 * _GIB),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast._cgroup_memory",
        lambda: (16 * _GIB, 10 * _GIB),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast._cgroup_free_swap",
        lambda: 1 * _GIB,
    )

    snapshot = snapshot_resources(tmp_path / "future-output")

    assert snapshot.total_memory_bytes == 16 * _GIB
    assert snapshot.available_memory_bytes == 10 * _GIB
    assert snapshot.memory_limit_bytes == 16 * _GIB
    assert snapshot.free_swap_bytes == 1 * _GIB
    assert snapshot.free_disk_bytes == 500 * _GIB


def test_forecast_always_reports_memory_disk_and_calibration() -> None:
    """A forecast includes both resource dimensions even when neither warns."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)

    forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
    )

    assert forecast.memory.lower_bytes < forecast.memory.expected_bytes
    assert forecast.memory.expected_bytes < forecast.memory.upper_bytes
    assert forecast.disk.lower_bytes < forecast.disk.expected_bytes
    assert forecast.disk.expected_bytes < forecast.disk.upper_bytes
    assert forecast.calibration_version == 2
    assert forecast.pressures == ()


def test_disk_calibration_covers_every_shipped_output_format() -> None:
    """New source formats must receive an explicit measured or provisional rate."""
    shipped_formats = {path.stem for path in get_formats_directory().glob("*.yaml")}
    calibration = load_resource_forecast_calibration()

    assert shipped_formats <= set(calibration.disk.formats)


def test_memory_pressure_uses_low_medium_and_high_levels() -> None:
    """Expected use is classified against live memory plus swap capacity."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    calibration = load_resource_forecast_calibration()
    baseline = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
        calibration=calibration,
    )
    expected = baseline.memory.expected_bytes

    for target_ratio, level in ((0.75, "low"), (0.90, "medium"), (1.10, "high")):
        raw_capacity = int(expected / target_ratio / calibration.capacity.memory_headroom_fraction)
        forecast = build_resource_forecast(
            scenario,
            estimate,
            Path("/forecast-target"),
            snapshot=_snapshot(memory_and_swap=raw_capacity, disk=1024 * _GIB),
            calibration=calibration,
        )

        memory_pressure = next(
            pressure for pressure in forecast.pressures if pressure.resource == "memory"
        )
        assert memory_pressure.level == level


def test_disk_pressure_is_classified_independently_from_memory() -> None:
    """Low destination capacity produces a disk warning without memory pressure."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    calibration = load_resource_forecast_calibration()
    baseline = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
        calibration=calibration,
    )
    disk_capacity = int(
        baseline.disk.expected_bytes / 0.85 / calibration.capacity.disk_headroom_fraction
    )

    forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=disk_capacity),
        calibration=calibration,
    )

    assert [(pressure.resource, pressure.level) for pressure in forecast.pressures] == [
        ("disk", "medium")
    ]


def test_cli_prints_warning_immediately_after_informational_forecast(monkeypatch) -> None:
    """Pressure language follows the complete forecast and carries its severity."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    calibration = load_resource_forecast_calibration()
    baseline = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
    )
    constrained_disk = int(
        baseline.disk.expected_bytes / 0.85 / calibration.capacity.disk_headroom_fraction
    )
    forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=constrained_disk),
    )
    stream = StringIO()
    monkeypatch.setattr(commands, "console", Console(file=stream, force_terminal=False))

    commands._display_resource_forecast(forecast)

    output = stream.getvalue()
    assert "Resource forecast" in output
    assert "Forecast model" in output
    assert "MEDIUM resource warning" in output
    assert output.index("Forecast model") < output.index("MEDIUM resource warning")


def test_sysmon_projection_accounts_for_retained_event_state() -> None:
    """Sysmon-enabled output projects more peak memory than a streamed-only source."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)
    sysmon_forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    zeek_scenario = scenario.model_copy(deep=True)
    zeek_scenario.output.logs = [{"format": "zeek_conn"}]
    zeek_forecast = build_resource_forecast(
        zeek_scenario,
        estimate_workload(zeek_scenario),
        Path("/forecast-target"),
        snapshot=snapshot,
    )

    assert sysmon_forecast.memory.expected_bytes > zeek_forecast.memory.expected_bytes
