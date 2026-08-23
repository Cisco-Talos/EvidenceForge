# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for machine-aware generation resource forecasts."""

import os
import subprocess
import sys
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from evidenceforge.cli import commands
from evidenceforge.config import get_formats_directory
from evidenceforge.generation.resource_forecast import (
    RegistryForecastReport,
    RegistryResourceProjection,
    ResourceForecast,
    ResourceForecastCalibration,
    ResourceSnapshot,
    build_resource_forecast,
    load_resource_forecast_calibration,
    snapshot_resources,
)
from evidenceforge.generation.workload import RETAINED_STATE_FAMILIES, estimate_workload
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

_GIB = 1024**3


def _registry(
    forecast: ResourceForecast,
    name: str,
) -> RegistryResourceProjection:
    report = forecast.registry_report
    assert report is not None
    return next(item for item in report.registries if item.registry == name)


def _minimal_scenario() -> Scenario:
    fixture = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    return Scenario(**load_yaml(fixture))


def _smb_scenario(*, batch_all: bool) -> Scenario:
    """Return a compact scenario whose only variable is authored SMB batch size."""
    fixture = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    data = load_yaml(fixture)
    data["environment"]["systems"].append(
        {
            "hostname": "FS-01",
            "ip": "10.0.0.20",
            "os": "Windows Server 2022",
            "type": "server",
            "roles": ["file_server"],
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("FS-01")
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\"}],
                "shares": [
                    {
                        "id": "team",
                        "name": "Team",
                        "volume": "data",
                        "root": "Team",
                        "preset": "collaboration",
                    }
                ],
            }
        ],
    }
    event: dict[str, object] = {
        "type": "smb_activity",
        "operation": "read",
        "target": {"type": "share", "share": "FS-01.team"},
    }
    if batch_all:
        event["batch"] = {"all": True}
    data["storyline"] = [
        {
            "id": "smb-read",
            "time": "+30m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Read team files",
            "events": [event],
        }
    ]
    data["output"]["logs"] = [
        {"format": "zeek"},
        {"format": "windows"},
        {"format": "ecar"},
    ]
    return Scenario(**data)


def _linux_smb_scenario() -> Scenario:
    """Return the high-volume Linux client and Samba calibration holdout."""

    fixture = (
        Path(__file__).parent.parent
        / "fixtures"
        / "scenarios"
        / "smb-linux-resource-calibration.yaml"
    )
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


def test_resource_snapshot_treats_unavailable_swap_as_zero(monkeypatch, tmp_path: Path) -> None:
    """Restricted swap telemetry cannot make an otherwise valid forecast unavailable."""

    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.virtual_memory",
        lambda: SimpleNamespace(total=64 * _GIB, available=40 * _GIB),
    )

    def unavailable_swap() -> None:
        raise OSError("swap telemetry denied")

    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.swap_memory",
        unavailable_swap,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast.psutil.disk_usage",
        lambda _path: SimpleNamespace(free=500 * _GIB),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast._cgroup_memory",
        lambda: None,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.resource_forecast._cgroup_free_swap",
        lambda: None,
    )

    snapshot = snapshot_resources(tmp_path / "future-output")

    assert snapshot.available_memory_bytes == 40 * _GIB
    assert snapshot.free_swap_bytes == 0
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
    assert forecast.final_output.lower_bytes < forecast.final_output.expected_bytes
    assert forecast.final_output.expected_bytes < forecast.final_output.upper_bytes
    assert forecast.disk.lower_bytes < forecast.disk.expected_bytes
    assert forecast.disk.expected_bytes < forecast.disk.upper_bytes
    assert forecast.disk.lower_bytes >= forecast.final_output.lower_bytes
    assert forecast.disk.expected_bytes >= forecast.final_output.expected_bytes
    assert forecast.calibration_version == 5
    assert forecast.registry_report is not None
    assert len(forecast.registry_report.registries) == 5
    coverage = forecast.registry_report.retained_state_family_coverage
    assert tuple(item.family for item in coverage) == RETAINED_STATE_FAMILIES
    assert {item.family for item in coverage if item.disposition == "modeled_registry"} == {
        "lifecycle",
        "application_channels",
        "local_artifacts",
        "collection_deployment",
        "deployment_content",
    }
    assert {item.family for item in coverage if item.disposition == "legacy_calibrated_peak"} == {
        "process_runtime",
        "timing_runtime",
        "http",
        "proxy",
        "smb",
        "rdp",
        "ssh",
    }
    assert all(item.rationale for item in coverage)
    evidence = {
        item.family: (item.calibration_evidence_kind, item.calibration_evidence_id)
        for item in coverage
    }
    assert evidence == {
        "lifecycle": ("scenario_forecast", "resource_forecast:registry:lifecycle"),
        "application_channels": (
            "scenario_forecast",
            "resource_forecast:registry:application_channels",
        ),
        "local_artifacts": (
            "scenario_forecast",
            "resource_forecast:registry:local_artifacts",
        ),
        "collection_deployment": (
            "scenario_forecast",
            "resource_forecast:registry:collection_deployment",
        ),
        "deployment_content": (
            "scenario_forecast",
            "resource_forecast:registry:deployment_content",
        ),
        "process_runtime": (
            "historical_calibration",
            "resource_forecast:historical:process_runtime",
        ),
        "timing_runtime": (
            "historical_calibration",
            "resource_forecast:historical:timing_runtime",
        ),
        "http": ("historical_calibration", "resource_forecast:historical:http"),
        "proxy": ("historical_calibration", "resource_forecast:historical:proxy"),
        "smb": ("historical_calibration", "resource_forecast:historical:smb"),
        "rdp": ("historical_calibration", "resource_forecast:historical:rdp"),
        "ssh": ("historical_calibration", "resource_forecast:historical:ssh"),
    }
    assert forecast.pressures == ()


def test_registry_report_uses_maximum_floor_without_double_counting() -> None:
    """Measured registry memory is a floor, not an additive legacy duplicate."""

    scenario = _minimal_scenario()
    forecast = build_resource_forecast(
        scenario,
        estimate_workload(scenario),
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
    )
    report = forecast.registry_report
    assert report is not None

    assert report.total_registry_memory.expected_bytes == sum(
        item.memory.expected_bytes for item in report.registries
    )
    assert report.total_structural_bytes == sum(item.structural_bytes for item in report.registries)
    assert report.modeled_peak_floor_bytes == (
        report.total_registry_memory.expected_bytes + report.emitter_payload_excluded_bytes
    )
    assert forecast.memory.expected_bytes == max(
        report.legacy_calibrated_peak_bytes,
        report.modeled_peak_floor_bytes,
    )
    assert report.peak_memory_combination == "maximum_not_sum"
    assert "rendered_payload_and_attachment_buffers" in report.excluded_components


def test_registry_report_rejects_reclassifying_an_excluded_retained_state_family() -> None:
    """A sidecar cannot silently masquerade as one of the five modeled registries."""

    scenario = _minimal_scenario()
    forecast = build_resource_forecast(
        scenario,
        estimate_workload(scenario),
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
    )
    report = forecast.registry_report
    assert report is not None
    payload = report.model_dump(mode="python")
    process_runtime = next(
        item
        for item in payload["retained_state_family_coverage"]
        if item["family"] == "process_runtime"
    )
    process_runtime["disposition"] = "modeled_registry"
    process_runtime["registry"] = "lifecycle"
    process_runtime["calibration_evidence_kind"] = "scenario_forecast"
    process_runtime["calibration_evidence_id"] = "resource_forecast:registry:lifecycle"

    with pytest.raises(ValueError, match="canonical registry map"):
        RegistryForecastReport.model_validate(payload)


def test_registry_report_rejects_swapped_historical_calibration_evidence() -> None:
    """A documented legacy-peak exclusion must retain its historical family calibration."""

    scenario = _minimal_scenario()
    forecast = build_resource_forecast(
        scenario,
        estimate_workload(scenario),
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
    )
    report = forecast.registry_report
    assert report is not None
    payload = report.model_dump(mode="python")
    ssh = next(
        item for item in payload["retained_state_family_coverage"] if item["family"] == "ssh"
    )
    ssh["calibration_evidence_id"] = "resource_forecast:historical:http"

    with pytest.raises(ValueError, match="canonical forecast or historical calibration evidence"):
        RegistryForecastReport.model_validate(payload)


def test_legacy_calibration_without_registry_section_remains_compatible() -> None:
    """Existing callers may construct the pre-v5 calibration shape unchanged."""

    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    current = load_resource_forecast_calibration()
    legacy_payload = current.model_dump(mode="python", exclude={"registries"})
    legacy_payload["version"] = 4
    calibration = ResourceForecastCalibration.model_validate(legacy_payload)
    forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
        calibration=calibration,
    )

    assert forecast.registry_report is None
    assert forecast.memory.expected_bytes > 0

    legacy_payload["version"] = 5
    with pytest.raises(ValueError, match=r"v5\+ requires registry costs"):
        ResourceForecastCalibration.model_validate(legacy_payload)


def test_registry_forecasts_plateau_between_large_and_thirty_day_runs() -> None:
    """Bounded mutable state plateaus while lifetime expiry work keeps growing."""

    scenario = _minimal_scenario()
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)

    def forecast_for(duration: str):
        candidate = scenario.model_copy(
            update={
                "time_window": scenario.time_window.model_copy(
                    update={"duration": duration, "end": None}
                )
            }
        )
        return build_resource_forecast(
            candidate,
            estimate_workload(candidate),
            Path("/forecast-target"),
            snapshot=snapshot,
        )

    small = forecast_for("1h")
    large = forecast_for("7d")
    month = forecast_for("30d")
    for name in ("lifecycle", "application_channels", "local_artifacts"):
        small_registry = _registry(small, name)
        large_registry = _registry(large, name)
        month_registry = _registry(month, name)
        assert (
            small_registry.entries.high_water_entries <= large_registry.entries.high_water_entries
        )
        assert (
            large_registry.entries.high_water_entries == month_registry.entries.high_water_entries
        )
        assert large_registry.memory.expected_bytes == month_registry.memory.expected_bytes
        assert month_registry.plateau_reached_after_seconds == (
            month_registry.plateau_horizon_seconds
        )
        assert month_registry.costs.expiry_operations >= large_registry.costs.expiry_operations


def test_channel_fanout_increases_lookup_work_not_canonical_registry_rows() -> None:
    """Additional render channels do not duplicate canonical channel state."""

    scenario = _minimal_scenario()
    single = scenario.model_copy(deep=True)
    single.output.logs = [{"format": "zeek_conn"}]
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)
    single_forecast = build_resource_forecast(
        single,
        estimate_workload(single),
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    fanout_forecast = build_resource_forecast(
        scenario,
        estimate_workload(scenario),
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    single_channels = _registry(single_forecast, "application_channels")
    fanout_channels = _registry(fanout_forecast, "application_channels")

    assert fanout_channels.input.channel_fanout > single_channels.input.channel_fanout
    assert fanout_channels.entries.created_entries == single_channels.entries.created_entries
    assert fanout_channels.entries.high_water_entries == single_channels.entries.high_water_entries
    assert fanout_channels.costs.lookup_operations > single_channels.costs.lookup_operations


def test_deployment_overrides_replace_projected_application_bindings() -> None:
    """Exact host/user replacements reduce rather than append deployment inventory."""

    fixture = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    base_data = load_yaml(fixture)
    base_data["environment"]["users"][0]["persona"] = "developer"
    base = Scenario(**base_data)
    override_data = load_yaml(fixture)
    override_data["environment"]["users"][0]["persona"] = "developer"
    override_data["environment"]["deployment_overrides"] = [
        {
            "system": "TEST-01",
            "applications": ["slack"],
            "user_applications": [{"user": "test_user", "applications": ["slack"]}],
        }
    ]
    overridden = Scenario(**override_data)
    base_input = next(
        item
        for item in estimate_workload(base).registry_inputs
        if item.registry == "deployment_content"
    )
    override_input = next(
        item
        for item in estimate_workload(overridden).registry_inputs
        if item.registry == "deployment_content"
    )

    assert override_input.scenario_override_entries == 2
    assert override_input.static_entries < base_input.static_entries


def test_measured_cost_update_is_data_only_and_changes_registry_projection() -> None:
    """Replacing one measured cost requires no forecast-code change."""

    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)
    calibration = load_resource_forecast_calibration()
    baseline = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
        calibration=calibration,
    )
    artifact = calibration.registries["local_artifacts"]
    resident = artifact.measurement.resident_bytes_per_entry
    assert resident is not None
    changed_measurement = artifact.measurement.model_copy(
        update={
            "profile": "replacement-measurement",
            "resident_bytes_per_entry": resident * 2,
        }
    )
    changed_registry = artifact.model_copy(update={"measurement": changed_measurement})
    changed_calibration = calibration.model_copy(
        update={
            "registries": {
                **calibration.registries,
                "local_artifacts": changed_registry,
            }
        }
    )
    changed = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
        calibration=changed_calibration,
    )

    assert _registry(changed, "local_artifacts").measured_profile == "replacement-measurement"
    assert _registry(changed, "local_artifacts").memory.expected_bytes > (
        _registry(baseline, "local_artifacts").memory.expected_bytes
    )


def test_unavailable_registry_measurement_fails_closed() -> None:
    """A missing measured cost cannot silently become a zero-memory forecast."""

    scenario = _minimal_scenario()
    estimate = estimate_workload(scenario)
    calibration = load_resource_forecast_calibration()
    lifecycle = calibration.registries["lifecycle"]
    unavailable = lifecycle.measurement.model_copy(
        update={"status": "unavailable", "profile": "missing", "measured_entries": 0}
    )
    changed_calibration = calibration.model_copy(
        update={
            "registries": {
                **calibration.registries,
                "lifecycle": lifecycle.model_copy(update={"measurement": unavailable}),
            }
        }
    )

    with pytest.raises(ValueError, match="registry measurement unavailable for lifecycle"):
        build_resource_forecast(
            scenario,
            estimate,
            Path("/forecast-target"),
            snapshot=_snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB),
            calibration=changed_calibration,
        )


def test_registry_forecast_is_python_hash_seed_independent() -> None:
    """Registry drivers and projections are stable across interpreter hash seeds."""

    script = r"""
import json
from pathlib import Path
from evidenceforge.generation.resource_forecast import ResourceSnapshot, build_resource_forecast
from evidenceforge.generation.workload import estimate_workload
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

scenario = Scenario(**load_yaml(Path("tests/fixtures/scenarios/minimal.yaml")))
estimate = estimate_workload(scenario)
forecast = build_resource_forecast(
    scenario,
    estimate,
    Path("/forecast-target"),
    snapshot=ResourceSnapshot(
        total_memory_bytes=10**12,
        available_memory_bytes=10**12,
        free_swap_bytes=0,
        free_disk_bytes=10**12,
        disk_path="/forecast-target",
    ),
)
print(json.dumps(forecast.registry_report.model_dump(mode="json"), sort_keys=True))
"""
    outputs: list[str] = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1]


def test_disk_calibration_covers_every_shipped_output_format() -> None:
    """New source formats must receive an explicit measured or provisional rate."""
    shipped_formats = {path.stem for path in get_formats_directory().glob("*.yaml")}
    calibration = load_resource_forecast_calibration()

    assert shipped_formats <= set(calibration.disk.formats)


def test_smb_batch_operations_increase_final_output_and_peak_disk() -> None:
    """SMB-heavy authored scenarios must not share a duration-only disk forecast."""
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)
    single = _smb_scenario(batch_all=False)
    batch = _smb_scenario(batch_all=True)

    single_forecast = build_resource_forecast(
        single,
        estimate_workload(single),
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    batch_estimate = estimate_workload(batch)
    batch_forecast = build_resource_forecast(
        batch,
        batch_estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
    )

    assert batch_estimate.smb_activity_events == 1
    assert batch_estimate.smb_batch_operations == 24
    assert batch_estimate.smb_catalog_files >= 24
    assert batch_forecast.final_output.expected_bytes > single_forecast.final_output.expected_bytes
    assert batch_forecast.disk.expected_bytes > single_forecast.disk.expected_bytes
    assert batch_forecast.disk.expected_bytes > batch_forecast.final_output.expected_bytes


def test_linux_smb_operations_increase_forecast_and_include_samba_sources() -> None:
    """Linux SMB activity must contribute operation costs beyond host-rate noise."""

    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)
    scenario = _linux_smb_scenario()
    without_smb = scenario.model_copy(update={"storyline": []}, deep=True)
    estimate = estimate_workload(scenario)
    empty_estimate = estimate_workload(without_smb)

    forecast = build_resource_forecast(
        scenario,
        estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    empty_forecast = build_resource_forecast(
        without_smb,
        empty_estimate,
        Path("/forecast-target"),
        snapshot=snapshot,
    )

    assert estimate.smb_activity_events > empty_estimate.smb_activity_events
    assert estimate.smb_batch_operations >= 100
    assert forecast.memory.expected_bytes > empty_forecast.memory.expected_bytes
    assert forecast.final_output.expected_bytes > empty_forecast.final_output.expected_bytes
    assert forecast.disk.expected_bytes > empty_forecast.disk.expected_bytes


def test_linux_smb_calibration_covers_sensor_and_samba_operation_costs() -> None:
    """SMB rates must cover Samba hosts and their source-native syslog fan-out."""

    calibration = load_resource_forecast_calibration()

    assert calibration.disk.formats["zeek_smb_files"].system_scope == "all"
    assert calibration.disk.formats["zeek_smb_mapping"].system_scope == "all"
    assert calibration.memory.smb_bytes_per_operation_by_format["syslog"] > 0
    assert calibration.disk.smb_activity_fixed_bytes_by_format["syslog"] > 0
    assert calibration.disk.smb_operation_bytes_by_format["syslog"] > 0


def test_linux_smb_long_duration_forecast_saturates_memory_but_scales_disk() -> None:
    """Linux/Samba retained state should stay bounded while 31-day output grows."""

    scenario = _linux_smb_scenario()
    seven_days = scenario.model_copy(
        update={
            "time_window": scenario.time_window.model_copy(update={"duration": "7d", "end": None})
        }
    )
    thirty_one_days = scenario.model_copy(
        update={
            "time_window": scenario.time_window.model_copy(update={"duration": "31d", "end": None})
        }
    )
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)

    seven_day_forecast = build_resource_forecast(
        seven_days,
        estimate_workload(seven_days),
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    thirty_one_day_forecast = build_resource_forecast(
        thirty_one_days,
        estimate_workload(thirty_one_days),
        Path("/forecast-target"),
        snapshot=snapshot,
    )

    assert thirty_one_day_forecast.memory.expected_bytes == seven_day_forecast.memory.expected_bytes
    assert thirty_one_day_forecast.final_output.expected_bytes > (
        seven_day_forecast.final_output.expected_bytes
    )
    assert thirty_one_day_forecast.disk.expected_bytes > seven_day_forecast.disk.expected_bytes


def test_bounded_zeek_memory_forecast_saturates_for_long_duration() -> None:
    """Streaming occurrence memory must not grow linearly after its retention cap."""
    scenario = _smb_scenario(batch_all=True)
    scenario = scenario.model_copy(
        update={"output": scenario.output.model_copy(update={"logs": [{"format": "zeek"}]})}
    )
    seven_days = scenario.model_copy(
        update={
            "time_window": scenario.time_window.model_copy(update={"duration": "7d", "end": None})
        }
    )
    thirty_one_days = scenario.model_copy(
        update={
            "time_window": scenario.time_window.model_copy(update={"duration": "31d", "end": None})
        }
    )
    snapshot = _snapshot(memory_and_swap=128 * _GIB, disk=1024 * _GIB)

    seven_day_forecast = build_resource_forecast(
        seven_days,
        estimate_workload(seven_days),
        Path("/forecast-target"),
        snapshot=snapshot,
    )
    thirty_one_day_forecast = build_resource_forecast(
        thirty_one_days,
        estimate_workload(thirty_one_days),
        Path("/forecast-target"),
        snapshot=snapshot,
    )

    assert thirty_one_day_forecast.memory.expected_bytes == seven_day_forecast.memory.expected_bytes
    assert thirty_one_day_forecast.final_output.expected_bytes > (
        seven_day_forecast.final_output.expected_bytes
    )


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
