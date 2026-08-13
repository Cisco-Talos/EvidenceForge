# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Machine-aware resource forecasting for generation workloads."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.config import get_config_directory
from evidenceforge.events.dispatcher import expand_formats
from evidenceforge.generation.workload import WorkloadEstimate
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

WarningLevel = Literal["low", "medium", "high"]
ResourceKind = Literal["memory", "disk"]


class ForecastRange(BaseModel):
    """Lower, expected, and upper resource projections in bytes."""

    lower_bytes: int = Field(ge=0)
    expected_bytes: int = Field(ge=0)
    upper_bytes: int = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class ResourceSnapshot(BaseModel):
    """Resources available to this process at forecast time."""

    total_memory_bytes: int = Field(ge=0)
    available_memory_bytes: int = Field(ge=0)
    free_swap_bytes: int = Field(ge=0)
    free_disk_bytes: int = Field(ge=0)
    disk_path: str
    memory_limit_bytes: int | None = Field(default=None, ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @property
    def memory_and_swap_bytes(self) -> int:
        """Return currently available RAM plus free swap."""
        return self.available_memory_bytes + self.free_swap_bytes


class ResourcePressure(BaseModel):
    """One machine-capacity warning produced by a forecast."""

    resource: ResourceKind
    level: WarningLevel
    projected_bytes: int = Field(ge=0)
    usable_bytes: int = Field(ge=0)
    ratio: float = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class ResourceForecast(BaseModel):
    """Scenario projection compared with a live machine resource snapshot."""

    calibration_version: int
    calibration_label: str
    memory: ForecastRange
    disk: ForecastRange
    snapshot: ResourceSnapshot
    pressures: tuple[ResourcePressure, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")


class _MemoryCalibration(BaseModel):
    base_mib: int = Field(gt=0)
    emitter_queue_mib_per_format: int = Field(ge=0)
    baseline_bytes_per_occurrence: int = Field(ge=0)
    explicit_bytes_per_occurrence: int = Field(ge=0)
    fixed_mib_by_format: dict[str, float] = Field(default_factory=dict)
    baseline_bytes_per_occurrence_by_format: dict[str, int] = Field(default_factory=dict)
    lower_multiplier: float = Field(gt=0)
    upper_multiplier: float = Field(gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_multipliers(self) -> Self:
        """Require expected memory to remain inside the forecast interval."""
        if self.lower_multiplier > 1 or self.upper_multiplier < 1:
            raise ValueError("memory multipliers must bracket the expected value 1.0")
        return self


class _DiskFormatCalibration(BaseModel):
    bytes_per_host_second: float = Field(ge=0)
    system_scope: str

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """Require a supported platform or role system scope."""
        if self.system_scope not in {
            "all",
            "windows",
            "linux",
        } and not self.system_scope.startswith("role:"):
            raise ValueError("disk format system_scope must be all, windows, linux, or role:<name>")
        if self.system_scope == "role:":
            raise ValueError("disk format role scope requires a role name")
        return self


class _DiskCalibration(BaseModel):
    base_mib: float = Field(ge=0)
    unknown_format_bytes_per_host_second: float = Field(ge=0)
    lower_multiplier: float = Field(gt=0)
    upper_multiplier: float = Field(gt=0)
    formats: dict[str, _DiskFormatCalibration]

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_multipliers(self) -> Self:
        """Require expected disk use to remain inside the forecast interval."""
        if self.lower_multiplier > 1 or self.upper_multiplier < 1:
            raise ValueError("disk multipliers must bracket the expected value 1.0")
        return self


class _WarningRatios(BaseModel):
    low: float = Field(gt=0)
    medium: float = Field(gt=0)
    high: float = Field(gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        """Require warning severities to increase with pressure."""
        if not self.low < self.medium < self.high:
            raise ValueError("warning ratios must satisfy low < medium < high")
        return self


class _CapacityCalibration(BaseModel):
    memory_headroom_fraction: float = Field(gt=0, le=1)
    disk_headroom_fraction: float = Field(gt=0, le=1)
    warning_ratios: _WarningRatios

    model_config = ConfigDict(frozen=True, extra="forbid")


class ResourceForecastCalibration(BaseModel):
    """Versioned coefficients used by the initial resource projection model."""

    version: int = Field(gt=0)
    calibration_label: str
    memory: _MemoryCalibration
    disk: _DiskCalibration
    capacity: _CapacityCalibration

    model_config = ConfigDict(frozen=True, extra="forbid")


@lru_cache(maxsize=1)
def load_resource_forecast_calibration() -> ResourceForecastCalibration:
    """Load the versioned resource forecast coefficients."""
    path = get_config_directory() / "resource_forecast.yaml"
    return ResourceForecastCalibration.model_validate(load_yaml(path))


def _nearest_existing_path(path: Path) -> Path:
    """Return the nearest existing ancestor used for filesystem capacity."""
    candidate = path.resolve(strict=False)
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _read_int(path: Path) -> int | None:
    """Read a non-negative integer from a Linux control file when available."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    if value == "max":
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _cgroup_memory() -> tuple[int, int] | None:
    """Return a Linux cgroup memory limit and remaining bytes when constrained."""
    candidates = (
        (
            Path("/sys/fs/cgroup/memory.max"),
            Path("/sys/fs/cgroup/memory.current"),
        ),
        (
            Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
            Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"),
        ),
    )
    for limit_path, usage_path in candidates:
        limit = _read_int(limit_path)
        usage = _read_int(usage_path)
        if limit is not None and usage is not None and limit > 0:
            return limit, max(0, limit - usage)
    return None


def _cgroup_free_swap() -> int | None:
    """Return remaining cgroup swap bytes when the container constrains swap."""
    swap_limit = _read_int(Path("/sys/fs/cgroup/memory.swap.max"))
    swap_usage = _read_int(Path("/sys/fs/cgroup/memory.swap.current"))
    if swap_limit is not None and swap_usage is not None:
        return max(0, swap_limit - swap_usage)

    combined_limit = _read_int(Path("/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes"))
    combined_usage = _read_int(Path("/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes"))
    memory_limit = _read_int(Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
    memory_usage = _read_int(Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
    if None not in (combined_limit, combined_usage, memory_limit, memory_usage):
        combined_remaining = int(combined_limit) - int(combined_usage)
        memory_remaining = int(memory_limit) - int(memory_usage)
        return max(0, combined_remaining - memory_remaining)
    return None


def snapshot_resources(destination: Path) -> ResourceSnapshot:
    """Capture RAM, swap, container, and destination-filesystem capacity."""
    virtual = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk_path = _nearest_existing_path(destination)
    disk = psutil.disk_usage(str(disk_path))
    total_memory = int(virtual.total)
    available_memory = int(virtual.available)
    free_swap = int(swap.free)
    memory_limit: int | None = None
    cgroup = _cgroup_memory()
    if cgroup is not None:
        cgroup_limit, cgroup_available = cgroup
        if cgroup_limit < total_memory:
            memory_limit = cgroup_limit
            total_memory = cgroup_limit
            available_memory = min(available_memory, cgroup_available)
    cgroup_swap = _cgroup_free_swap()
    if cgroup_swap is not None:
        free_swap = min(free_swap, cgroup_swap)
    return ResourceSnapshot(
        total_memory_bytes=total_memory,
        available_memory_bytes=available_memory,
        free_swap_bytes=free_swap,
        free_disk_bytes=int(disk.free),
        disk_path=str(disk_path),
        memory_limit_bytes=memory_limit,
    )


def _pressure_level(ratio: float, ratios: _WarningRatios) -> WarningLevel | None:
    if ratio >= ratios.high:
        return "high"
    if ratio >= ratios.medium:
        return "medium"
    if ratio >= ratios.low:
        return "low"
    return None


def _pressure(
    resource: ResourceKind,
    projected_bytes: int,
    usable_bytes: int,
    ratios: _WarningRatios,
) -> ResourcePressure | None:
    ratio = projected_bytes / usable_bytes if usable_bytes else float("inf")
    level = _pressure_level(ratio, ratios)
    if level is None:
        return None
    return ResourcePressure(
        resource=resource,
        level=level,
        projected_bytes=projected_bytes,
        usable_bytes=usable_bytes,
        ratio=ratio,
    )


def _system_count_for_scope(scenario: Scenario, scope: str) -> int:
    """Return systems eligible to emit one calibrated source format."""
    systems = scenario.environment.systems
    if scope == "all":
        return len(systems)
    if scope == "windows":
        return sum("windows" in str(system.os or "").lower() for system in systems)
    if scope == "linux":
        linux_tokens = ("linux", "ubuntu", "debian", "centos", "rhel")
        return sum(
            any(token in str(system.os or "").lower() for token in linux_tokens)
            for system in systems
        )
    role = scope.removeprefix("role:")
    return sum(role in system.roles for system in systems)


def build_resource_forecast(
    scenario: Scenario,
    estimate: WorkloadEstimate,
    destination: Path,
    *,
    snapshot: ResourceSnapshot | None = None,
    calibration: ResourceForecastCalibration | None = None,
) -> ResourceForecast:
    """Project peak memory and disk use, then classify machine pressure."""
    effective_calibration = calibration or load_resource_forecast_calibration()
    resources = snapshot or snapshot_resources(destination)
    formats = expand_formats(
        {entry["format"] for entry in scenario.output.logs if "format" in entry}
    )
    format_count = max(1, len(formats))
    memory_config = effective_calibration.memory
    expected_memory = (
        memory_config.base_mib * 1024 * 1024
        + format_count * memory_config.emitter_queue_mib_per_format * 1024 * 1024
        + estimate.baseline_occurrences * memory_config.baseline_bytes_per_occurrence
        + estimate.explicit_occurrences * memory_config.explicit_bytes_per_occurrence
        + estimate.email_artifact_bytes
    )
    expected_memory += int(
        sum(memory_config.fixed_mib_by_format.get(name, 0) for name in formats) * 1024 * 1024
    )
    expected_memory += estimate.baseline_occurrences * sum(
        memory_config.baseline_bytes_per_occurrence_by_format.get(name, 0) for name in formats
    )
    memory = ForecastRange(
        lower_bytes=int(expected_memory * memory_config.lower_multiplier),
        expected_bytes=expected_memory,
        upper_bytes=int(expected_memory * memory_config.upper_multiplier),
    )

    disk_config = effective_calibration.disk
    bytes_per_second = 0.0
    zeek_bytes_per_second = 0.0
    for format_name in formats:
        format_config = disk_config.formats.get(format_name)
        if format_config is None:
            bytes_per_second += disk_config.unknown_format_bytes_per_host_second * len(
                scenario.environment.systems
            )
            continue
        bytes_per_second += format_config.bytes_per_host_second * _system_count_for_scope(
            scenario, format_config.system_scope
        )
        if format_name.startswith("zeek_"):
            zeek_bytes_per_second += format_config.bytes_per_host_second * _system_count_for_scope(
                scenario, format_config.system_scope
            )
    external_sort_transient = int(estimate.primary_duration_seconds * zeek_bytes_per_second * 1.1)
    expected_disk = int(
        disk_config.base_mib * 1024 * 1024
        + estimate.primary_duration_seconds * bytes_per_second
        + estimate.email_artifact_bytes
        + external_sort_transient
    )
    disk = ForecastRange(
        lower_bytes=int(expected_disk * disk_config.lower_multiplier),
        expected_bytes=expected_disk,
        upper_bytes=int(expected_disk * disk_config.upper_multiplier),
    )

    capacity = effective_calibration.capacity
    usable_memory = int(resources.memory_and_swap_bytes * capacity.memory_headroom_fraction)
    usable_disk = int(resources.free_disk_bytes * capacity.disk_headroom_fraction)
    pressures = tuple(
        pressure
        for pressure in (
            _pressure(
                "memory",
                memory.expected_bytes,
                usable_memory,
                capacity.warning_ratios,
            ),
            _pressure(
                "disk",
                disk.expected_bytes,
                usable_disk,
                capacity.warning_ratios,
            ),
        )
        if pressure is not None
    )
    return ResourceForecast(
        calibration_version=effective_calibration.version,
        calibration_label=effective_calibration.calibration_label,
        memory=memory,
        disk=disk,
        snapshot=resources,
        pressures=pressures,
    )
