# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Machine-aware resource forecasting for generation workloads."""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.config import get_config_directory
from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.events.dispatcher import expand_formats
from evidenceforge.generation.workload import (
    RETAINED_STATE_FAMILIES,
    RegistryName,
    RegistryWorkloadInput,
    RetainedStateFamilyName,
    WorkloadEstimate,
    build_registry_workload_inputs,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

WarningLevel = Literal["low", "medium", "high"]
ResourceKind = Literal["memory", "disk"]
RegistryMeasurementStatus = Literal["measured", "provisional", "unavailable"]
RegistryMeasurementUnit = Literal["live_entry", "source", "path_binding_equivalent"]
RetainedStateCoverageDisposition = Literal["modeled_registry", "legacy_calibrated_peak"]
RetainedStateReleaseEvidenceKind = Literal[
    "scenario_forecast",
    "mixed_exact_case",
    "sidecar_exact_case",
]

_REGISTRY_NAMES: tuple[RegistryName, ...] = (
    "lifecycle",
    "application_channels",
    "local_artifacts",
    "collection_deployment",
    "deployment_content",
)

_MODELED_RETAINED_STATE_REGISTRIES: dict[RetainedStateFamilyName, RegistryName] = {
    "lifecycle": "lifecycle",
    "application_channels": "application_channels",
    "local_artifacts": "local_artifacts",
    "collection_deployment": "collection_deployment",
    "deployment_content": "deployment_content",
}

_MODELED_RETAINED_STATE_EVIDENCE: dict[RetainedStateFamilyName, str] = {
    family: f"resource_forecast:registry:{registry}"
    for family, registry in _MODELED_RETAINED_STATE_REGISTRIES.items()
}

_EXACT_TESTED_RETAINED_STATE_EXCLUSIONS: dict[
    RetainedStateFamilyName,
    tuple[RetainedStateReleaseEvidenceKind, str],
] = {
    "process_runtime": (
        "mixed_exact_case",
        "foundation_scale:mixed:process_runtime",
    ),
    "timing_runtime": (
        "mixed_exact_case",
        "foundation_scale:mixed:timing_runtime",
    ),
    "http": ("sidecar_exact_case", "foundation_scale:sidecar:http"),
    "proxy": ("sidecar_exact_case", "foundation_scale:sidecar:proxy"),
    "smb": ("sidecar_exact_case", "foundation_scale:sidecar:smb"),
    "rdp": ("sidecar_exact_case", "foundation_scale:sidecar:rdp"),
    "ssh": ("sidecar_exact_case", "foundation_scale:sidecar:ssh"),
}

_LEGACY_PEAK_RETAINED_STATE_RATIONALES: dict[RetainedStateFamilyName, str] = {
    "process_runtime": (
        "Process-runtime caches remain in the calibrated whole-generator peak until the "
        "production-shaped duration migration and release measurement close."
    ),
    "timing_runtime": (
        "Timing audit, clock, and constraint indexes remain in the calibrated whole-generator "
        "peak until a scenario-driver projection is measured."
    ),
    "http": (
        "HTTP sidecar memory is retained in the calibrated whole-generator peak; the common "
        "application registry is modeled separately."
    ),
    "proxy": (
        "Explicit-proxy sidecar memory is retained in the calibrated whole-generator peak; the "
        "common application registry is modeled separately."
    ),
    "smb": (
        "SMB sidecar memory is retained in the calibrated whole-generator peak and SMB output "
        "costs; the common application registry is modeled separately."
    ),
    "rdp": (
        "RDP reconnect sidecar memory is retained in the calibrated whole-generator peak; the "
        "common application registry is modeled separately."
    ),
    "ssh": (
        "SSH sidecar memory is retained in the calibrated whole-generator peak; the common "
        "application registry is modeled separately."
    ),
}


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


class RegistryEntryProjection(BaseModel):
    """Bounded logical and backing cardinalities for one registry."""

    created_entries: int = Field(ge=0)
    live_entries: int = Field(ge=0)
    retained_entries: int = Field(ge=0)
    leased_entries: int = Field(ge=0)
    stale_entries: int = Field(ge=0)
    expired_entries: int = Field(ge=0)
    backing_entries: int = Field(ge=0)
    high_water_entries: int = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class RegistryCostProjection(BaseModel):
    """Measured operation-cost projection for one registry workload."""

    load_seconds: float = Field(ge=0)
    mutation_seconds: float = Field(ge=0)
    expiry_seconds: float = Field(ge=0)
    lookup_p95_microseconds: float | None = Field(default=None, ge=0)
    lookup_operations: int = Field(ge=0)
    mutation_operations: int = Field(ge=0)
    expiry_operations: int = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class RegistryResourceProjection(BaseModel):
    """Per-registry memory, cardinality, plateau, and measured cost report."""

    registry: RegistryName
    input: RegistryWorkloadInput
    entries: RegistryEntryProjection
    memory: ForecastRange
    structural_bytes: int = Field(ge=0)
    plateau_horizon_seconds: int = Field(ge=0)
    plateau_reached_after_seconds: int | None = Field(default=None, ge=0)
    maximum_lookup_candidates: int | None = Field(default=None, ge=0)
    heap_segment_amplification: float | None = Field(default=None, ge=1)
    compaction_budget_entries: int = Field(ge=0)
    measured_profile: str
    operation_profile: str | None = None
    measurement_status: RegistryMeasurementStatus
    measurement_unit: RegistryMeasurementUnit
    measured_entries: int = Field(ge=0)
    costs: RegistryCostProjection

    model_config = ConfigDict(frozen=True, extra="forbid")


class RetainedStateFamilyCoverage(BaseModel):
    """Declare how one retained-state family contributes to the memory forecast."""

    family: RetainedStateFamilyName
    disposition: RetainedStateCoverageDisposition
    registry: RegistryName | None = None
    rationale: str = Field(min_length=1)
    release_evidence_kind: RetainedStateReleaseEvidenceKind
    release_evidence_id: str = Field(min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        """Require modeled families to name a registry and exclusions not to impersonate one."""

        if self.disposition == "modeled_registry" and self.registry is None:
            raise ValueError("modeled retained-state families require a registry")
        if self.disposition == "legacy_calibrated_peak" and self.registry is not None:
            raise ValueError("legacy-peak retained-state families cannot name a registry")
        if (
            self.disposition == "modeled_registry"
            and self.release_evidence_kind != "scenario_forecast"
        ):
            raise ValueError("modeled retained-state families require scenario-forecast evidence")
        if self.disposition == "legacy_calibrated_peak" and self.release_evidence_kind not in {
            "mixed_exact_case",
            "sidecar_exact_case",
        }:
            raise ValueError(
                "legacy-peak retained-state families require exact release-case evidence"
            )
        return self


class RegistryForecastReport(BaseModel):
    """Registry working-set floor and its explicit non-registry exclusions."""

    registries: tuple[RegistryResourceProjection, ...]
    total_registry_memory: ForecastRange
    total_structural_bytes: int = Field(ge=0)
    total_created_entries: int = Field(ge=0)
    total_live_entries: int = Field(ge=0)
    total_retained_entries: int = Field(ge=0)
    total_leased_entries: int = Field(ge=0)
    total_stale_entries: int = Field(ge=0)
    emitter_payload_excluded_bytes: int = Field(ge=0)
    modeled_peak_floor_bytes: int = Field(ge=0)
    legacy_calibrated_peak_bytes: int = Field(ge=0)
    peak_memory_combination: Literal["maximum_not_sum"] = "maximum_not_sum"
    excluded_components: tuple[str, ...]
    retained_state_family_coverage: tuple[RetainedStateFamilyCoverage, ...]

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def require_complete_retained_state_coverage(self) -> Self:
        """Reject reports that silently omit or double-count a measured mixed family."""

        families = tuple(item.family for item in self.retained_state_family_coverage)
        if len(set(families)) != len(families) or set(families) != set(RETAINED_STATE_FAMILIES):
            raise ValueError(
                "retained-state family coverage must classify every family exactly once"
            )
        modeled = {
            item.family: item.registry
            for item in self.retained_state_family_coverage
            if item.disposition == "modeled_registry"
        }
        if modeled != _MODELED_RETAINED_STATE_REGISTRIES:
            raise ValueError("modeled retained-state families must use the canonical registry map")
        legacy_peak = {
            item.family
            for item in self.retained_state_family_coverage
            if item.disposition == "legacy_calibrated_peak"
        }
        if legacy_peak != set(_LEGACY_PEAK_RETAINED_STATE_RATIONALES):
            raise ValueError(
                "legacy-peak retained-state families must match the explicit exclusions"
            )
        expected_evidence = {
            **{
                family: ("scenario_forecast", evidence_id)
                for family, evidence_id in _MODELED_RETAINED_STATE_EVIDENCE.items()
            },
            **_EXACT_TESTED_RETAINED_STATE_EXCLUSIONS,
        }
        actual_evidence = {
            item.family: (item.release_evidence_kind, item.release_evidence_id)
            for item in self.retained_state_family_coverage
        }
        if actual_evidence != expected_evidence:
            raise ValueError(
                "retained-state family coverage must bind canonical forecast or exact-case evidence"
            )
        return self


class ResourceForecast(BaseModel):
    """Scenario projection compared with a live machine resource snapshot."""

    calibration_version: int
    calibration_label: str
    memory: ForecastRange
    final_output: ForecastRange
    disk: ForecastRange
    snapshot: ResourceSnapshot
    registry_report: RegistryForecastReport | None = None
    pressures: tuple[ResourcePressure, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")


class _MemoryCalibration(BaseModel):
    base_mib: int = Field(gt=0)
    emitter_queue_mib_per_format: float = Field(ge=0)
    baseline_bytes_per_occurrence: int = Field(ge=0)
    explicit_bytes_per_occurrence: int = Field(ge=0)
    baseline_occurrence_retention_cap: int = Field(gt=0)
    explicit_occurrence_retention_cap: int = Field(gt=0)
    fixed_mib_by_format: dict[str, float] = Field(default_factory=dict)
    baseline_bytes_per_occurrence_by_format: dict[str, int] = Field(default_factory=dict)
    smb_catalog_bytes_per_file: int = Field(ge=0)
    smb_retained_bytes_per_mutation: int = Field(ge=0)
    external_sort_mib_per_zeek_format: float = Field(ge=0)
    smb_bytes_per_operation_by_format: dict[str, int] = Field(default_factory=dict)
    lower_multiplier: float = Field(gt=0)
    upper_multiplier: float = Field(gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_multipliers(self) -> Self:
        """Require expected memory to remain inside the forecast interval."""
        if self.lower_multiplier > 1 or self.upper_multiplier < 1:
            raise ValueError("memory multipliers must bracket the expected value 1.0")
        return self


class RegistryMeasuredCost(BaseModel):
    """One versioned fresh-process registry scale measurement."""

    status: RegistryMeasurementStatus
    profile: str
    operation_profile: str | None = None
    unit: RegistryMeasurementUnit = "live_entry"
    measured_entries: int = Field(ge=0)
    resident_bytes_per_entry: float | None = Field(default=None, gt=0)
    structural_bytes_per_entry: float | None = Field(default=None, gt=0)
    load_microseconds_per_entry: float | None = Field(default=None, ge=0)
    mutation_microseconds_per_entry: float | None = Field(default=None, ge=0)
    lookup_p95_microseconds: float | None = Field(default=None, ge=0)
    expiry_microseconds_per_entry: float | None = Field(default=None, ge=0)
    resident_upper_multiplier: float | None = Field(default=None, ge=1)
    maximum_lookup_candidates: int | None = Field(default=None, ge=0)
    heap_segment_amplification: float | None = Field(default=None, ge=1)
    compaction_budget_entries: int = Field(default=0, ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def require_available_measurement(self) -> Self:
        """Keep unavailable measurements explicit instead of silently inventing costs."""

        required = (
            self.resident_bytes_per_entry,
            self.structural_bytes_per_entry,
            self.load_microseconds_per_entry,
            self.mutation_microseconds_per_entry,
            self.lookup_p95_microseconds,
            self.expiry_microseconds_per_entry,
            self.resident_upper_multiplier,
        )
        if self.status == "unavailable":
            if any(value is not None for value in required):
                raise ValueError("unavailable registry measurements cannot carry cost values")
            if self.measured_entries != 0:
                raise ValueError("unavailable registry measurements must use measured_entries=0")
            return self
        if self.measured_entries <= 0 or any(value is None for value in required):
            raise ValueError("measured/provisional registry costs require every measured value")
        assert self.resident_bytes_per_entry is not None
        assert self.structural_bytes_per_entry is not None
        if self.structural_bytes_per_entry > self.resident_bytes_per_entry:
            raise ValueError("registry structural bytes cannot exceed resident bytes")
        return self


class RegistryProjectionPolicy(BaseModel):
    """Scenario-to-cardinality policy kept separate from measured costs."""

    created_per_effect: float = Field(ge=0)
    mutations_per_created: float = Field(ge=0)
    lookups_per_created: float = Field(ge=0)
    live_horizon_seconds: int = Field(ge=0)
    retention_horizon_seconds: int = Field(ge=0)
    lease_fraction: float = Field(ge=0, le=1)
    lease_bytes_per_entry: int = Field(ge=0)
    maximum_entries: int | None = Field(default=None, gt=0)
    stale_fraction_before_compaction: float = Field(ge=0, le=1)

    model_config = ConfigDict(frozen=True, extra="forbid")


class RegistryForecastCalibration(BaseModel):
    """Measured costs and projection policy for one registry family."""

    measurement: RegistryMeasuredCost
    projection: RegistryProjectionPolicy

    model_config = ConfigDict(frozen=True, extra="forbid")


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
    peak_lower_multiplier: float = Field(gt=0)
    external_sort_transient_multiplier: float = Field(ge=0)
    smb_activity_sidecar_bytes: int = Field(ge=0)
    smb_operation_sidecar_bytes: int = Field(ge=0)
    smb_activity_fixed_bytes_by_format: dict[str, int] = Field(default_factory=dict)
    smb_operation_bytes_by_format: dict[str, int] = Field(default_factory=dict)
    formats: dict[str, _DiskFormatCalibration]

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_multipliers(self) -> Self:
        """Require expected disk use to remain inside the forecast interval."""
        if self.lower_multiplier > 1 or self.peak_lower_multiplier > 1 or self.upper_multiplier < 1:
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
    registries: dict[RegistryName, RegistryForecastCalibration] = Field(default_factory=dict)
    disk: _DiskCalibration
    capacity: _CapacityCalibration

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def require_every_registry(self) -> Self:
        """Reject partial registry calibration instead of hiding unknown memory."""

        if not self.registries:
            if self.version >= 5:
                raise ValueError("resource forecast calibration v5+ requires registry costs")
            return self
        missing = sorted(set(_REGISTRY_NAMES) - set(self.registries))
        extra = sorted(set(self.registries) - set(_REGISTRY_NAMES))
        if missing or extra:
            raise ValueError(
                "registry calibration keys must match the supported registry set; "
                f"missing={missing}, extra={extra}"
            )
        return self


@lru_cache(maxsize=1)
def load_resource_forecast_calibration() -> ResourceForecastCalibration:
    """Load the versioned resource forecast coefficients."""
    path = get_config_directory() / "resource_forecast.yaml"
    return ResourceForecastCalibration.model_validate(load_yaml(path))


_register_trusted_derived_cache(
    __name__,
    "load_resource_forecast_calibration",
    globals(),
    load_resource_forecast_calibration,
)


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
    try:
        swap = psutil.swap_memory()
    except OSError:
        # Some restricted macOS environments deny the sysctl used by psutil.
        # Treat unavailable swap as zero so the forecast remains conservative.
        free_swap = 0
    else:
        free_swap = int(swap.free)
    disk_path = _nearest_existing_path(destination)
    disk = psutil.disk_usage(str(disk_path))
    total_memory = int(virtual.total)
    available_memory = int(virtual.available)
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


def _forecast_registry_inputs(
    scenario: Scenario,
    estimate: WorkloadEstimate,
) -> tuple[RegistryWorkloadInput, ...]:
    """Return current typed inputs or reconstruct them for legacy callers."""

    if estimate.registry_inputs:
        by_name = {item.registry: item for item in estimate.registry_inputs}
        if len(by_name) != len(estimate.registry_inputs) or set(by_name) != set(_REGISTRY_NAMES):
            raise ValueError("registry workload inputs must contain each registry exactly once")
        return tuple(by_name[name] for name in _REGISTRY_NAMES)
    return build_registry_workload_inputs(
        scenario,
        primary_seconds=estimate.primary_duration_seconds,
        warmup_seconds=estimate.warmup_seconds,
        baseline_occurrences=estimate.baseline_occurrences,
        explicit_occurrences=estimate.explicit_occurrences,
        canonical_occurrences=estimate.canonical_occurrences,
        rendered_records=estimate.rendered_records,
        enabled_formats=estimate.enabled_formats,
    )


def _project_registry(
    workload_input: RegistryWorkloadInput,
    calibration: RegistryForecastCalibration,
) -> RegistryResourceProjection:
    """Convert one scenario driver into a bounded, measured-cost projection."""

    measurement = calibration.measurement
    if measurement.status == "unavailable":
        raise ValueError(
            f"registry measurement unavailable for {workload_input.registry}: {measurement.profile}"
        )
    resident_bytes = measurement.resident_bytes_per_entry
    structural_bytes = measurement.structural_bytes_per_entry
    load_microseconds = measurement.load_microseconds_per_entry
    mutation_microseconds = measurement.mutation_microseconds_per_entry
    lookup_microseconds = measurement.lookup_p95_microseconds
    expiry_microseconds = measurement.expiry_microseconds_per_entry
    upper_multiplier = measurement.resident_upper_multiplier
    assert resident_bytes is not None
    assert structural_bytes is not None
    assert load_microseconds is not None
    assert mutation_microseconds is not None
    assert lookup_microseconds is not None
    assert expiry_microseconds is not None
    assert upper_multiplier is not None

    policy = calibration.projection
    dynamic_created = math.ceil(workload_input.effect_occurrences * policy.created_per_effect)
    created = workload_input.static_entries + dynamic_created
    mutation_operations = math.ceil(dynamic_created * policy.mutations_per_created)
    lookup_operations = math.ceil(
        created * policy.lookups_per_created * workload_input.channel_fanout
    )

    if workload_input.static_entries:
        static_live = workload_input.static_entries
    else:
        static_live = 0
    if dynamic_created and workload_input.scenario_seconds > 0:
        rate = dynamic_created / workload_input.scenario_seconds
        dynamic_live = min(
            dynamic_created,
            math.ceil(rate * policy.live_horizon_seconds),
        )
        closed_entries = dynamic_created - dynamic_live
        dynamic_retained = min(
            closed_entries,
            math.ceil(rate * policy.retention_horizon_seconds),
        )
    else:
        dynamic_live = dynamic_created
        dynamic_retained = 0

    live = static_live + dynamic_live
    retained = dynamic_retained
    if policy.maximum_entries is not None and live + retained > policy.maximum_entries:
        live = min(live, policy.maximum_entries)
        retained = min(retained, policy.maximum_entries - live)
    active_entries = live + retained
    leased = min(active_entries, math.ceil(active_entries * policy.lease_fraction))
    expired = max(0, created - active_entries)
    stale = min(
        measurement.compaction_budget_entries,
        math.ceil(active_entries * policy.stale_fraction_before_compaction),
    )
    backing = active_entries + stale
    expected_memory = math.ceil(
        active_entries * resident_bytes
        + stale * structural_bytes
        + leased * policy.lease_bytes_per_entry
    )
    projected_structural_bytes = math.ceil(
        backing * structural_bytes + leased * policy.lease_bytes_per_entry
    )
    memory = ForecastRange(
        lower_bytes=min(projected_structural_bytes, expected_memory),
        expected_bytes=expected_memory,
        upper_bytes=math.ceil(expected_memory * upper_multiplier),
    )
    plateau_horizon = policy.live_horizon_seconds + policy.retention_horizon_seconds
    plateau_reached = (
        plateau_horizon if workload_input.scenario_seconds >= plateau_horizon else None
    )
    if workload_input.static_entries and dynamic_created == 0:
        plateau_reached = 0

    return RegistryResourceProjection(
        registry=workload_input.registry,
        input=workload_input,
        entries=RegistryEntryProjection(
            created_entries=created,
            live_entries=live,
            retained_entries=retained,
            leased_entries=leased,
            stale_entries=stale,
            expired_entries=expired,
            backing_entries=backing,
            high_water_entries=active_entries,
        ),
        memory=memory,
        structural_bytes=projected_structural_bytes,
        plateau_horizon_seconds=plateau_horizon,
        plateau_reached_after_seconds=plateau_reached,
        maximum_lookup_candidates=measurement.maximum_lookup_candidates,
        heap_segment_amplification=measurement.heap_segment_amplification,
        compaction_budget_entries=measurement.compaction_budget_entries,
        measured_profile=measurement.profile,
        operation_profile=measurement.operation_profile,
        measurement_status=measurement.status,
        measurement_unit=measurement.unit,
        measured_entries=measurement.measured_entries,
        costs=RegistryCostProjection(
            load_seconds=created * load_microseconds / 1_000_000,
            mutation_seconds=mutation_operations * mutation_microseconds / 1_000_000,
            expiry_seconds=expired * expiry_microseconds / 1_000_000,
            lookup_p95_microseconds=lookup_microseconds,
            lookup_operations=lookup_operations,
            mutation_operations=mutation_operations,
            expiry_operations=expired,
        ),
    )


def _retained_state_family_coverage() -> tuple[RetainedStateFamilyCoverage, ...]:
    """Return the exhaustive mixed-family forecast disposition in canonical order."""

    coverage: list[RetainedStateFamilyCoverage] = []
    for family in RETAINED_STATE_FAMILIES:
        registry = _MODELED_RETAINED_STATE_REGISTRIES.get(family)
        if registry is not None:
            coverage.append(
                RetainedStateFamilyCoverage(
                    family=family,
                    disposition="modeled_registry",
                    registry=registry,
                    rationale="Scenario-derived cardinality and a versioned per-entry calibration.",
                    release_evidence_kind="scenario_forecast",
                    release_evidence_id=_MODELED_RETAINED_STATE_EVIDENCE[family],
                )
            )
            continue
        rationale = _LEGACY_PEAK_RETAINED_STATE_RATIONALES.get(family)
        if rationale is None:
            raise ValueError(f"retained-state family {family!r} has no forecast disposition")
        coverage.append(
            RetainedStateFamilyCoverage(
                family=family,
                disposition="legacy_calibrated_peak",
                rationale=rationale,
                release_evidence_kind=_EXACT_TESTED_RETAINED_STATE_EXCLUSIONS[family][0],
                release_evidence_id=_EXACT_TESTED_RETAINED_STATE_EXCLUSIONS[family][1],
            )
        )
    return tuple(coverage)


def _registry_report(
    scenario: Scenario,
    estimate: WorkloadEstimate,
    calibration: ResourceForecastCalibration,
    *,
    emitter_payload_excluded_bytes: int,
    legacy_calibrated_peak_bytes: int,
) -> RegistryForecastReport:
    """Build a complete per-registry report without retaining runtime state."""

    projections = tuple(
        _project_registry(workload_input, calibration.registries[workload_input.registry])
        for workload_input in _forecast_registry_inputs(scenario, estimate)
    )
    total_memory = ForecastRange(
        lower_bytes=sum(item.memory.lower_bytes for item in projections),
        expected_bytes=sum(item.memory.expected_bytes for item in projections),
        upper_bytes=sum(item.memory.upper_bytes for item in projections),
    )
    return RegistryForecastReport(
        registries=projections,
        total_registry_memory=total_memory,
        total_structural_bytes=sum(item.structural_bytes for item in projections),
        total_created_entries=sum(item.entries.created_entries for item in projections),
        total_live_entries=sum(item.entries.live_entries for item in projections),
        total_retained_entries=sum(item.entries.retained_entries for item in projections),
        total_leased_entries=sum(item.entries.leased_entries for item in projections),
        total_stale_entries=sum(item.entries.stale_entries for item in projections),
        emitter_payload_excluded_bytes=emitter_payload_excluded_bytes,
        modeled_peak_floor_bytes=(total_memory.expected_bytes + emitter_payload_excluded_bytes),
        legacy_calibrated_peak_bytes=legacy_calibrated_peak_bytes,
        excluded_components=(
            "interpreter_and_generator_base",
            "emitter_queues_and_format_state",
            "rendered_payload_and_attachment_buffers",
            "external_sort_and_storage_catalog_state",
        ),
        retained_state_family_coverage=_retained_state_family_coverage(),
    )


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
    base_memory = int(memory_config.base_mib * 1024 * 1024)
    queue_memory = int(format_count * memory_config.emitter_queue_mib_per_format * 1024 * 1024)
    occurrence_memory = (
        min(
            estimate.baseline_occurrences,
            memory_config.baseline_occurrence_retention_cap,
        )
        * memory_config.baseline_bytes_per_occurrence
        + min(
            estimate.explicit_occurrences,
            memory_config.explicit_occurrence_retention_cap,
        )
        * memory_config.explicit_bytes_per_occurrence
    )
    fixed_format_memory = int(
        sum(memory_config.fixed_mib_by_format.get(name, 0) for name in formats) * 1024 * 1024
    )
    retained_format_memory = estimate.baseline_occurrences * sum(
        memory_config.baseline_bytes_per_occurrence_by_format.get(name, 0) for name in formats
    )
    storage_catalog_memory = estimate.smb_catalog_files * memory_config.smb_catalog_bytes_per_file
    storage_mutation_memory = (
        estimate.smb_retained_mutations * memory_config.smb_retained_bytes_per_mutation
    )
    external_sort_memory = int(
        sum(name.startswith("zeek_") for name in formats)
        * memory_config.external_sort_mib_per_zeek_format
        * 1024
        * 1024
    )
    storage_emitter_memory = estimate.smb_batch_operations * sum(
        memory_config.smb_bytes_per_operation_by_format.get(name, 0) for name in formats
    )
    legacy_expected_memory = int(
        base_memory
        + queue_memory
        + occurrence_memory
        + estimate.email_artifact_bytes
        + fixed_format_memory
        + retained_format_memory
        + storage_catalog_memory
        + storage_mutation_memory
        + external_sort_memory
        + storage_emitter_memory
    )
    emitter_payload_excluded_bytes = int(
        base_memory
        + queue_memory
        + estimate.email_artifact_bytes
        + fixed_format_memory
        + retained_format_memory
        + storage_catalog_memory
        + storage_mutation_memory
        + external_sort_memory
        + storage_emitter_memory
    )
    registry_report = (
        _registry_report(
            scenario,
            estimate,
            effective_calibration,
            emitter_payload_excluded_bytes=emitter_payload_excluded_bytes,
            legacy_calibrated_peak_bytes=legacy_expected_memory,
        )
        if effective_calibration.registries
        else None
    )
    expected_memory = (
        max(legacy_expected_memory, registry_report.modeled_peak_floor_bytes)
        if registry_report is not None
        else legacy_expected_memory
    )
    memory = ForecastRange(
        lower_bytes=int(expected_memory * memory_config.lower_multiplier),
        expected_bytes=expected_memory,
        upper_bytes=int(expected_memory * memory_config.upper_multiplier),
    )

    disk_config = effective_calibration.disk
    format_output_bytes: dict[str, int] = {}
    for format_name in formats:
        format_config = disk_config.formats.get(format_name)
        if format_config is None:
            format_output_bytes[format_name] = int(
                estimate.primary_duration_seconds
                * disk_config.unknown_format_bytes_per_host_second
                * len(scenario.environment.systems)
            )
            continue
        format_output_bytes[format_name] = int(
            estimate.primary_duration_seconds
            * format_config.bytes_per_host_second
            * _system_count_for_scope(scenario, format_config.system_scope)
        )
        format_output_bytes[format_name] += (
            estimate.smb_activity_events
            * disk_config.smb_activity_fixed_bytes_by_format.get(format_name, 0)
            + estimate.smb_batch_operations
            * disk_config.smb_operation_bytes_by_format.get(format_name, 0)
        )
    expected_final_output = int(
        disk_config.base_mib * 1024 * 1024
        + sum(format_output_bytes.values())
        + estimate.email_artifact_bytes
        + estimate.smb_activity_events * disk_config.smb_activity_sidecar_bytes
        + estimate.smb_batch_operations * disk_config.smb_operation_sidecar_bytes
    )
    expected_zeek_output = sum(
        byte_count
        for format_name, byte_count in format_output_bytes.items()
        if format_name.startswith("zeek_")
    )
    external_sort_transient = int(
        expected_zeek_output * disk_config.external_sort_transient_multiplier
    )
    expected_disk = expected_final_output + external_sort_transient
    final_output = ForecastRange(
        lower_bytes=int(expected_final_output * disk_config.lower_multiplier),
        expected_bytes=expected_final_output,
        upper_bytes=int(expected_final_output * disk_config.upper_multiplier),
    )
    disk = ForecastRange(
        lower_bytes=max(
            final_output.lower_bytes,
            int(expected_disk * disk_config.peak_lower_multiplier),
        ),
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
        final_output=final_output,
        disk=disk,
        snapshot=resources,
        registry_report=registry_report,
        pressures=pressures,
    )
