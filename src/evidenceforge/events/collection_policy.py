# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable collection-policy identities and projection value objects.

These types describe what a concrete source instance can collect. They do not
perform observation sampling or rendering. Runtime compilation lives in
``generation.collection_deployment`` so source definitions can be shared by
every occurrence without copying policy maps into projection envelopes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntFlag, StrEnum
from types import MappingProxyType
from typing import Self, TypeAlias

SourceInstanceKey: TypeAlias = tuple[str, str, str]


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip().casefold()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _required_exact_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


class CollectionCapability(IntFlag):
    """Fixed machine-word capability flags for one source instance."""

    NONE = 0

    PROCESS = 1 << 0
    AUTHENTICATION = 1 << 1
    SESSION = 1 << 2
    NETWORK = 1 << 3
    DNS = 1 << 4
    TLS = 1 << 5
    HTTP = 1 << 6
    FILE = 1 << 7
    REGISTRY = 1 << 8
    SERVICE = 1 << 9
    TASK = 1 << 10
    ACCOUNT = 1 << 11
    SMB = 1 << 12
    SSH = 1 << 13
    RDP = 1 << 14
    IDS = 1 << 15

    SOURCE_ENDPOINT = 1 << 16
    DESTINATION_ENDPOINT = 1 << 17
    COHERENT_ACTOR = 1 << 18

    DNS_ANALYZER = 1 << 19
    TLS_ANALYZER = 1 << 20
    HTTP_ANALYZER = 1 << 21
    FILE_ANALYZER = 1 << 22
    SMB_ANALYZER = 1 << 23

    OPTIONAL_FIELDS = 1 << 24
    COLLECTION_WINDOWS = 1 << 25
    BATCHING = 1 << 26

    def covers(self, required: CollectionCapability) -> bool:
        """Return whether every required bit is available."""

        return self & required == required


_STRUCTURAL_CAPABILITIES = (
    CollectionCapability.OPTIONAL_FIELDS
    | CollectionCapability.COLLECTION_WINDOWS
    | CollectionCapability.BATCHING
)


@dataclass(frozen=True, slots=True)
class SourceInstanceIdentity:
    """Exact identity for one deployed source on one host."""

    source_instance: str
    hostname: str
    family: str

    def __post_init__(self) -> None:
        """Normalize identity parts into stable exact lookup material."""

        object.__setattr__(
            self,
            "source_instance",
            _required_text(self.source_instance, "source_instance"),
        )
        object.__setattr__(self, "hostname", _required_text(self.hostname, "hostname"))
        object.__setattr__(self, "family", _required_text(self.family, "family"))

    @property
    def canonical_key(self) -> SourceInstanceKey:
        """Return the host/family/instance exact composite key."""

        return (self.hostname, self.family, self.source_instance)


@dataclass(frozen=True, slots=True)
class CollectionWindow:
    """One half-open deployment interval for a source instance."""

    start: datetime | None = None
    end: datetime | None = None

    def __post_init__(self) -> None:
        """Normalize configured endpoints and reject empty intervals."""

        start = _aware_utc(self.start, "start") if self.start is not None else None
        end = _aware_utc(self.end, "end") if self.end is not None else None
        if start is not None and end is not None and start >= end:
            raise ValueError("collection window start must be earlier than end")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def contains(self, at: datetime) -> bool:
        """Return whether ``at`` falls inside this half-open interval."""

        point = _aware_utc(at, "at")
        return (self.start is None or self.start <= point) and (
            self.end is None or point < self.end
        )


@dataclass(frozen=True, slots=True)
class CollectionBatchingPolicy:
    """Immutable collection-batch constraints for a source instance."""

    enabled: bool = False
    interval_us: int = 0
    max_records: int = 0

    def __post_init__(self) -> None:
        """Validate batching bounds without inventing runtime defaults."""

        if self.interval_us < 0:
            raise ValueError("batch interval_us must be non-negative")
        if self.max_records < 0:
            raise ValueError("batch max_records must be non-negative")
        if self.enabled and self.interval_us < 1:
            raise ValueError("enabled batching requires a positive interval_us")


def _normalize_probability_map(values: Mapping[str, float]) -> Mapping[str, float]:
    normalized: dict[str, float] = {}
    for raw_name, probability in values.items():
        name = _required_text(raw_name, "format name")
        numeric = float(probability)
        if not 0.0 <= numeric <= 1.0:
            raise ValueError(f"format missingness for {name!r} must be between 0 and 1")
        normalized[name] = numeric
    return MappingProxyType(dict(sorted(normalized.items())))


def _normalize_optional_fields(values: frozenset[str]) -> frozenset[str]:
    return frozenset(_required_exact_text(value, "optional field") for value in values)


def _window_sort_key(window: CollectionWindow) -> datetime:
    return window.start or datetime.min.replace(tzinfo=UTC)


def _normalize_windows(values: tuple[CollectionWindow, ...]) -> tuple[CollectionWindow, ...]:
    windows = tuple(sorted(values, key=_window_sort_key))
    previous: CollectionWindow | None = None
    for window in windows:
        if previous is not None and (
            previous.end is None or window.start is None or window.start < previous.end
        ):
            raise ValueError("collection windows must not overlap")
        previous = window
    return windows


@dataclass(frozen=True, slots=True)
class SourceCollectionPolicy:
    """Fully normalized immutable observation policy for one source."""

    enabled: bool = True
    capabilities: CollectionCapability = CollectionCapability.NONE
    missingness: float = 0.0
    format_missingness: Mapping[str, float] = field(default_factory=lambda: MappingProxyType({}))
    optional_fields: frozenset[str] = frozenset()
    windows: tuple[CollectionWindow, ...] = field(default_factory=lambda: (CollectionWindow(),))
    batching: CollectionBatchingPolicy = field(default_factory=CollectionBatchingPolicy)

    def __post_init__(self) -> None:
        """Normalize composite fields and align structural capability flags."""

        missingness = float(self.missingness)
        if not 0.0 <= missingness <= 1.0:
            raise ValueError("missingness must be between 0 and 1")
        optional_fields = _normalize_optional_fields(frozenset(self.optional_fields))
        windows = _normalize_windows(tuple(self.windows))
        capabilities = CollectionCapability(self.capabilities) & ~_STRUCTURAL_CAPABILITIES
        if optional_fields:
            capabilities |= CollectionCapability.OPTIONAL_FIELDS
        if windows != (CollectionWindow(),):
            capabilities |= CollectionCapability.COLLECTION_WINDOWS
        if self.batching.enabled:
            capabilities |= CollectionCapability.BATCHING

        object.__setattr__(self, "missingness", missingness)
        object.__setattr__(
            self,
            "format_missingness",
            _normalize_probability_map(self.format_missingness),
        )
        object.__setattr__(self, "optional_fields", optional_fields)
        object.__setattr__(self, "windows", windows)
        object.__setattr__(self, "capabilities", capabilities)

    def missingness_for(self, source_format: str) -> float:
        """Return exact format missingness or the source-wide fallback."""

        return self.format_missingness.get(
            _required_text(source_format, "source_format"),
            self.missingness,
        )


@dataclass(frozen=True, slots=True)
class SourceCollectionOverride:
    """Partial boundary-normalization patch for an observation policy."""

    enabled: bool | None = None
    capabilities: CollectionCapability | None = None
    missingness: float | None = None
    format_missingness: Mapping[str, float] | None = None
    optional_fields: frozenset[str] | None = None
    windows: tuple[CollectionWindow, ...] | None = None
    batching: CollectionBatchingPolicy | None = None

    def __post_init__(self) -> None:
        """Normalize supplied patch fields without filling absent values."""

        if self.capabilities is not None:
            object.__setattr__(
                self,
                "capabilities",
                CollectionCapability(self.capabilities),
            )
        if self.missingness is not None and not 0.0 <= float(self.missingness) <= 1.0:
            raise ValueError("missingness must be between 0 and 1")
        if self.missingness is not None:
            object.__setattr__(self, "missingness", float(self.missingness))
        if self.format_missingness is not None:
            object.__setattr__(
                self,
                "format_missingness",
                _normalize_probability_map(self.format_missingness),
            )
        if self.optional_fields is not None:
            object.__setattr__(
                self,
                "optional_fields",
                _normalize_optional_fields(frozenset(self.optional_fields)),
            )
        if self.windows is not None:
            object.__setattr__(self, "windows", _normalize_windows(tuple(self.windows)))

    def apply(self, base: SourceCollectionPolicy) -> SourceCollectionPolicy:
        """Return ``base`` with only explicitly supplied fields replaced."""

        return SourceCollectionPolicy(
            enabled=base.enabled if self.enabled is None else self.enabled,
            capabilities=(base.capabilities if self.capabilities is None else self.capabilities),
            missingness=base.missingness if self.missingness is None else self.missingness,
            format_missingness=(
                base.format_missingness
                if self.format_missingness is None
                else self.format_missingness
            ),
            optional_fields=(
                base.optional_fields if self.optional_fields is None else self.optional_fields
            ),
            windows=base.windows if self.windows is None else self.windows,
            batching=base.batching if self.batching is None else self.batching,
        )


def normalize_source_collection_policy(
    *,
    defaults: SourceCollectionPolicy,
    profile: SourceCollectionOverride | None = None,
    project_pack: SourceCollectionOverride | None = None,
    scenario: SourceCollectionOverride | None = None,
) -> SourceCollectionPolicy:
    """Apply observation layers in documented lowest-to-highest precedence."""

    policy = defaults
    for override in (profile, project_pack, scenario):
        if override is not None:
            policy = override.apply(policy)
    return policy


class ProjectionAdmission(StrEnum):
    """Foundation-level source-deployment admission result."""

    READY = "ready"
    SOURCE_DISABLED = "source_disabled"
    OUTSIDE_COLLECTION_WINDOW = "outside_collection_window"
    MISSING_CAPABILITY = "missing_capability"


class ProjectionRole(StrEnum):
    """Stable role of one source-native projection target."""

    HOST = "host"
    SOURCE_ENDPOINT = "source_endpoint"
    DESTINATION_ENDPOINT = "destination_endpoint"
    SENSOR = "sensor"


@dataclass(frozen=True, slots=True)
class ProjectionEnvelope:
    """Ephemeral per-target projection state referencing one compiled source."""

    occurrence_id: str
    target_id: str
    source_ordinal: int
    source: SourceInstanceIdentity
    canonical_time: datetime
    requested_capabilities: CollectionCapability
    effective_capabilities: CollectionCapability
    admission: ProjectionAdmission
    collection_window: CollectionWindow | None
    role: ProjectionRole = ProjectionRole.HOST
    optional_capabilities: CollectionCapability = CollectionCapability.NONE
    observed_time: datetime | None = None

    def __post_init__(self) -> None:
        """Normalize occurrence identity and timestamp values."""

        if not self.occurrence_id.strip():
            raise ValueError("occurrence_id must not be empty")
        if not self.target_id.strip():
            raise ValueError("target_id must not be empty")
        if self.source_ordinal < 0:
            raise ValueError("source_ordinal must be non-negative")
        object.__setattr__(
            self,
            "requested_capabilities",
            CollectionCapability(self.requested_capabilities),
        )
        object.__setattr__(
            self,
            "effective_capabilities",
            CollectionCapability(self.effective_capabilities),
        )
        object.__setattr__(self, "role", ProjectionRole(self.role))
        object.__setattr__(
            self,
            "optional_capabilities",
            CollectionCapability(self.optional_capabilities),
        )
        object.__setattr__(
            self,
            "canonical_time",
            _aware_utc(self.canonical_time, "canonical_time"),
        )
        if self.observed_time is not None:
            object.__setattr__(
                self,
                "observed_time",
                _aware_utc(self.observed_time, "observed_time"),
            )

    @property
    def admitted(self) -> bool:
        """Return whether source deployment admits the projection target."""

        return self.admission is ProjectionAdmission.READY

    def with_observed_time(self, observed_time: datetime) -> Self:
        """Return a finalized envelope without mutating canonical time."""

        return type(self)(
            occurrence_id=self.occurrence_id,
            target_id=self.target_id,
            source_ordinal=self.source_ordinal,
            source=self.source,
            canonical_time=self.canonical_time,
            requested_capabilities=self.requested_capabilities,
            effective_capabilities=self.effective_capabilities,
            admission=self.admission,
            collection_window=self.collection_window,
            role=self.role,
            optional_capabilities=self.optional_capabilities,
            observed_time=observed_time,
        )
