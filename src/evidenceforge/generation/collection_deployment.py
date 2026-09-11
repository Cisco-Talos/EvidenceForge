# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable compiled source-instance deployment indexes.

Compilation turns normalized source definitions into dense ordinal arrays and
exact maps. Runtime lookups never scan the deployment, and collection-window
queries inspect at most one candidate after a binary search.
"""

from __future__ import annotations

import hashlib
import json
import sys
from array import array
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol

from evidenceforge.events.collection_policy import (
    CollectionCapability,
    CollectionWindow,
    ProjectionAdmission,
    ProjectionEnvelope,
    ProjectionRole,
    SourceCollectionOverride,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
    normalize_source_collection_policy,
)

_MIN_TIME_US = -(1 << 63)
_EMPTY_ORDINAL = (1 << 32) - 1
_EMPTY_COMPOSITE_KEY = (1 << 64) - 1
_MASK_64 = (1 << 64) - 1
_FINAL_INDEX_LOAD = 0.70


class _DigestWriter(Protocol):
    """Minimal structural type accepted by digest framing helpers."""

    def update(self, data: bytes, /) -> None:
        """Add bytes to the digest state."""


def _normalized_lookup_text(value: str, field_name: str) -> str:
    normalized = value.strip().casefold()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _time_us(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collection lookup time must be timezone-aware")
    utc = value.astimezone(UTC)
    return (
        (utc.toordinal() * 86_400 + utc.hour * 3_600 + utc.minute * 60 + utc.second) * 1_000_000
    ) + utc.microsecond


def _window_start_us(window: CollectionWindow) -> int:
    return _MIN_TIME_US if window.start is None else _time_us(window.start)


@dataclass(frozen=True, slots=True)
class SourceInstanceDeployment:
    """One fully normalized immutable source-instance deployment."""

    identity: SourceInstanceIdentity
    formats: tuple[str, ...]
    policy: SourceCollectionPolicy

    def __post_init__(self) -> None:
        """Normalize source format identities once at compile input."""

        formats = tuple(
            sorted(
                {
                    _normalized_lookup_text(source_format, "source format")
                    for source_format in self.formats
                }
            )
        )
        if not formats:
            raise ValueError("source deployment must provide at least one source format")
        object.__setattr__(self, "formats", formats)

    @classmethod
    def from_layers(
        cls,
        *,
        identity: SourceInstanceIdentity,
        formats: Iterable[str],
        defaults: SourceCollectionPolicy,
        profile: SourceCollectionOverride | None = None,
        project_pack: SourceCollectionOverride | None = None,
        scenario: SourceCollectionOverride | None = None,
    ) -> SourceInstanceDeployment:
        """Build a deployment using documented observation-layer precedence."""

        return cls(
            identity=identity,
            formats=tuple(formats),
            policy=normalize_source_collection_policy(
                defaults=defaults,
                profile=profile,
                project_pack=project_pack,
                scenario=scenario,
            ),
        )


@dataclass(frozen=True, slots=True)
class CollectionDeploymentCensus:
    """Precomputed cardinality and memory estimate for a deployment."""

    source_instances: int
    collection_windows: int
    exact_identity_keys: int
    host_family_buckets: int
    max_host_family_bucket: int
    capability_words: int
    estimated_bytes: int
    unique_hostnames: int = 0
    unique_families: int = 0
    unique_format_sets: int = 0
    unique_policies: int = 0
    exact_index_capacity: int = 0
    host_index_capacity: int = 0
    host_family_index_capacity: int = 0
    packed_index_bytes: int = 0
    estimated_index_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _CompiledWindows:
    """Sorted window arrays for one source ordinal."""

    starts_us: tuple[int, ...]
    windows: tuple[CollectionWindow, ...]

    @classmethod
    def compile(cls, windows: tuple[CollectionWindow, ...]) -> _CompiledWindows:
        return cls(
            starts_us=tuple(_window_start_us(window) for window in windows),
            windows=windows,
        )

    def at(self, timestamp: datetime) -> CollectionWindow | None:
        """Return the active interval using logarithmic lookup."""

        if not self.windows:
            return None
        point_us = _time_us(timestamp)
        position = bisect_right(self.starts_us, point_us) - 1
        if position < 0:
            return None
        candidate = self.windows[position]
        return candidate if candidate.contains(timestamp) else None


class _ExactInstanceIndex:
    """Native exact map with interned reverse values and compact source arrays.

    CPython's native hash table is deliberately used for the hottest exact
    identity lookup. It preserves effectively flat lookup latency at million
    scale while the reverse ordinal list and every secondary index remain
    packed. The map is wrapped read-only after compilation.
    """

    __slots__ = (
        "_count",
        "_mapping_bytes",
        "_ordinal_bytes",
        "_ordinals",
        "_strings",
        "_text_bytes",
    )

    def __init__(self) -> None:
        self._count = 0
        self._ordinals: dict[str, int] | Mapping[str, int] = {}
        self._strings: list[str] | tuple[str, ...] = []
        self._text_bytes = 0
        self._ordinal_bytes = 0
        self._mapping_bytes = 0

    def __len__(self) -> int:
        return self._count

    @property
    def capacity(self) -> int:
        """Return exact semantic key capacity after freezing."""

        return self._count

    @property
    def strings(self) -> list[str] | tuple[str, ...]:
        return self._strings

    def intern(self, value: str) -> tuple[int, bool]:
        """Return the ordinal for ``value`` and whether it was newly inserted."""

        existing = self._ordinals.get(value)
        if existing is not None:
            return existing, False
        if self._count >= _EMPTY_ORDINAL:
            raise ValueError("compiled collection deployment exceeds 32-bit ordinal capacity")
        if not isinstance(self._strings, list) or not isinstance(self._ordinals, dict):
            raise RuntimeError("cannot mutate a frozen exact instance index")
        ordinal = self._count
        self._strings.append(value)
        self._ordinals[value] = ordinal
        self._count += 1
        self._text_bytes += sys.getsizeof(value)
        self._ordinal_bytes += sys.getsizeof(ordinal)
        return ordinal, True

    def find(self, value: str) -> int | None:
        """Return one exact source ordinal with a native hash lookup."""

        return self._ordinals.get(value)

    def find_with_candidates(self, value: str) -> tuple[int | None, int]:
        """Return an exact ordinal and its bounded semantic candidate count."""

        ordinal = self._ordinals.get(value)
        return ordinal, int(ordinal is not None)

    def freeze(self) -> None:
        """Freeze forward and reverse identity storage for lock-free reads."""

        if isinstance(self._strings, list):
            self._strings = tuple(self._strings)
        if isinstance(self._ordinals, dict):
            self._mapping_bytes = sys.getsizeof(self._ordinals)
            self._ordinals = MappingProxyType(self._ordinals)

    def estimated_bytes(self) -> int:
        """Return retained map, ordinal, reverse-list, and unique-text bytes."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._ordinals)
            + self._mapping_bytes
            + self._ordinal_bytes
            + sys.getsizeof(self._strings)
            + self._text_bytes
        )

    def estimated_index_bytes(self) -> int:
        """Return index structures while excluding canonical identity text."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._ordinals)
            + self._mapping_bytes
            + self._ordinal_bytes
            + sys.getsizeof(self._strings)
        )


class _StringOrdinalIndex:
    """Compact immutable-after-build exact string-to-ordinal index."""

    __slots__ = ("_count", "_strings", "_table", "_text_bytes")

    def __init__(self) -> None:
        self._count = 0
        self._strings: list[str] | tuple[str, ...] = []
        self._table = array("I", [_EMPTY_ORDINAL]) * 8
        self._text_bytes = 0

    def __len__(self) -> int:
        return self._count

    @property
    def capacity(self) -> int:
        return len(self._table)

    @property
    def strings(self) -> list[str] | tuple[str, ...]:
        return self._strings

    @staticmethod
    def _position(value: str, capacity: int) -> int:
        return hash(value) % capacity

    def _resize(self, capacity: int) -> None:
        table = array("I", [_EMPTY_ORDINAL]) * max(8, capacity)
        for ordinal in range(self._count):
            self._place_into(ordinal, table)
        self._table = table

    def _place_into(self, ordinal: int, table: array) -> None:
        value = self._strings[ordinal]
        position = self._position(value, len(table))
        while table[position] != _EMPTY_ORDINAL:
            position = (position + 1) % len(table)
        table[position] = ordinal

    def intern(self, value: str) -> tuple[int, bool]:
        """Return the ordinal for ``value`` and whether it was newly inserted."""

        existing, _ = self.find_with_candidates(value)
        if existing is not None:
            return existing, False
        if self._count >= _EMPTY_ORDINAL:
            raise ValueError("compiled collection deployment exceeds 32-bit ordinal capacity")
        if (self._count + 1) * 3 > len(self._table) * 2:
            self._resize(len(self._table) * 2)
        if not isinstance(self._strings, list):
            raise RuntimeError("cannot mutate a frozen string index")
        ordinal = self._count
        self._strings.append(value)
        self._count += 1
        self._text_bytes += sys.getsizeof(value)
        self._place_into(ordinal, self._table)
        return ordinal, True

    def find_with_candidates(self, value: str) -> tuple[int | None, int]:
        """Return an exact ordinal and the number of occupied slots inspected."""

        position = self._position(value, len(self._table))
        candidates = 0
        while True:
            ordinal = self._table[position]
            if ordinal == _EMPTY_ORDINAL:
                return None, candidates
            candidates += 1
            if self._strings[ordinal] == value:
                return ordinal, candidates
            position = (position + 1) % len(self._table)

    def find(self, value: str) -> int | None:
        """Return an exact ordinal without allocating a result collection."""

        return self.find_with_candidates(value)[0]

    def freeze(self) -> None:
        """Compact the table and make reverse ordinal storage immutable."""

        if isinstance(self._strings, list):
            self._strings = tuple(self._strings)
        capacity = max(8, int(self._count / _FINAL_INDEX_LOAD) + 1)
        self._resize(capacity)

    def estimated_bytes(self) -> int:
        """Return retained index and unique-text bytes without scanning strings."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._table)
            + sys.getsizeof(self._strings)
            + self._text_bytes
        )

    def estimated_index_bytes(self) -> int:
        """Return packed/reverse index structures without canonical text."""

        return sys.getsizeof(self) + sys.getsizeof(self._table) + sys.getsizeof(self._strings)


def _mix_composite_key(value: int) -> int:
    value ^= value >> 33
    value = (value * 0xFF51AFD7ED558CCD) & _MASK_64
    value ^= value >> 33
    value = (value * 0xC4CEB9FE1A85EC53) & _MASK_64
    return value ^ (value >> 33)


class _HostFamilyIndex:
    """Packed host/family composite index with adaptive collision buckets."""

    __slots__ = ("_buckets", "_count", "_keys", "_max_bucket", "_values")

    def __init__(self) -> None:
        self._keys = array("Q", [_EMPTY_COMPOSITE_KEY]) * 8
        self._values = array("q", [0]) * 8
        self._buckets: list[array] | tuple[array, ...] = []
        self._count = 0
        self._max_bucket = 0

    @staticmethod
    def pack(host_ordinal: int, family_ordinal: int) -> int:
        if not 0 <= host_ordinal < _EMPTY_ORDINAL:
            raise ValueError("host ordinal exceeds packed composite capacity")
        if not 0 <= family_ordinal < _EMPTY_ORDINAL:
            raise ValueError("family ordinal exceeds packed composite capacity")
        return (host_ordinal << 32) | family_ordinal

    @staticmethod
    def _position(key: int, capacity: int) -> int:
        return _mix_composite_key(key) % capacity

    @property
    def bucket_count(self) -> int:
        return self._count

    @property
    def max_bucket(self) -> int:
        return self._max_bucket

    @property
    def capacity(self) -> int:
        return len(self._keys)

    def _find_position(self, key: int) -> tuple[int, int]:
        position = self._position(key, len(self._keys))
        candidates = 0
        while True:
            current = self._keys[position]
            if current == _EMPTY_COMPOSITE_KEY or current == key:
                return position, candidates
            candidates += 1
            position = (position + 1) % len(self._keys)

    def _resize(self, capacity: int) -> None:
        old_keys = self._keys
        old_values = self._values
        self._keys = array("Q", [_EMPTY_COMPOSITE_KEY]) * max(8, capacity)
        self._values = array("q", [0]) * max(8, capacity)
        for old_position, key in enumerate(old_keys):
            if key == _EMPTY_COMPOSITE_KEY:
                continue
            position, _ = self._find_position(key)
            self._keys[position] = key
            self._values[position] = old_values[old_position]

    def add(self, key: int, ordinal: int) -> int:
        """Append one ordinal and return the resulting semantic bucket size."""

        position, _ = self._find_position(key)
        if self._keys[position] == _EMPTY_COMPOSITE_KEY:
            if (self._count + 1) * 3 > len(self._keys) * 2:
                self._resize(len(self._keys) * 2)
                position, _ = self._find_position(key)
            self._keys[position] = key
            self._values[position] = ordinal
            self._count += 1
            self._max_bucket = max(self._max_bucket, 1)
            return 1

        value = self._values[position]
        if not isinstance(self._buckets, list):
            raise RuntimeError("cannot mutate a frozen host/family index")
        if value >= 0:
            bucket = array("I", (value, ordinal))
            self._buckets.append(bucket)
            self._values[position] = -len(self._buckets)
        else:
            bucket = self._buckets[-value - 1]
            bucket.append(ordinal)
        size = len(bucket)
        self._max_bucket = max(self._max_bucket, size)
        return size

    def lookup_with_candidates(self, key: int) -> tuple[int | array | None, int]:
        """Return a singleton/bucket and occupied hash candidates inspected."""

        position, collisions = self._find_position(key)
        if self._keys[position] == _EMPTY_COMPOSITE_KEY:
            return None, collisions
        value = self._values[position]
        if value >= 0:
            return value, collisions + 1
        return self._buckets[-value - 1], collisions + 1

    def lookup(self, key: int) -> int | array | None:
        return self.lookup_with_candidates(key)[0]

    def freeze(self) -> None:
        """Compact hash storage and freeze semantic collision buckets."""

        capacity = max(8, int(self._count / _FINAL_INDEX_LOAD) + 1)
        self._resize(capacity)
        if isinstance(self._buckets, list):
            self._buckets = tuple(self._buckets)

    def estimated_bytes(self) -> int:
        """Return retained packed-table and collision-bucket bytes."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._keys)
            + sys.getsizeof(self._values)
            + sys.getsizeof(self._buckets)
            + sum(sys.getsizeof(bucket) for bucket in self._buckets)
        )


def _policy_key(policy: SourceCollectionPolicy) -> tuple[object, ...]:
    return (
        policy.enabled,
        int(policy.capabilities),
        policy.missingness,
        tuple(policy.format_missingness.items()),
        tuple(sorted(policy.optional_fields)),
        policy.windows,
        policy.batching,
    )


def _time_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _policy_material(policy: SourceCollectionPolicy) -> bytes:
    payload = {
        "enabled": policy.enabled,
        "capabilities": int(policy.capabilities),
        "missingness": policy.missingness,
        "format_missingness": dict(policy.format_missingness),
        "optional_fields": sorted(policy.optional_fields),
        "windows": [
            {"start": _time_text(window.start), "end": _time_text(window.end)}
            for window in policy.windows
        ],
        "batching": {
            "enabled": policy.batching.enabled,
            "interval_us": policy.batching.interval_us,
            "max_records": policy.batching.max_records,
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _update_digest_bytes(hasher: _DigestWriter, value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _update_digest_text(hasher: _DigestWriter, value: str) -> None:
    _update_digest_bytes(hasher, value.encode("utf-8"))


def _estimate_policy_bytes(policy: SourceCollectionPolicy, windows: _CompiledWindows) -> int:
    total = sys.getsizeof(policy) + sys.getsizeof(windows)
    total += sys.getsizeof(policy.format_missingness) + sys.getsizeof(policy.optional_fields)
    total += sys.getsizeof(policy.windows) + sys.getsizeof(policy.batching)
    total += sys.getsizeof(windows.starts_us) + sys.getsizeof(windows.windows)
    total += sum(
        sys.getsizeof(name) + sys.getsizeof(probability)
        for name, probability in policy.format_missingness.items()
    )
    total += sum(sys.getsizeof(name) for name in policy.optional_fields)
    total += sum(sys.getsizeof(window) for window in windows.windows)
    return total


class CompiledCollectionDeployment:
    """Scenario-scoped immutable source deployment with exact indexes."""

    __slots__ = (
        "_by_format",
        "_by_instance",
        "_census",
        "_content_digest",
        "_families",
        "_family_by_name",
        "_family_ordinals",
        "_format_set_ordinals",
        "_format_sets",
        "_host_family",
        "_host_ordinals",
        "_hosts",
        "_policies",
        "_policy_ordinals",
        "_policy_windows",
        "_source_count",
    )

    def __init__(self, sources: Iterable[SourceInstanceDeployment]) -> None:
        """Compile normalized sources into immutable ordinal arrays and maps."""

        by_instance = _ExactInstanceIndex()
        hosts = _StringOrdinalIndex()
        host_family = _HostFamilyIndex()
        families: list[str] = []
        family_by_name: dict[str, int] = {}
        format_sets: list[tuple[str, ...]] = []
        format_set_by_value: dict[tuple[str, ...], int] = {}
        policies: list[SourceCollectionPolicy] = []
        policy_windows: list[_CompiledWindows] = []
        policy_by_value: dict[tuple[object, ...], int] = {}
        policy_materials: list[bytes] = []
        format_materials: list[bytes] = []
        host_ordinals = array("I")
        family_ordinals = array("I")
        format_set_ordinals = array("I")
        policy_ordinals = array("I")
        mutable_by_format: dict[str, array] = {}
        collection_window_count = 0
        content_hasher = hashlib.sha256()

        for ordinal, source in enumerate(sources):
            if ordinal >= _EMPTY_ORDINAL:
                raise ValueError("compiled collection deployment exceeds 32-bit ordinal capacity")
            instance = source.identity.source_instance
            hostname = source.identity.hostname
            family = source.identity.family
            existing = by_instance.find(instance)
            if existing is not None:
                existing_host = hosts.strings[host_ordinals[existing]]
                existing_family = families[family_ordinals[existing]]
                if existing_host == hostname and existing_family == family:
                    raise ValueError(
                        f"duplicate source-instance canonical key: {(hostname, family, instance)!r}"
                    )
                raise ValueError(
                    "source_instance must be globally unique within a compiled deployment: "
                    f"{instance!r}"
                )

            instance_ordinal, created = by_instance.intern(instance)
            if not created or instance_ordinal != ordinal:
                raise AssertionError("source-instance ordinal compilation lost dense ordering")
            host_ordinal, _ = hosts.intern(hostname)
            family_ordinal = family_by_name.get(family)
            if family_ordinal is None:
                family_ordinal = len(families)
                if family_ordinal >= _EMPTY_ORDINAL:
                    raise ValueError("collection deployment has too many source families")
                family_by_name[family] = family_ordinal
                families.append(family)

            format_set_ordinal = format_set_by_value.get(source.formats)
            if format_set_ordinal is None:
                format_set_ordinal = len(format_sets)
                format_set_by_value[source.formats] = format_set_ordinal
                format_sets.append(source.formats)
                format_materials.append(
                    json.dumps(source.formats, separators=(",", ":")).encode("utf-8")
                )

            policy_key = _policy_key(source.policy)
            policy_ordinal = policy_by_value.get(policy_key)
            if policy_ordinal is None:
                policy_ordinal = len(policies)
                policy_by_value[policy_key] = policy_ordinal
                policies.append(source.policy)
                policy_windows.append(_CompiledWindows.compile(source.policy.windows))
                policy_materials.append(_policy_material(source.policy))

            host_ordinals.append(host_ordinal)
            family_ordinals.append(family_ordinal)
            format_set_ordinals.append(format_set_ordinal)
            policy_ordinals.append(policy_ordinal)
            host_family.add(_HostFamilyIndex.pack(host_ordinal, family_ordinal), ordinal)
            for source_format in source.formats:
                mutable_by_format.setdefault(source_format, array("I")).append(ordinal)
            collection_window_count += len(source.policy.windows)
            _update_digest_text(content_hasher, instance)
            _update_digest_text(content_hasher, hostname)
            _update_digest_text(content_hasher, family)
            _update_digest_bytes(content_hasher, format_materials[format_set_ordinal])
            _update_digest_bytes(content_hasher, policy_materials[policy_ordinal])

        by_instance.freeze()
        hosts.freeze()
        host_family.freeze()
        self._source_count = len(by_instance)
        self._by_instance = by_instance
        self._hosts = hosts
        self._host_family = host_family
        self._families = tuple(families)
        self._family_by_name = MappingProxyType(family_by_name)
        self._format_sets = tuple(format_sets)
        self._policies = tuple(policies)
        self._policy_windows = tuple(policy_windows)
        self._host_ordinals = host_ordinals
        self._family_ordinals = family_ordinals
        self._format_set_ordinals = format_set_ordinals
        self._policy_ordinals = policy_ordinals
        self._by_format = MappingProxyType(mutable_by_format)
        self._content_digest = content_hasher.hexdigest()

        packed_index_bytes = (
            sys.getsizeof(host_ordinals)
            + sys.getsizeof(family_ordinals)
            + sys.getsizeof(format_set_ordinals)
            + sys.getsizeof(policy_ordinals)
            + host_family.estimated_bytes()
            + sum(sys.getsizeof(bucket) for bucket in mutable_by_format.values())
        )
        estimated_bytes = (
            sys.getsizeof(self)
            + sys.getsizeof(self._content_digest)
            + by_instance.estimated_bytes()
            + hosts.estimated_bytes()
            + packed_index_bytes
            + sys.getsizeof(self._families)
            + sum(sys.getsizeof(family) for family in self._families)
            + sys.getsizeof(self._family_by_name)
            + sys.getsizeof(family_by_name)
            + sys.getsizeof(self._format_sets)
            + sum(
                sys.getsizeof(format_set)
                + sum(sys.getsizeof(source_format) for source_format in format_set)
                for format_set in self._format_sets
            )
            + sys.getsizeof(self._policies)
            + sys.getsizeof(self._policy_windows)
            + sum(
                _estimate_policy_bytes(policy, windows)
                for policy, windows in zip(self._policies, self._policy_windows, strict=True)
            )
            + sys.getsizeof(self._by_format)
            + sys.getsizeof(mutable_by_format)
            + sum(sys.getsizeof(source_format) for source_format in self._by_format)
        )
        estimated_index_bytes = (
            sys.getsizeof(self)
            + by_instance.estimated_index_bytes()
            + hosts.estimated_index_bytes()
            + packed_index_bytes
            + sys.getsizeof(self._families)
            + sys.getsizeof(self._family_by_name)
            + sys.getsizeof(family_by_name)
            + sys.getsizeof(self._by_format)
            + sys.getsizeof(mutable_by_format)
        )
        self._census = CollectionDeploymentCensus(
            source_instances=self._source_count,
            collection_windows=collection_window_count,
            exact_identity_keys=self._source_count,
            host_family_buckets=host_family.bucket_count,
            max_host_family_bucket=host_family.max_bucket,
            capability_words=self._source_count,
            estimated_bytes=estimated_bytes,
            unique_hostnames=len(hosts),
            unique_families=len(self._families),
            unique_format_sets=len(self._format_sets),
            unique_policies=len(self._policies),
            exact_index_capacity=by_instance.capacity,
            host_index_capacity=hosts.capacity,
            host_family_index_capacity=host_family.capacity,
            packed_index_bytes=packed_index_bytes,
            estimated_index_bytes=estimated_index_bytes,
        )

    def __len__(self) -> int:
        return self._source_count

    def __iter__(self) -> Iterator[SourceInstanceDeployment]:
        for ordinal in range(self._source_count):
            yield self.source_by_ordinal(ordinal)

    @property
    def census(self) -> CollectionDeploymentCensus:
        """Return the precomputed deployment census without scanning."""

        return self._census

    @property
    def content_digest(self) -> str:
        """Return the deterministic ordered deployment SHA-256 digest."""

        return self._content_digest

    def source_by_ordinal(self, ordinal: int) -> SourceInstanceDeployment:
        """Return one source from the immutable dense deployment array."""

        if ordinal < 0 or ordinal >= self._source_count:
            raise KeyError(ordinal)
        return self._materialize_source(ordinal)

    def _materialize_identity(self, ordinal: int) -> SourceInstanceIdentity:
        identity = object.__new__(SourceInstanceIdentity)
        object.__setattr__(identity, "source_instance", self._by_instance.strings[ordinal])
        object.__setattr__(identity, "hostname", self._hosts.strings[self._host_ordinals[ordinal]])
        object.__setattr__(identity, "family", self._families[self._family_ordinals[ordinal]])
        return identity

    def _materialize_source(self, ordinal: int) -> SourceInstanceDeployment:
        source = object.__new__(SourceInstanceDeployment)
        object.__setattr__(source, "identity", self._materialize_identity(ordinal))
        object.__setattr__(source, "formats", self._format_sets[self._format_set_ordinals[ordinal]])
        object.__setattr__(source, "policy", self._policies[self._policy_ordinals[ordinal]])
        return source

    def source_by_instance(self, source_instance: str) -> SourceInstanceDeployment | None:
        """Return a globally exact source instance in amortized constant time."""

        ordinal = self._by_instance.find(
            _normalized_lookup_text(source_instance, "source_instance")
        )
        return self._materialize_source(ordinal) if ordinal is not None else None

    def ordinal_for_instance(self, source_instance: str) -> int | None:
        """Return one dense source ordinal with a single exact hash lookup."""

        return self._by_instance.find(_normalized_lookup_text(source_instance, "source_instance"))

    def policy_by_ordinal(self, ordinal: int) -> SourceCollectionPolicy:
        """Return the interned immutable policy for one dense source ordinal."""

        if ordinal < 0 or ordinal >= self._source_count:
            raise KeyError(ordinal)
        return self._policies[self._policy_ordinals[ordinal]]

    def source_for(
        self,
        hostname: str,
        family: str,
        source_instance: str,
    ) -> SourceInstanceDeployment | None:
        """Return one exact host/family/instance source without a broad scan."""

        normalized_hostname = _normalized_lookup_text(hostname, "hostname")
        normalized_family = _normalized_lookup_text(family, "family")
        normalized_instance = _normalized_lookup_text(source_instance, "source_instance")
        ordinal = self._by_instance.find(normalized_instance)
        if ordinal is None:
            return None
        if self._hosts.strings[self._host_ordinals[ordinal]] != normalized_hostname:
            return None
        if self._families[self._family_ordinals[ordinal]] != normalized_family:
            return None
        return self._materialize_source(ordinal)

    def _host_family_bucket(self, hostname: str, family: str) -> int | array | None:
        normalized_hostname = _normalized_lookup_text(hostname, "hostname")
        normalized_family = _normalized_lookup_text(family, "family")
        host_ordinal = self._hosts.find(normalized_hostname)
        family_ordinal = self._family_by_name.get(normalized_family)
        if host_ordinal is None or family_ordinal is None:
            return None
        return self._host_family.lookup(_HostFamilyIndex.pack(host_ordinal, family_ordinal))

    def iter_host_family(
        self,
        hostname: str,
        family: str,
    ) -> Iterator[SourceInstanceDeployment]:
        """Yield one exact host/family bucket without copying its ordinal tuple."""

        bucket = self._host_family_bucket(hostname, family)
        if bucket is None:
            return
        if isinstance(bucket, int):
            yield self._materialize_source(bucket)
            return
        for ordinal in bucket:
            yield self._materialize_source(ordinal)

    def count_host_family(self, hostname: str, family: str) -> int:
        """Return the exact host/family cardinality without materializing results."""

        bucket = self._host_family_bucket(hostname, family)
        if bucket is None:
            return 0
        return 1 if isinstance(bucket, int) else len(bucket)

    def iter_format(self, source_format: str) -> Iterator[SourceInstanceDeployment]:
        """Yield sources supporting one exact format in compiled ordinal order."""

        normalized_format = _normalized_lookup_text(source_format, "source format")
        for ordinal in self._by_format.get(normalized_format, ()):
            yield self._materialize_source(ordinal)

    def count_format(self, source_format: str) -> int:
        """Return source cardinality for one format without materializing results."""

        normalized_format = _normalized_lookup_text(source_format, "source format")
        return len(self._by_format.get(normalized_format, ()))

    def collection_window_at(
        self,
        source_instance: str,
        timestamp: datetime,
    ) -> CollectionWindow | None:
        """Resolve one source window in ``O(log n)`` time."""

        ordinal = self._by_instance.find(
            _normalized_lookup_text(source_instance, "source_instance")
        )
        if ordinal is None:
            return None
        return self._policy_windows[self._policy_ordinals[ordinal]].at(timestamp)

    def capability_intersection(
        self,
        source_instance: str,
        requested: CollectionCapability,
    ) -> CollectionCapability:
        """Intersect requested and available capabilities with one word operation."""

        ordinal = self._by_instance.find(
            _normalized_lookup_text(source_instance, "source_instance")
        )
        if ordinal is None:
            return CollectionCapability.NONE
        return self._policies[self._policy_ordinals[ordinal]].capabilities & CollectionCapability(
            requested
        )

    def projection_envelope(
        self,
        *,
        occurrence_id: str,
        target_id: str,
        source_instance: str,
        canonical_time: datetime,
        requested_capabilities: CollectionCapability,
        optional_capabilities: CollectionCapability = CollectionCapability.NONE,
        role: ProjectionRole = ProjectionRole.HOST,
    ) -> ProjectionEnvelope:
        """Create an ephemeral deployment-stage envelope for one projection target."""

        normalized_instance = _normalized_lookup_text(source_instance, "source_instance")
        ordinal = self._by_instance.find(normalized_instance)
        if ordinal is None:
            raise KeyError(f"unknown source_instance {normalized_instance!r}")
        return self.projection_envelope_by_ordinal(
            occurrence_id=occurrence_id,
            target_id=target_id,
            source_ordinal=ordinal,
            canonical_time=canonical_time,
            requested_capabilities=requested_capabilities,
            optional_capabilities=optional_capabilities,
            role=role,
        )

    def projection_envelope_by_ordinal(
        self,
        *,
        occurrence_id: str,
        target_id: str,
        source_ordinal: int,
        canonical_time: datetime,
        requested_capabilities: CollectionCapability,
        optional_capabilities: CollectionCapability = CollectionCapability.NONE,
        role: ProjectionRole = ProjectionRole.HOST,
    ) -> ProjectionEnvelope:
        """Create an envelope from a pre-resolved dense source ordinal."""

        if source_ordinal < 0 or source_ordinal >= self._source_count:
            raise KeyError(source_ordinal)
        policy_ordinal = self._policy_ordinals[source_ordinal]
        policy = self._policies[policy_ordinal]
        requested = CollectionCapability(requested_capabilities)
        optional = CollectionCapability(optional_capabilities)
        effective = policy.capabilities & (requested | optional)
        window = self._policy_windows[policy_ordinal].at(canonical_time)
        if not policy.enabled:
            admission = ProjectionAdmission.SOURCE_DISABLED
        elif window is None:
            admission = ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW
        elif not effective.covers(requested):
            admission = ProjectionAdmission.MISSING_CAPABILITY
        else:
            admission = ProjectionAdmission.READY
        return ProjectionEnvelope(
            occurrence_id=occurrence_id,
            target_id=target_id,
            source_ordinal=source_ordinal,
            source=self._materialize_identity(source_ordinal),
            canonical_time=canonical_time,
            requested_capabilities=requested,
            effective_capabilities=effective,
            admission=admission,
            collection_window=window,
            role=role,
            optional_capabilities=optional,
        )

    def exact_lookup_candidates(self, source_instance: str) -> int:
        """Return occupied primary-index candidates inspected by one exact lookup."""

        normalized = _normalized_lookup_text(source_instance, "source_instance")
        return self._by_instance.find_with_candidates(normalized)[1]

    def host_family_lookup_candidates(self, hostname: str, family: str) -> int:
        """Return occupied host and composite candidates inspected by one lookup."""

        normalized_hostname = _normalized_lookup_text(hostname, "hostname")
        normalized_family = _normalized_lookup_text(family, "family")
        host_ordinal, host_candidates = self._hosts.find_with_candidates(normalized_hostname)
        family_ordinal = self._family_by_name.get(normalized_family)
        if host_ordinal is None or family_ordinal is None:
            return host_candidates
        _, composite_candidates = self._host_family.lookup_with_candidates(
            _HostFamilyIndex.pack(host_ordinal, family_ordinal)
        )
        return host_candidates + composite_candidates
