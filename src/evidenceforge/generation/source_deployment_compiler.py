# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compile resolved scenarios into exact immutable collection deployments.

This module is deliberately independent of the dispatcher and engine. It
compiles source instances from a resolved ``Scenario``, the concrete emitter
formats enabled for that run, and the scenario's network-sensor catalog.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from evidenceforge.config.observation_profiles import get_observation_profile
from evidenceforge.events.collection_policy import (
    CollectionBatchingPolicy,
    CollectionCapability,
    CollectionWindow,
    SourceCollectionOverride,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.source_catalog import (
    DEFAULT_SOURCE_CATALOG,
    SourceCatalog,
    SourceCatalogError,
    SourceFormatDescriptor,
    SourceOwnerKind,
    source_platform_for_os,
)
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.models.exceptions import GenerationError
from evidenceforge.models.scenario import Scenario

_SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*:[a-z0-9][a-z0-9._-]*(?::[a-z0-9][a-z0-9._-]*)*$")
_STRUCTURAL_CAPABILITIES = (
    CollectionCapability.OPTIONAL_FIELDS
    | CollectionCapability.COLLECTION_WINDOWS
    | CollectionCapability.BATCHING
)


class SourceDeploymentCompilationError(GenerationError):
    """A resolved scenario cannot produce an unambiguous source deployment."""


@dataclass(frozen=True, slots=True)
class SourceDeploymentCompilation:
    """Deterministic compilation result and its canonical digest."""

    deployment: CompiledCollectionDeployment
    digest: str
    catalog_digest: str
    source_instances: tuple[str, ...]
    census: SourceDeploymentCompilerCensus


@dataclass(frozen=True, slots=True)
class SourceDeploymentCompilerCensus:
    """Precomputed compiler work and exact-lookup bounds."""

    source_instances: int
    host_sources: int
    sensor_sources: int
    selected_formats: int
    max_formats_per_source: int
    host_applicability_checks: int
    sensor_applicability_checks: int
    exact_lookup_candidate_bound: int


@dataclass(frozen=True, slots=True)
class _SourceDraft:
    identity: SourceInstanceIdentity
    formats: tuple[str, ...]
    descriptors: tuple[SourceFormatDescriptor, ...]

    @property
    def supported_capabilities(self) -> CollectionCapability:
        value = CollectionCapability.NONE
        for descriptor in self.descriptors:
            value |= descriptor.capabilities
        return value


def _source_segment(value: str, field_name: str) -> str:
    normalized = value.strip().casefold()
    if not normalized or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", normalized) is None:
        raise SourceDeploymentCompilationError(
            f"{field_name} {value!r} cannot form a stable source ID; use letters, digits, "
            "'.', '_', or '-'"
        )
    return normalized


def exact_source_instance_id(family: str, owner_id: str, local_name: str = "") -> str:
    """Build one stable exact ``family:owner[:local]`` source identifier."""

    parts = [
        _source_segment(family, "source family"),
        _source_segment(owner_id, "source owner"),
    ]
    if local_name:
        parts.append(_source_segment(local_name, "source local name"))
    return ":".join(parts)


def _normalize_source_id(value: str, field_name: str) -> str:
    normalized = value.strip().casefold()
    if _SOURCE_ID_RE.fullmatch(normalized) is None:
        raise SourceDeploymentCompilationError(
            f"{field_name} {value!r} must be an exact family:owner[:local] source ID"
        )
    return normalized


def _roles(system: object) -> tuple[str, ...]:
    return tuple(str(role) for role in (getattr(system, "roles", None) or ()))


def _drafts_for_hosts(
    scenario: Scenario,
    enabled_formats: frozenset[str],
    catalog: SourceCatalog,
) -> list[_SourceDraft]:
    host_descriptors: list[SourceFormatDescriptor] = []
    for format_name in sorted(enabled_formats):
        descriptor = catalog.descriptor(format_name)
        if descriptor.owner is SourceOwnerKind.HOST:
            host_descriptors.append(descriptor)
    drafts: list[_SourceDraft] = []
    systems = sorted(
        scenario.environment.systems,
        key=lambda system: system.hostname.strip().casefold(),
    )
    for system in systems:
        platform = source_platform_for_os(system.os)
        by_family: dict[str, list[SourceFormatDescriptor]] = {}
        for descriptor in host_descriptors:
            if descriptor.applies_to_host(platform, _roles(system)):
                by_family.setdefault(descriptor.family, []).append(descriptor)
        for family, descriptors in sorted(by_family.items()):
            source_id = exact_source_instance_id(family, system.hostname)
            ordered = tuple(sorted(descriptors, key=lambda descriptor: descriptor.name))
            drafts.append(
                _SourceDraft(
                    identity=SourceInstanceIdentity(
                        source_instance=source_id,
                        hostname=system.hostname,
                        family=family,
                    ),
                    formats=tuple(descriptor.name for descriptor in ordered),
                    descriptors=ordered,
                )
            )
    return drafts


def _sensor_descriptors(
    sensor: object,
    catalog: SourceCatalog,
) -> tuple[SourceFormatDescriptor, ...]:
    sensor_name = str(getattr(sensor, "name", ""))
    sensor_type = str(getattr(sensor, "type", ""))
    declared_names = tuple(str(value) for value in (getattr(sensor, "log_formats", None) or ()))
    selected_by: dict[str, str] = {}
    for raw_name in declared_names:
        try:
            expansion = catalog.expand((raw_name,))
        except SourceCatalogError as error:
            raise SourceDeploymentCompilationError(
                f"network sensor {sensor_name!r} has an invalid log_formats selection: {error}"
            ) from error
        for format_name in expansion:
            existing = selected_by.get(format_name)
            if existing is not None:
                raise SourceDeploymentCompilationError(
                    f"network sensor {sensor_name!r} has ambiguous log_formats selectors "
                    f"{existing!r} and {raw_name!r}; both select {format_name!r}"
                )
            selected_by[format_name] = raw_name
    declared_formats = tuple(sorted(selected_by))

    descriptors: list[SourceFormatDescriptor] = []
    for format_name in declared_formats:
        descriptor = catalog.descriptor(format_name)
        if descriptor.owner is not SourceOwnerKind.SENSOR:
            raise SourceDeploymentCompilationError(
                f"network sensor {sensor_name!r} cannot deploy host format {format_name!r}"
            )
        if not descriptor.applies_to_sensor(sensor_type):
            allowed = ", ".join(sorted(descriptor.sensor_types))
            raise SourceDeploymentCompilationError(
                f"network sensor {sensor_name!r} has type {sensor_type!r}, but format "
                f"{format_name!r} requires one of: {allowed}"
            )
        descriptors.append(descriptor)
    return tuple(descriptors)


def _drafts_for_sensors(
    scenario: Scenario,
    enabled_formats: frozenset[str],
    catalog: SourceCatalog,
) -> list[_SourceDraft]:
    network = scenario.environment.network
    if network is None:
        return []

    sensors = sorted(
        network.sensors,
        key=lambda sensor: (
            str(sensor.name).strip().casefold(),
            str(sensor.hostname or sensor.name).strip().casefold(),
        ),
    )
    drafts: list[_SourceDraft] = []
    for sensor in sensors:
        selected = tuple(
            descriptor
            for descriptor in _sensor_descriptors(sensor, catalog)
            if descriptor.name in enabled_formats
        )
        by_family: dict[str, list[SourceFormatDescriptor]] = {}
        for descriptor in selected:
            by_family.setdefault(descriptor.family, []).append(descriptor)
        for family, descriptors in sorted(by_family.items()):
            source_id = exact_source_instance_id(family, sensor.name)
            ordered = tuple(sorted(descriptors, key=lambda descriptor: descriptor.name))
            drafts.append(
                _SourceDraft(
                    identity=SourceInstanceIdentity(
                        source_instance=source_id,
                        hostname=sensor.hostname or sensor.name,
                        family=family,
                    ),
                    formats=tuple(descriptor.name for descriptor in ordered),
                    descriptors=ordered,
                )
            )
    return drafts


def _parse_profile_time(value: object, field_name: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise SourceDeploymentCompilationError(
                f"named observation profile {field_name} is not an ISO-8601 datetime: {value!r}"
            ) from error
    else:
        raise SourceDeploymentCompilationError(
            f"named observation profile {field_name} must be a datetime string"
        )
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceDeploymentCompilationError(
            f"named observation profile {field_name} must be timezone-aware"
        )
    return parsed.astimezone(UTC)


def _profile_batching(
    value: object,
    *,
    profile_name: str,
    source_id: str,
) -> CollectionBatchingPolicy | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise SourceDeploymentCompilationError(
            "named observation profile collection_batching must be a mapping"
        )
    enabled = bool(value.get("enabled", False))
    if not enabled:
        return CollectionBatchingPolicy()

    if "interval_us" in value:
        interval_us = int(value["interval_us"])
    else:
        interval_range = value.get("interval_ms", {})
        if not isinstance(interval_range, Mapping):
            raise SourceDeploymentCompilationError(
                "named observation profile collection_batching.interval_ms must be a mapping"
            )
        minimum = int(interval_range.get("min_ms", 0))
        maximum = int(interval_range.get("max_ms", 0))
        if minimum < 0 or maximum < minimum:
            raise SourceDeploymentCompilationError(
                "named observation profile collection batching interval is invalid"
            )
        width = maximum - minimum + 1
        material = f"{profile_name}|{source_id}|collection-batching".encode()
        sampled_ms = minimum + (
            int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % width
        )
        interval_us = sampled_ms * 1_000
    if interval_us < 1:
        raise SourceDeploymentCompilationError(
            "enabled named observation profile batching requires a positive interval"
        )
    return CollectionBatchingPolicy(
        enabled=True,
        interval_us=interval_us,
        max_records=int(value.get("max_records", 0)),
    )


def _profile_windows(value: object) -> tuple[CollectionWindow, ...] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise SourceDeploymentCompilationError(
            "named observation profile collection_window must be a mapping"
        )
    if not bool(value.get("enabled", False)):
        return (CollectionWindow(),)
    return (
        CollectionWindow(
            start=_parse_profile_time(value.get("start"), "collection_window.start"),
            end=_parse_profile_time(value.get("end"), "collection_window.end"),
        ),
    )


def _profile_override(
    profile: Mapping[str, Any],
    *,
    profile_name: str,
    draft: _SourceDraft,
    catalog: SourceCatalog,
) -> SourceCollectionOverride | None:
    default = profile.get("default", {})
    sources = profile.get("sources", {})
    if not isinstance(default, Mapping) or not isinstance(sources, Mapping):
        raise SourceDeploymentCompilationError(
            f"named observation profile {profile_name!r} has invalid default or sources data"
        )
    family_value = sources.get(draft.identity.family, {})
    if not isinstance(family_value, Mapping):
        raise SourceDeploymentCompilationError(
            f"named observation profile family {draft.identity.family!r} must be a mapping"
        )
    settings = dict(default)
    settings.update(family_value)
    if not settings:
        return None

    missingness = float(settings["missingness"]) if "missingness" in settings else None
    raw_format_missingness = settings.get("format_missingness")
    format_missingness: dict[str, float] | None = None
    if raw_format_missingness is not None:
        if not isinstance(raw_format_missingness, Mapping):
            raise SourceDeploymentCompilationError(
                "named observation profile format_missingness must be a mapping"
            )
        format_missingness = {}
        for raw_format, raw_probability in raw_format_missingness.items():
            format_name = str(raw_format).strip().casefold()
            try:
                descriptor = catalog.descriptor(format_name)
            except SourceCatalogError as error:
                raise SourceDeploymentCompilationError(str(error)) from error
            if descriptor.family != draft.identity.family:
                continue
            if format_name in draft.formats:
                format_missingness[format_name] = float(raw_probability)

    return SourceCollectionOverride(
        missingness=missingness,
        format_missingness=format_missingness,
        windows=_profile_windows(settings.get("collection_window")),
        batching=_profile_batching(
            settings.get("collection_batching"),
            profile_name=profile_name,
            source_id=draft.identity.source_instance,
        ),
    )


def _validate_profile_catalog(profile: Mapping[str, Any], catalog: SourceCatalog) -> None:
    default = profile.get("default", {})
    sources = profile.get("sources", {})
    if not isinstance(default, Mapping) or not isinstance(sources, Mapping):
        raise SourceDeploymentCompilationError(
            "named observation profile default and sources must be mappings"
        )
    known_families = set(catalog.family_names)
    normalized_families = {str(family).strip().casefold() for family in sources}
    unknown_families = sorted(normalized_families - known_families)
    if unknown_families:
        raise SourceDeploymentCompilationError(
            "named observation profile contains unknown source families: "
            + ", ".join(unknown_families)
        )

    entries: list[tuple[str | None, Mapping[str, Any]]] = [(None, default)]
    for raw_family, raw_settings in sources.items():
        family = str(raw_family).strip().casefold()
        if family != raw_family:
            raise SourceDeploymentCompilationError(
                f"named observation profile family {raw_family!r} must use canonical name "
                f"{family!r}"
            )
        if not isinstance(raw_settings, Mapping):
            raise SourceDeploymentCompilationError(
                f"named observation profile family {family!r} must be a mapping"
            )
        entries.append((family, raw_settings))

    for family, settings in entries:
        format_missingness = settings.get("format_missingness")
        if format_missingness is None:
            continue
        if not isinstance(format_missingness, Mapping):
            raise SourceDeploymentCompilationError(
                "named observation profile format_missingness must be a mapping"
            )
        for raw_format_name in format_missingness:
            format_name = str(raw_format_name).strip().casefold()
            if format_name != raw_format_name:
                raise SourceDeploymentCompilationError(
                    f"named observation format {raw_format_name!r} must use canonical name "
                    f"{format_name!r}"
                )
            try:
                descriptor = catalog.descriptor(format_name)
            except SourceCatalogError as error:
                raise SourceDeploymentCompilationError(str(error)) from error
            if family is not None and descriptor.family != family:
                raise SourceDeploymentCompilationError(
                    f"named profile format {format_name!r} does not belong to source family "
                    f"{family!r}"
                )


def _scenario_override(value: object) -> SourceCollectionOverride:
    capabilities_value = getattr(value, "capabilities", None)
    capabilities: CollectionCapability | None = None
    if capabilities_value is not None:
        capabilities = CollectionCapability.NONE
        for capability_name in capabilities_value:
            try:
                capabilities |= CollectionCapability[str(capability_name).upper()]
            except KeyError as error:
                raise SourceDeploymentCompilationError(
                    f"unknown collection capability {capability_name!r}"
                ) from error

    windows_value = getattr(value, "windows", None)
    windows = None
    if windows_value is not None:
        windows = tuple(CollectionWindow(window.start, window.end) for window in windows_value)

    batching_value = getattr(value, "batching", None)
    batching = None
    if batching_value is not None:
        batching = CollectionBatchingPolicy(
            enabled=batching_value.enabled,
            interval_us=batching_value.interval_us,
            max_records=batching_value.max_records,
        )

    format_missingness = getattr(value, "format_missingness", None)
    optional_fields = getattr(value, "optional_fields", None)
    return SourceCollectionOverride(
        enabled=getattr(value, "enabled", None),
        capabilities=capabilities,
        missingness=getattr(value, "missingness", None),
        format_missingness=format_missingness,
        optional_fields=(frozenset(optional_fields) if optional_fields is not None else None),
        windows=windows,
        batching=batching,
    )


def _exact_override_map(
    values: Mapping[str, SourceCollectionOverride],
    field_name: str,
) -> dict[str, SourceCollectionOverride]:
    result: dict[str, SourceCollectionOverride] = {}
    for raw_source_id, override in values.items():
        source_id = _normalize_source_id(str(raw_source_id), field_name)
        if source_id in result:
            raise SourceDeploymentCompilationError(
                f"{field_name} contains duplicate exact source {source_id!r}"
            )
        result[source_id] = override
    return result


def _scenario_override_map(
    scenario: Scenario,
) -> tuple[dict[str, SourceCollectionOverride], dict[str, object]]:
    result: dict[str, SourceCollectionOverride] = {}
    raw_values: dict[str, object] = {}
    for value in getattr(scenario.environment, "observation_overrides", ()):
        source_id = _normalize_source_id(value.source_instance, "scenario observation override")
        if source_id in result:
            raise SourceDeploymentCompilationError(
                f"scenario contains duplicate exact source override {source_id!r}"
            )
        result[source_id] = _scenario_override(value)
        raw_values[source_id] = value
    return result, raw_values


def _validate_override(
    source_id: str,
    override: SourceCollectionOverride | None,
    draft: _SourceDraft,
    layer_name: str,
) -> None:
    if override is None:
        return
    if override.capabilities is not None:
        unsupported = override.capabilities & ~(
            draft.supported_capabilities | _STRUCTURAL_CAPABILITIES
        )
        if unsupported:
            raise SourceDeploymentCompilationError(
                f"{layer_name} for {source_id!r} requests unsupported capability bits "
                f"{int(unsupported)}"
            )
    if override.format_missingness is not None:
        undeployed = sorted(set(override.format_missingness) - set(draft.formats))
        if undeployed:
            raise SourceDeploymentCompilationError(
                f"{layer_name} for {source_id!r} names formats not deployed by that source: "
                + ", ".join(undeployed)
            )


def _validate_scenario_guards(source_id: str, value: object, draft: _SourceDraft) -> None:
    family = getattr(value, "family", None)
    if family is not None and str(family).casefold() != draft.identity.family:
        raise SourceDeploymentCompilationError(
            f"scenario guard for {source_id!r} does not match family {draft.identity.family!r}"
        )
    system = getattr(value, "system", None)
    if system is not None and str(system).casefold() != draft.identity.hostname:
        raise SourceDeploymentCompilationError(
            f"scenario system guard for {source_id!r} does not match {draft.identity.hostname!r}"
        )


def _effective_deployment(
    draft: _SourceDraft,
    *,
    profile_name: str,
    profile: Mapping[str, Any],
    project_pack: SourceCollectionOverride | None,
    scenario_override: SourceCollectionOverride | None,
    catalog: SourceCatalog,
) -> SourceInstanceDeployment:
    default = SourceCollectionPolicy(capabilities=draft.supported_capabilities)
    named = _profile_override(
        profile,
        profile_name=profile_name,
        draft=draft,
        catalog=catalog,
    )
    _validate_override(draft.identity.source_instance, named, draft, "named profile")
    _validate_override(draft.identity.source_instance, project_pack, draft, "project/pack override")
    _validate_override(
        draft.identity.source_instance,
        scenario_override,
        draft,
        "scenario override",
    )
    return SourceInstanceDeployment.from_layers(
        identity=draft.identity,
        formats=draft.formats,
        defaults=default,
        profile=named,
        project_pack=project_pack,
        scenario=scenario_override,
    )


def _time_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _compilation_digest(
    sources: tuple[SourceInstanceDeployment, ...],
    catalog_digest: str,
) -> str:
    payload = {
        "catalog_sha256": catalog_digest,
        "sources": [
            {
                "source_instance": source.identity.source_instance,
                "hostname": source.identity.hostname,
                "family": source.identity.family,
                "formats": list(source.formats),
                "policy": {
                    "enabled": source.policy.enabled,
                    "capabilities": int(source.policy.capabilities),
                    "missingness": source.policy.missingness,
                    "format_missingness": dict(source.policy.format_missingness),
                    "optional_fields": sorted(source.policy.optional_fields),
                    "windows": [
                        {"start": _time_text(window.start), "end": _time_text(window.end)}
                        for window in source.policy.windows
                    ],
                    "batching": {
                        "enabled": source.policy.batching.enabled,
                        "interval_us": source.policy.batching.interval_us,
                        "max_records": source.policy.batching.max_records,
                    },
                },
            }
            for source in sources
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def compile_scenario_source_deployment(
    scenario: Scenario,
    *,
    emitter_formats: Iterable[str] | None = None,
    named_profile: Mapping[str, Any] | None = None,
    project_pack_overrides: Mapping[str, SourceCollectionOverride] | None = None,
    catalog: SourceCatalog = DEFAULT_SOURCE_CATALOG,
) -> SourceDeploymentCompilation:
    """Compile exact host and sensor collection sources for a resolved scenario.

    Precedence is built-in catalog defaults, the selected named profile,
    project/organization-pack exact-source overrides, and scenario exact-source
    overrides. Every selector must resolve exactly once.
    """

    raw_formats = (
        emitter_formats
        if emitter_formats is not None
        else (
            str(log_entry["format"]) for log_entry in scenario.output.logs if "format" in log_entry
        )
    )
    try:
        enabled_formats = frozenset(catalog.expand(raw_formats))
    except SourceCatalogError as error:
        raise SourceDeploymentCompilationError(
            f"invalid emitter format selection: {error}"
        ) from error

    profile_name = scenario.observation_profile or "complete"
    profile_data = get_observation_profile(profile_name) if named_profile is None else named_profile
    if not isinstance(profile_data, Mapping) or not profile_data:
        raise SourceDeploymentCompilationError(
            f"named observation profile {profile_name!r} does not exist or is empty"
        )
    _validate_profile_catalog(profile_data, catalog)

    drafts = [
        *_drafts_for_hosts(scenario, enabled_formats, catalog),
        *_drafts_for_sensors(scenario, enabled_formats, catalog),
    ]
    drafts.sort(key=lambda draft: draft.identity.source_instance)
    source_ids = tuple(draft.identity.source_instance for draft in drafts)
    seen_source_ids: set[str] = set()
    duplicate_source_ids: set[str] = set()
    for source_id in source_ids:
        if source_id in seen_source_ids:
            duplicate_source_ids.add(source_id)
        seen_source_ids.add(source_id)
    duplicate_ids = sorted(duplicate_source_ids)
    if duplicate_ids:
        raise SourceDeploymentCompilationError(
            "ambiguous source-instance identities: " + ", ".join(duplicate_ids)
        )
    deployed_sensor_formats = {
        format_name
        for draft in drafts
        if draft.descriptors and draft.descriptors[0].owner is SourceOwnerKind.SENSOR
        for format_name in draft.formats
    }
    selected_sensor_formats = {
        format_name
        for format_name in enabled_formats
        if catalog.descriptor(format_name).owner is SourceOwnerKind.SENSOR
    }
    missing_sensor_deployments = sorted(selected_sensor_formats - deployed_sensor_formats)
    if missing_sensor_deployments:
        raise SourceDeploymentCompilationError(
            "selected sensor-backed formats have no applicable deployed sensor: "
            + ", ".join(missing_sensor_deployments)
        )

    project_overrides = _exact_override_map(
        project_pack_overrides or {},
        "project/pack observation overrides",
    )
    scenario_overrides, raw_scenario_overrides = _scenario_override_map(scenario)
    known_ids = set(source_ids)
    unused_project = sorted(set(project_overrides) - known_ids)
    unused_scenario = sorted(set(scenario_overrides) - known_ids)
    if unused_project:
        raise SourceDeploymentCompilationError(
            "project/pack observation overrides name undeployed sources: "
            + ", ".join(unused_project)
        )
    if unused_scenario:
        raise SourceDeploymentCompilationError(
            "scenario observation overrides name undeployed sources: " + ", ".join(unused_scenario)
        )

    sources: list[SourceInstanceDeployment] = []
    for draft in drafts:
        source_id = draft.identity.source_instance
        raw_scenario = raw_scenario_overrides.get(source_id)
        if raw_scenario is not None:
            _validate_scenario_guards(source_id, raw_scenario, draft)
        sources.append(
            _effective_deployment(
                draft,
                profile_name=profile_name,
                profile=profile_data,
                project_pack=project_overrides.get(source_id),
                scenario_override=scenario_overrides.get(source_id),
                catalog=catalog,
            )
        )

    frozen_sources = tuple(sources)
    host_formats = sum(
        catalog.descriptor(format_name).owner is SourceOwnerKind.HOST
        for format_name in enabled_formats
    )
    sensor_applicability_checks = 0
    network = scenario.environment.network
    if network is not None:
        for sensor in network.sensors:
            sensor_applicability_checks += len(catalog.expand(sensor.log_formats))
    host_sources = sum(
        bool(draft.descriptors) and draft.descriptors[0].owner is SourceOwnerKind.HOST
        for draft in drafts
    )
    census = SourceDeploymentCompilerCensus(
        source_instances=len(drafts),
        host_sources=host_sources,
        sensor_sources=len(drafts) - host_sources,
        selected_formats=len(enabled_formats),
        max_formats_per_source=max((len(draft.formats) for draft in drafts), default=0),
        host_applicability_checks=len(scenario.environment.systems) * host_formats,
        sensor_applicability_checks=sensor_applicability_checks,
        exact_lookup_candidate_bound=1 if drafts else 0,
    )
    return SourceDeploymentCompilation(
        deployment=CompiledCollectionDeployment(frozen_sources),
        digest=_compilation_digest(frozen_sources, catalog.digest),
        catalog_digest=catalog.digest,
        source_instances=source_ids,
        census=census,
    )


__all__ = [
    "SourceDeploymentCompilation",
    "SourceDeploymentCompilerCensus",
    "SourceDeploymentCompilationError",
    "compile_scenario_source_deployment",
    "exact_source_instance_id",
]
