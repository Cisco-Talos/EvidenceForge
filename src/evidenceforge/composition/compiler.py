# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compile authored or authoritative documents into one canonical runtime input."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from evidenceforge.config import get_config_directory
from evidenceforge.models.exceptions import PackError, SchemaValidationError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import LoadedSourceGraph, load_scenario_source_graph
from evidenceforge.utils.assets import EMAIL_CORPUS_MAX_SOURCE_BYTES
from evidenceforge.utils.paths import read_text_file_beneath
from evidenceforge.utils.personas import merge_builtin_personas
from evidenceforge.utils.yaml_loader import load_yaml_file

from .models import (
    CompiledScenario,
    CompositionSpec,
    EffectiveConfig,
    ResolvedScenarioDocument,
    ScenarioV1Document,
    ScenarioV2Document,
    SelectedPack,
)
from .packs import LoadedPack, PackRepository

CONFIG_FAMILY_REGISTRY: dict[str, str] = {
    "persona_catalog": "pack-safe",
    "process_catalog": "pack-safe",
    "application_catalog": "pack-safe",
    "destination_catalog": "pack-safe",
    "traffic_catalog": "pack-safe",
    "storage_catalog": "pack-safe",
    "project_overlay": "project-only",
    "formats": "engine-owned",
    "evaluation": "engine-owned",
    "safety": "engine-owned",
    "resource_limits": "engine-owned",
    "oob_authorization": "engine-owned",
}
_PACKAGED_DEFAULTS_LOCK = threading.Lock()
_PACKAGED_DEFAULTS_SIGNATURE: tuple[tuple[str, int, int], ...] | None = None
_PACKAGED_DEFAULTS_SNAPSHOT: dict[str, Any] | None = None

_KEYED_LIST_FIELDS: dict[tuple[str, ...], str] = {
    ("environment", "users"): "username",
    ("environment", "systems"): "hostname",
    ("environment", "network_identities"): "id",
    ("environment", "stale_accounts"): "username",
    ("environment", "groups"): "name",
    ("environment", "storage", "servers"): "system",
    ("environment", "storage", "mappings"): "id",
    ("personas",): "name",
}


def resolve_project_root(scenario_path: Path, explicit: Path | None = None) -> Path:
    """Resolve the deterministic project root for a scenario compilation."""

    if explicit is not None:
        return explicit.resolve()
    resolved = scenario_path.resolve()
    for parent in (resolved.parent, *resolved.parents):
        if (parent / ".eforge").is_dir():
            return parent
    return resolved.parent


def resolve_management_project_root(explicit: Path | None = None) -> Path:
    """Resolve project root for pack commands that do not have a scenario."""

    if explicit is not None:
        return explicit.resolve()
    current = Path.cwd().resolve()
    for parent in (current, *current.parents):
        if (parent / ".eforge").is_dir():
            return parent
    return current


def _canonical_hash(value: Any) -> str:
    """Hash a JSON-compatible value with stable separators and key ordering."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_graph_digest(graph: LoadedSourceGraph) -> str:
    """Hash the ordered source content identities without machine-specific paths."""

    return _canonical_hash([source.sha256 for source in graph.sources])


def _portable_source_assets(graph: LoadedSourceGraph) -> dict[str, str]:
    """Embed exact YAML sources under stable content-addressed names."""

    assets: dict[str, str] = {}
    for source in graph.sources:
        key = _portable_source_key(source.sha256, source.path.name)
        assets[key] = source.content.decode("utf-8")
    return assets


def _portable_source_key(sha256: str, filename: str) -> str:
    """Return a content-addressed source identity without an absolute path."""

    return f"sources/{sha256[:16]}-{filename}"


def _portable_field_origins(graph: LoadedSourceGraph) -> dict[str, str]:
    """Map every authored leaf/list item to its portable declaring source."""

    identities = {
        source.path: _portable_source_key(source.sha256, source.path.name)
        for source in graph.sources
    }
    return {".".join(path): identities[source] for path, source in sorted(graph.origins.items())}


def _embed_scenario_assets(
    scenario: Scenario,
    graph: LoadedSourceGraph,
) -> tuple[Scenario, dict[str, str]]:
    """Inline generation-relevant YAML sidecars and rewrite their canonical references."""

    email = scenario.environment.email
    if email is None or email.corpus is None:
        return scenario, {}
    if email.corpus.startswith("embedded:"):
        raise SchemaValidationError("authored scenarios cannot use reserved embedded: asset refs")
    declaring_file = _declaring_file_for(graph, ("environment", "email", "corpus"))
    content = read_text_file_beneath(
        declaring_file.parent,
        email.corpus,
        max_bytes=EMAIL_CORPUS_MAX_SOURCE_BYTES,
        label="email corpus",
    )
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    asset_key = f"email-corpus/{content_hash}.yaml"
    embedded_email = email.model_copy(update={"corpus": f"embedded:{asset_key}"})
    environment = scenario.environment.model_copy(update={"email": embedded_email})
    return scenario.model_copy(update={"environment": environment}), {asset_key: content}


def _load_project_overlays(project_root: Path) -> dict[str, Any]:
    """Snapshot project overlay YAML without consulting a user-global location."""

    overlay_root = project_root / ".eforge" / "config"
    if not overlay_root.is_dir():
        return {}
    overlays: dict[str, Any] = {}
    for path in sorted(overlay_root.rglob("*.yaml")):
        if path.is_symlink():
            raise PackError(f"project configuration overlay cannot be a symlink: {path}")
        resolved = path.resolve()
        if not resolved.is_relative_to(overlay_root.resolve()):
            raise PackError(f"project configuration overlay escapes project root: {path}")
        overlays[str(path.relative_to(overlay_root))] = load_yaml_file(path) or {}
    return overlays


def _load_packaged_defaults() -> dict[str, Any]:
    """Snapshot all packaged semantic YAML outside the independently resolved pack repository."""

    global _PACKAGED_DEFAULTS_SIGNATURE, _PACKAGED_DEFAULTS_SNAPSHOT
    config_root = get_config_directory().resolve()
    paths = [
        path
        for path in sorted(config_root.rglob("*.yaml"))
        if path.relative_to(config_root).parts[0] != "packs"
    ]
    signature = tuple(
        (
            str(path.relative_to(config_root)),
            path.stat().st_mtime_ns,
            path.stat().st_size,
        )
        for path in paths
    )
    with _PACKAGED_DEFAULTS_LOCK:
        if signature == _PACKAGED_DEFAULTS_SIGNATURE and _PACKAGED_DEFAULTS_SNAPSHOT is not None:
            return copy.deepcopy(_PACKAGED_DEFAULTS_SNAPSHOT)

    defaults: dict[str, Any] = {}
    for path in paths:
        relative = path.relative_to(config_root)
        if path.is_symlink():
            raise PackError(f"packaged configuration cannot be a symlink: {path}")
        defaults[str(relative)] = load_yaml_file(path)
    with _PACKAGED_DEFAULTS_LOCK:
        _PACKAGED_DEFAULTS_SIGNATURE = signature
        _PACKAGED_DEFAULTS_SNAPSHOT = copy.deepcopy(defaults)
    return defaults


def _merge_keyed_list(
    lower: list[Any],
    higher: list[Any],
    *,
    key_field: str,
    path: tuple[str, ...],
) -> list[Any]:
    """Merge a registered keyed list while preserving deterministic lower order."""

    if not all(isinstance(entry, dict) and key_field in entry for entry in (*lower, *higher)):
        return copy.deepcopy(higher)
    result = copy.deepcopy(lower)
    positions = {str(entry[key_field]).casefold(): index for index, entry in enumerate(result)}
    for incoming in higher:
        key = str(incoming[key_field]).casefold()
        if key in positions:
            index = positions[key]
            result[index] = _merge_registered(
                result[index], incoming, path=(*path, str(incoming[key_field]))
            )
        else:
            positions[key] = len(result)
            result.append(copy.deepcopy(incoming))
    return result


def _merge_registered(lower: Any, higher: Any, *, path: tuple[str, ...] = ()) -> Any:
    """Apply explicit scenario/org merge behavior; the higher-precedence value wins."""

    if isinstance(lower, dict) and isinstance(higher, dict):
        result = copy.deepcopy(lower)
        for key, incoming in higher.items():
            child_path = (*path, str(key))
            if key in result:
                result[key] = _merge_registered(result[key], incoming, path=child_path)
            else:
                result[key] = copy.deepcopy(incoming)
        return result
    if isinstance(lower, list) and isinstance(higher, list):
        key_field = _KEYED_LIST_FIELDS.get(path)
        if key_field is not None:
            return _merge_keyed_list(lower, higher, key_field=key_field, path=path)
        return copy.deepcopy(higher)
    return copy.deepcopy(higher)


def _merge_catalogs(
    selected: list[LoadedPack],
    *,
    organization_index: int | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Merge fixed catalogs and reject peer-industry export collisions."""

    catalogs: dict[str, dict[str, Any]] = {
        "persona_catalog": {},
        "process_catalog": {},
        "application_catalog": {},
        "destination_catalog": {},
        "traffic_catalog": {},
        "storage_catalog": {},
    }
    origins: dict[str, str] = {}
    for index, pack in enumerate(selected):
        is_organization = organization_index == index
        for catalog_name, entries in pack.catalogs.items():
            for name, value in entries.items():
                origin_key = f"{catalog_name}.{name}"
                if name in catalogs[catalog_name] and not is_organization:
                    raise PackError(
                        f"peer industry pack collision at {origin_key}: "
                        f"{origins[origin_key]} and "
                        f"{pack.manifest.name}@{pack.manifest.version}"
                    )
                catalogs[catalog_name][name] = copy.deepcopy(value)
                origins[origin_key] = f"{pack.manifest.name}@{pack.manifest.version}"
    return catalogs, origins


def _declaring_file_for(
    graph: LoadedSourceGraph,
    path: tuple[str, ...],
) -> Path:
    """Find the declaring source for a composition field or its parent."""

    current = path
    while current:
        source = graph.origins.get(current)
        if source is not None:
            return source
        current = current[:-1]
    return graph.root


def _resolve_composition(
    spec: CompositionSpec,
    graph: LoadedSourceGraph,
    project_root: Path,
) -> tuple[list[LoadedPack], int | None]:
    """Resolve direct industries or an organization and its exact dependencies."""

    if not spec.industries and spec.organization is None:
        return [], None
    repository = PackRepository(project_root)
    selected: list[LoadedPack] = []
    if spec.industries:
        for index, reference in enumerate(spec.industries):
            declaring_file = _declaring_file_for(
                graph, ("composition", "industries", str(index), "path")
            )
            selected.append(
                repository.resolve(
                    reference,
                    expected_type="industry",
                    declaring_file=declaring_file,
                )
            )
        return selected, None

    assert spec.organization is not None
    organization_declaring_file = _declaring_file_for(
        graph, ("composition", "organization", "path")
    )
    organization = repository.resolve(
        spec.organization,
        expected_type="organization",
        declaring_file=organization_declaring_file,
    )
    for dependency in organization.manifest.industry_dependencies:
        selected.append(
            repository.resolve(
                dependency,
                expected_type="industry",
                declaring_file=organization.root / "pack.yaml",
            )
        )
    selected.append(organization)
    return selected, len(selected) - 1


def _compile_resolved(
    raw: dict[str, Any],
) -> CompiledScenario:
    """Load an authoritative document without discovering packs or project config."""

    from .artifacts import verify_resolved_document

    try:
        document = ResolvedScenarioDocument.model_validate(raw)
        verify_resolved_document(document)
        scenario = Scenario.model_validate(document.scenario)
        effective = EffectiveConfig.model_validate(document.effective_config)
        selected_packs = tuple(
            SelectedPack.model_validate(pack)
            for pack in document.provenance.get("selected_packs", [])
        )
    except ValidationError as exc:
        raise SchemaValidationError(f"invalid resolved scenario document: {exc}") from exc
    digests = dict(document.digests)
    return CompiledScenario(
        scenario=scenario,
        effective_config=effective,
        assets=document.assets,
        selected_packs=selected_packs,
        provenance=document.provenance,
        digests=digests,
        authored_kind="resolved",
    )


def compile_scenario(
    path: Path | str,
    *,
    project_root: Path | None = None,
    generation_seed: int | None = None,
) -> CompiledScenario:
    """Compile Scenario 1.0, Scenario 2.0, or authoritative resolved YAML."""

    graph = load_scenario_source_graph(path)
    raw = copy.deepcopy(graph.data)
    if raw.get("kind") == "evidenceforge.resolved-scenario":
        return _compile_resolved(raw)
    resolved_project_root = resolve_project_root(graph.root, project_root)

    selected: list[LoadedPack] = []
    catalogs: dict[str, dict[str, Any]] = {}
    catalog_origins: dict[str, str] = {}
    authored_kind: str
    if raw.get("scenario_version") == "2.0":
        try:
            composition = CompositionSpec.model_validate(raw.get("composition") or {})
        except ValidationError as exc:
            raise SchemaValidationError(f"invalid Scenario 2.0 composition: {exc}") from exc
        authored = {
            key: value
            for key, value in raw.items()
            if key not in {"scenario_version", "composition"}
        }
        if "version" in authored:
            raise SchemaValidationError(
                "Scenario 2.0 uses scenario_version: '2.0'; remove the legacy version field"
            )
        ScenarioV2Document(
            scenario_version="2.0",
            composition=composition,
            authored=authored,
        )
        selected, organization_index = _resolve_composition(
            composition, graph, resolved_project_root
        )
        catalogs, catalog_origins = _merge_catalogs(selected, organization_index=organization_index)
        lower: dict[str, Any] = {}
        if organization_index is not None:
            organization = selected[organization_index]
            if organization.environment:
                lower["environment"] = organization.environment
            if organization.baseline_activity:
                lower["baseline_activity"] = organization.baseline_activity
        if catalogs.get("persona_catalog"):
            lower["personas"] = list(catalogs["persona_catalog"].values())
        scenario_data = _merge_registered(lower, authored)
        scenario_data["version"] = "2.0"
        authored_kind = "scenario-2.0"
    else:
        version = raw.get("version", "1.0")
        if version != "1.0":
            raise SchemaValidationError(
                "authored scenario must use version: '1.0' or scenario_version: '2.0'"
            )
        scenario_data = raw
        authored_kind = "scenario-1.0"

    scenario_data = merge_builtin_personas(scenario_data)
    try:
        scenario = Scenario.model_validate(scenario_data)
        if authored_kind == "scenario-1.0":
            ScenarioV1Document(scenario=scenario)
    except ValidationError as exc:
        raise SchemaValidationError(f"scenario schema validation failed: {exc}") from exc
    if generation_seed is not None:
        scenario = scenario.model_copy(update={"generation_seed": generation_seed})
    scenario, embedded_yaml_assets = _embed_scenario_assets(scenario, graph)

    project_overlays = _load_project_overlays(resolved_project_root)
    effective_config = EffectiveConfig(
        project_root=".",
        packaged_defaults=_load_packaged_defaults(),
        catalogs=catalogs,
        project_overlays=project_overlays,
        families=CONFIG_FAMILY_REGISTRY,
        embedded_yaml_assets=embedded_yaml_assets,
    )
    assets = _portable_source_assets(graph)
    for asset_key, content in embedded_yaml_assets.items():
        assets[f"corpora/{asset_key}"] = content
    for pack in selected:
        for relative_path, content in pack.assets.items():
            assets[
                f"packs/{pack.manifest.type}/{pack.manifest.name}/"
                f"{pack.manifest.version}/{relative_path}"
            ] = content

    scenario_payload = scenario.model_dump(mode="json")
    effective_payload = effective_config.model_dump(mode="json")
    digests = {
        "source_graph_sha256": _source_graph_digest(graph),
        "scenario_sha256": _canonical_hash(scenario_payload),
        "effective_config_sha256": _canonical_hash(effective_payload),
    }
    digests["compiled_sha256"] = _canonical_hash(
        {
            "scenario": scenario_payload,
            "effective_config": effective_payload,
            "assets": assets,
            "packs": [pack.selected().model_dump(mode="json") for pack in selected],
        }
    )
    provenance = {
        "authored_kind": authored_kind,
        "source_count": len(graph.sources),
        "field_origins": _portable_field_origins(graph),
        "catalog_origins": catalog_origins,
        "project_overlay_files": sorted(project_overlays),
        "selected_packs": [pack.selected().model_dump(mode="json") for pack in selected],
        "composition_precedence": [
            "package-defaults",
            "industries",
            "organization",
            "project-overlay",
            "scenario",
        ],
        "merge_rules": {
            "registered_keyed_lists": {
                ".".join(path): key for path, key in sorted(_KEYED_LIST_FIELDS.items())
            },
            "unregistered_lists": "replace",
            "peer_industry_collision": "error",
            "organization_catalog_exports": "qualified-additive",
            "scenario_over_organization_model": "registered-merge",
        },
    }
    return CompiledScenario(
        scenario=scenario,
        effective_config=effective_config,
        assets=assets,
        selected_packs=tuple(pack.selected() for pack in selected),
        provenance=provenance,
        digests=digests,
        authored_kind=authored_kind,  # type: ignore[arg-type]
    )


def with_runtime_scenario(compiled: CompiledScenario, scenario: Scenario) -> CompiledScenario:
    """Refresh scenario-dependent digests after permitted generation-time overrides."""

    scenario_payload = scenario.model_dump(mode="json")
    effective_payload = compiled.effective_config.model_dump(mode="json")
    digests = dict(compiled.digests)
    digests["scenario_sha256"] = _canonical_hash(scenario_payload)
    digests["compiled_sha256"] = _canonical_hash(
        {
            "scenario": scenario_payload,
            "effective_config": effective_payload,
            "assets": compiled.assets,
            "packs": [pack.model_dump(mode="json") for pack in compiled.selected_packs],
        }
    )
    return compiled.model_copy(update={"scenario": scenario, "digests": digests})
