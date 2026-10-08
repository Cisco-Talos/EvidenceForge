"""Bounded asset browsing and validated file-owned Studio edits."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_core import to_jsonable_python

from evidenceforge.composition.accounts import (
    AccountTransition,
    account_directory_effects,
    account_transitions,
)
from evidenceforge.composition.compiler import compile_scenario
from evidenceforge.composition.models import (
    ApplicationCatalogEntry,
    DestinationCatalogEntry,
    PackReference,
    ProcessCatalogEntry,
    StorageCatalogEntry,
    TrafficCatalogEntry,
)
from evidenceforge.composition.packs import (
    CATALOG_FILES,
    LoadedPack,
    PackRepository,
    parse_pack_cli_reference,
)
from evidenceforge.composition.semantic_validation import (
    packaged_builtin_application_ids,
    packaged_builtin_dns_tags,
    packaged_builtin_persona_ids,
)
from evidenceforge.config import get_config_directory
from evidenceforge.config.context import ConfigurationContext, OverlayReference, select_context
from evidenceforge.config.overlay import load_with_overlay
from evidenceforge.config.provider import (
    effective_config_scope,
    pack_overlay_document,
)
from evidenceforge.config.schemas import ApplicationEntry, DnsEntry
from evidenceforge.generation.activity.application_catalog import _merge_catalog
from evidenceforge.generation.activity.dns_registry import _merge_dns_registry
from evidenceforge.generation.world_model import known_topology_roles
from evidenceforge.models.exceptions import SchemaValidationError
from evidenceforge.models.scenario import (
    Group,
    NetworkIdentity,
    Persona,
    StaleAccount,
    System,
    User,
)
from evidenceforge.studio.contexts import context_path, scenario_context_path, scenario_overlay_root
from evidenceforge.studio.imports import dependency_health
from evidenceforge.utils.files import load_scenario_source_graph
from evidenceforge.utils.yaml_loader import load_yaml_text

OriginKind = Literal["scenario", "pack", "mixed", "configuration"]


class AssetOrigin(BaseModel):
    """One graphical badge's accessible label and source."""

    model_config = ConfigDict(extra="forbid")
    kind: OriginKind
    source: str


class AssetSummary(BaseModel):
    """Compact list entry; full values are fetched only on expansion."""

    model_config = ConfigDict(extra="forbid")
    id: str
    key: str
    name: str
    description: str = ""
    origin: AssetOrigin
    account_status: Literal["active", "disabled", "stale"] | None = None


class AssetCategory(BaseModel):
    """Category metadata with counts before search and filtering."""

    model_config = ConfigDict(extra="forbid")
    key: str
    label: str
    total: int
    editable: bool = True


class AssetPage(BaseModel):
    """Filtered, bounded view of a fingerprinted inventory."""

    model_config = ConfigDict(extra="forbid")
    revision: str
    categories: list[AssetCategory]
    category: str
    total: int
    matching: int
    page: int
    page_size: int
    entries: list[AssetSummary]


class AssetDetail(BaseModel):
    """Lazy effective values, field origins and authoring schema."""

    model_config = ConfigDict(extra="forbid")
    revision: str
    summary: AssetSummary | None = None
    category: str
    identity_field: str
    value: dict[str, Any]
    field_origins: dict[str, AssetOrigin]
    schema_document: dict[str, Any]
    next_version: str | None = None
    inherited_value: dict[str, Any] | None = None
    override_fields: list[str] = Field(default_factory=list)
    conversion_from: Literal["users", "stale_accounts"] | None = None
    conversion_effects: list[str] = Field(default_factory=list)
    previous_value: dict[str, Any] | None = None


class AssetChoices(BaseModel):
    """Bounded searchable choices from the same effective asset revision."""

    model_config = ConfigDict(extra="forbid")
    revision: str
    matching: int
    page: int
    page_size: int
    entries: list[str]


class AssetEdit(BaseModel):
    """One requested change against the revision the user reviewed."""

    model_config = ConfigDict(extra="forbid")
    revision: str
    category: str
    asset_id: str | None = None
    key: str = Field(min_length=1, max_length=200)
    value: dict[str, Any]
    version: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")
    restore_fields: list[str] = Field(default_factory=list, max_length=100)
    convert_from: Literal["users", "stale_accounts"] | None = None
    preview: bool = False


class AssetSaved(BaseModel):
    """File destination of a successfully validated change."""

    model_config = ConfigDict(extra="forbid")
    path: Path
    version: str | None = None
    validation_errors: list[str] = Field(default_factory=list)
    effects: list[str] = Field(default_factory=list)


ENVIRONMENT_MODELS: dict[str, tuple[str, type[BaseModel], str]] = {
    "users": ("Users", User, "username"),
    "groups": ("Groups", Group, "name"),
    "systems": ("Systems", System, "hostname"),
    "network_identities": ("Network identities", NetworkIdentity, "id"),
    "stale_accounts": ("Stale accounts", StaleAccount, "username"),
}
CATALOG_MODELS: dict[str, tuple[str, type[BaseModel], str]] = {
    "persona_catalog": ("Personas", Persona, "name"),
    "process_catalog": ("Processes", ProcessCatalogEntry, "key"),
    "application_catalog": ("Applications", ApplicationCatalogEntry, "key"),
    "destination_catalog": ("Destinations / DNS", DestinationCatalogEntry, "key"),
    "traffic_catalog": ("Traffic profiles", TrafficCatalogEntry, "key"),
    "storage_catalog": ("Storage profiles", StorageCatalogEntry, "key"),
}
RUNTIME_MODELS: dict[str, tuple[str, type[BaseModel], str]] = {
    "dns": ("DNS", DnsEntry, "domain"),
    "applications": ("Applications", ApplicationEntry, "id"),
    "processes": ("Processes", ApplicationEntry, "id"),
}
RUNTIME_FILES = {
    "dns": ("activity/dns_registry.yaml", "domains", _merge_dns_registry),
    "applications": ("activity/application_catalog.yaml", "applications", _merge_catalog),
    "processes": ("activity/application_catalog.yaml", "applications", _merge_catalog),
}


def _editor_schema(model: type[BaseModel], category: str) -> dict[str, Any]:
    """Annotate authoring schemas with choices owned by the effective inventory."""
    document = model.model_json_schema()
    references = {
        "primary_system": "systems",
        "assigned_user": "users",
        "members": "users",
        "groups": "groups",
        "persona": "personas",
        "personas": "personas",
        "processes": "process_refs",
        "destination": "destination_refs",
        "builtins": "application_ids",
    }
    suggestions = {
        name: name for name in ("roles", "services", "permissions", "categories", "tags")
    }

    def choice_type(schema: dict[str, Any]) -> bool:
        if reference := schema.get("$ref"):
            return choice_type(document.get("$defs", {}).get(reference.rsplit("/", 1)[-1], {}))
        if variants := schema.get("anyOf") or schema.get("oneOf"):
            return all(choice_type(child) for child in variants if child.get("type") != "null")
        return schema.get("type") == "string" or (
            schema.get("type") == "array" and choice_type(schema.get("items", {}))
        )

    def annotate(schema: dict[str, Any]) -> None:
        for name, field_schema in schema.get("properties", {}).items():
            vocabulary = references.get(name) or suggestions.get(name)
            if vocabulary and choice_type(field_schema):
                field_schema["x-asset-choices"] = vocabulary
                field_schema["x-asset-custom"] = name in suggestions
            if name == "platforms":
                field_schema.setdefault("propertyNames", {"enum": ["windows", "linux"]})
                field_schema.setdefault("minProperties", 1)
            if name == "system_types":
                field_schema.setdefault(
                    "x-asset-enum", ["workstation", "server", "domain_controller"]
                )
            if name == "last_active":
                field_schema["format"] = "date"
            if name == "email":
                field_schema["format"] = "email"
            annotate(field_schema)
        for child in schema.get("$defs", {}).values():
            annotate(child)

    annotate(document)
    if category == "dns":
        document["properties"]["tags"]["x-asset-custom"] = False
    return document


def leaves(value: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten values structurally, including empty containers."""
    if isinstance(value, (dict, list)) and value:
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        return {
            path: leaf
            for key, child in entries
            for path, leaf in leaves(child, f"{prefix}.{key}" if prefix else str(key)).items()
        }
    return {prefix: value}


def _identifier(category: str, key: str) -> str:
    return hashlib.sha256(f"{category}\0{key}".encode()).hexdigest()[:24]


def _raw_owner(
    origins: dict[tuple[str, ...], Path], prefix: tuple[str, ...], fallback: Path
) -> Path:
    return next(
        (source for path, source in origins.items() if path[: len(prefix)] == prefix), fallback
    )


@dataclass
class Inventory:
    """Server-side immutable values; the list API exposes only summaries."""

    revision: str
    models: dict[str, tuple[str, type[BaseModel], str]]
    rows: dict[str, list[AssetSummary]] = field(default_factory=dict)
    values: dict[str, dict[str, Any]] = field(default_factory=dict)
    origins: dict[str, dict[str, AssetOrigin]] = field(default_factory=dict)
    pack: LoadedPack | None = None
    search_text: dict[str, str] = field(default_factory=dict)
    runtime_headers: dict[str, dict[str, Any]] = field(default_factory=dict)
    choice_values: dict[str, list[str]] = field(default_factory=dict)
    inherited_values: dict[str, dict[str, Any]] = field(default_factory=dict)
    override_fields: dict[str, list[str]] = field(default_factory=dict)
    conversion_values: dict[str, dict[str, Any]] = field(default_factory=dict)
    conversion_previous_values: dict[str, dict[str, Any]] = field(default_factory=dict)
    conversion_effects: dict[str, list[str]] = field(default_factory=dict)
    immutable: bool = False

    def add(
        self, category: str, key: str, value: dict[str, Any], origins: dict[str, AssetOrigin]
    ) -> None:
        """Index an effective entity and all searchable values once."""
        value = to_jsonable_python(value)
        kinds = {origin.kind for origin in origins.values()}
        kind: OriginKind = (
            "mixed"
            if "pack" in kinds and "scenario" in kinds
            else (
                "scenario"
                if "scenario" in kinds
                else "pack"
                if "pack" in kinds
                else "configuration"
            )
        )
        sources = list(
            dict.fromkeys(
                origin.source
                for origin in origins.values()
                if origin.kind
                in ({"scenario", "pack"} if kind != "configuration" else {"configuration"})
            )
        )
        if len(sources) > 1:
            sources = [source for source in sources if source != "Built-in defaults"]
        row_id = _identifier(category, key)
        description = str(
            value.get("email")
            or value.get("ip")
            or value.get("description")
            or value.get("display_name")
            or ""
        )
        summary = AssetSummary(
            id=row_id,
            key=key,
            name=key,
            description=description[:200],
            origin=AssetOrigin(kind=kind, source=" · ".join(sources)),
            account_status=(
                "stale"
                if category == "stale_accounts"
                else ("active" if value.get("enabled", True) else "disabled")
                if category == "users"
                else None
            ),
        )
        self.rows.setdefault(category, []).append(summary)
        self.search_text[row_id] = (
            f"{key} {summary.origin.source} {json.dumps(value, ensure_ascii=False)}".casefold()
        )
        self.values[row_id] = value
        self.origins[row_id] = origins

    def page(
        self,
        category: str,
        query: str,
        origin: str,
        source: str,
        page: int,
        size: int,
        account_status: str = "",
    ) -> AssetPage:
        """Search the entire inventory before slicing one bounded page."""
        if category not in self.models:
            raise ValueError("Choose an available asset category")
        rows = self.visible_rows(category)
        words = query.casefold().split()
        matching = [
            row
            for row in rows
            if (not origin or row.origin.kind == origin)
            and (not account_status or row.account_status == account_status)
            and (not source or source.casefold() in row.origin.source.casefold())
            and all(word in self.search_text[row.id] for word in words)
        ]
        current = min(page, max(0, (len(matching) - 1) // size))
        return AssetPage(
            revision=self.revision,
            categories=[
                AssetCategory(
                    key=key,
                    label=model[0],
                    total=len(self.visible_rows(key)),
                    editable=not self.immutable,
                )
                for key, model in self.models.items()
                if key != "stale_accounts"
            ],
            category=category,
            total=len(rows),
            matching=len(matching),
            page=current,
            page_size=size,
            entries=matching[current * size : (current + 1) * size],
        )

    def visible_rows(self, category: str) -> list[AssetSummary]:
        """Present ordinary and stale user accounts together without changing ownership."""
        if category == "users":
            return sorted(
                [*self.rows.get("users", []), *self.rows.get("stale_accounts", [])],
                key=lambda row: row.key.casefold(),
            )
        return self.rows.get(category, [])

    def choices(self, source: str, query: str, page: int, size: int) -> AssetChoices:
        """Search reference and suggested vocabularies before bounding the result."""
        if source not in self.choice_values:
            raise ValueError("Choose an available field vocabulary")
        words = query.casefold().split()
        matching = [
            value
            for value in self.choice_values[source]
            if all(word in value.casefold() for word in words)
        ]
        current = min(page, max(0, (len(matching) - 1) // size))
        return AssetChoices(
            revision=self.revision,
            matching=len(matching),
            page=current,
            page_size=size,
            entries=matching[current * size : (current + 1) * size],
        )

    def detail(self, category: str, asset_id: str | None) -> AssetDetail:
        """Return one entry, or the schema for adding an entry."""
        if category not in self.models:
            raise ValueError("Choose an available asset category")
        if (
            category == "users"
            and asset_id
            and any(row.id == asset_id for row in self.rows.get("stale_accounts", []))
        ):
            category = "stale_accounts"
        _label, model, identity = self.models[category]
        summary = next((row for row in self.rows.get(category, []) if row.id == asset_id), None)
        if asset_id and summary is None:
            raise ValueError("Asset no longer exists. Refresh the list")
        next_version = None
        if self.pack and self.pack.manifest.status != "draft":
            major, minor, patch = map(int, self.pack.manifest.version.split("."))
            next_version = f"{major}.{minor}.{patch + 1}"
        return AssetDetail(
            revision=self.revision,
            summary=summary,
            category=category,
            identity_field=identity,
            value=self.values[summary.id] if summary else {},
            field_origins=self.origins[summary.id] if summary else {},
            schema_document=_editor_schema(model, category),
            next_version=next_version,
            inherited_value=self.inherited_values.get(summary.id) if summary else None,
            override_fields=self.override_fields.get(summary.id, []) if summary else [],
        )

    def conversion_detail(self, category: str, asset_id: str) -> AssetDetail:
        """Prepare a scenario-only conversion using saved user details when available."""
        current = self.detail(category, asset_id)
        if self.pack or current.category not in {"users", "stale_accounts"}:
            raise ValueError("Convert accounts from their scenario workspace")
        target = "stale_accounts" if current.category == "users" else "users"
        draft = self.detail(target, None)
        return draft.model_copy(
            update={
                "summary": current.summary,
                "value": copy.deepcopy(self.conversion_values[asset_id]),
                "conversion_from": current.category,
                "previous_value": current.value,
                "conversion_effects": self.conversion_effects.get(asset_id, []),
            }
        )


def inventory_revision(source: Path, workspace: Path, is_pack: bool) -> str:
    """Fingerprint every selected dependency, include and configuration scope."""
    if not is_pack:
        return dependency_health(source, workspace).fingerprint
    reference, kind = parse_pack_cli_reference(str(source))
    repository = PackRepository(workspace)
    pack = repository.resolve(reference, expected_type=kind)
    dependencies = repository.validate_semantics(pack)
    return hashlib.sha256(
        json.dumps([pack.digest, *[member.digest for member in dependencies]]).encode()
    ).hexdigest()


def build_inventory(source: Path, workspace: Path, is_pack: bool) -> Inventory:
    """Project canonical compiler/provider truth without guessing runtime catalogs."""
    revision = inventory_revision(source, workspace, is_pack)
    models = {**ENVIRONMENT_MODELS, **(CATALOG_MODELS if is_pack else RUNTIME_MODELS)}
    inventory = Inventory(revision, models)
    from evidenceforge.artifacts.lifecycle import _receipt_root

    inventory.immutable = _receipt_root(source) is not None
    if is_pack:
        reference, kind = parse_pack_cli_reference(str(source))
        pack = PackRepository(workspace).resolve(reference, expected_type=kind)
        inventory.pack = pack
        pack_origin = AssetOrigin(
            kind="pack",
            source=f"{pack.manifest.publisher}/{pack.manifest.name}@{pack.manifest.version}",
        )
        if pack.manifest.type != "organization":
            inventory.models = dict(CATALOG_MODELS)
        else:
            for category, (_label, _model, identity) in ENVIRONMENT_MODELS.items():
                for value in pack.environment.get(category, []) or []:
                    inventory.add(
                        category,
                        value[identity],
                        value,
                        {path: pack_origin for path in leaves(value)},
                    )
        for category in CATALOG_MODELS:
            for key in pack.catalogs.get(category, {}):
                local = key.split(":", 1)[-1]
                # Author raw local values, not names qualified by compilation adapters.
                origins = [
                    origin
                    for path, origin in pack.catalog_field_origins.items()
                    if path.startswith(f"{category}.{key}.")
                ]
                declaring = pack.root / (
                    origins[0]
                    if origins
                    else dict((name, path) for name, path, _model in CATALOG_FILES)[category]
                )
                graph = load_scenario_source_graph(declaring, allowed_root=pack.root)
                value = graph.data[category][local]
                inventory.add(category, local, value, {path: pack_origin for path in leaves(value)})
    else:
        graph = load_scenario_source_graph(source)
        compiled = compile_scenario(
            source,
            project_root=workspace if context_path(source, workspace) is None else None,
            context=context_path(source, workspace),
        )
        if compiled.authored_kind == "resolved" and not inventory.immutable:
            raise ValueError("Open an authored scenario to edit its environment")
        effective = compiled.scenario.model_dump(mode="json")["environment"]
        inventory.choice_values["personas"] = [
            persona.name for persona in compiled.scenario.personas
        ]
        inventory.choice_values["application_ids"] = []
        authored = graph.data.get("environment") or {}
        organization = next(
            (pack for pack in compiled.selected_packs if pack.type == "organization"), None
        )
        lower: dict[str, Any] = {}
        if organization:
            if graph.data.get("composition", {}).get("organization", {}).get("source") in {
                "path",
                "draft",
            }:
                reference = PackReference.model_validate(graph.data["composition"]["organization"])
                declaring = graph.origins.get(("composition", "organization", "path"), source)
                reference = reference.model_copy(
                    update={"path": str((declaring.parent / reference.path).resolve())}
                )
                kind = "organization"
            else:
                reference, kind = parse_pack_cli_reference(organization.location)
            lower = PackRepository(workspace).resolve(reference, expected_type=kind).environment
        transitions = {item.username.casefold(): item for item in account_transitions(graph.data)}
        from evidenceforge.composition.compiler import _merge_registered

        directory = _merge_registered({"environment": lower}, {"environment": authored})
        directory_environment = directory["environment"]
        hidden = {
            category: {
                entry["username"].casefold(): entry
                for entry in directory_environment.get(category, []) or []
            }
            for category in ("users", "stale_accounts")
        }
        for category in ("users", "stale_accounts"):
            for value in effective.get(category, []) or []:
                key = value["username"]
                row_id = _identifier(category, key)
                target = "stale_accounts" if category == "users" else "users"
                seed = copy.deepcopy(hidden[target].get(key.casefold(), {"username": key}))
                if key.casefold() in hidden[target]:
                    inventory.conversion_previous_values[row_id] = (
                        ENVIRONMENT_MODELS[target][1]
                        .model_validate(hidden[target][key.casefold()])
                        .model_dump(mode="json")
                    )
                record = transitions.get(key.casefold())
                if target == "users" and record and record.previous_user:
                    seed = record.previous_user.model_dump(mode="json")
                if target == "stale_accounts":
                    seed.setdefault(
                        "last_active", compiled.scenario.time_window.start.date().isoformat()
                    )
                    seed.setdefault("reason", "Retired account")
                inventory.conversion_effects[row_id] = account_directory_effects(
                    directory_environment, key, restoring=target == "users"
                )
                inventory.conversion_values[row_id] = seed
        retired = {
            name for name, record in transitions.items() if record.target == "stale_accounts"
        }
        retired_links = {
            "groups": {
                entry["name"].casefold()
                for entry in directory_environment.get("groups", []) or []
                if any(name.casefold() in retired for name in entry.get("members", []))
            },
            "systems": {
                entry["hostname"].casefold()
                for entry in directory_environment.get("systems", []) or []
                if str(entry.get("assigned_user", "")).casefold() in retired
            },
        }
        pack_accounts = {
            category: {entry["username"].casefold() for entry in lower.get(category, []) or []}
            for category in ("users", "stale_accounts")
        }
        default_origin = AssetOrigin(kind="configuration", source="Built-in defaults")
        for category, (_label, _model, identity) in ENVIRONMENT_MODELS.items():
            inherited = {
                str(value[identity]).casefold(): value for value in lower.get(category, []) or []
            }
            local = {
                str(value[identity]).casefold(): (index, value)
                for index, value in enumerate(authored.get(category, []) or [])
            }
            for value in effective.get(category, []) or []:
                key = str(value[identity])
                origins = {path: default_origin for path in leaves(value)}
                if key.casefold() in inherited and organization:
                    origin = AssetOrigin(
                        kind="pack",
                        source=f"{organization.publisher}/{organization.name}@{organization.version}",
                    )
                    for path in leaves(inherited[key.casefold()]):
                        for leaf in origins:
                            if leaf == path or leaf.startswith(path + "."):
                                origins[leaf] = origin
                if key.casefold() in local:
                    index, raw = local[key.casefold()]
                    for path in leaves(raw):
                        owner = graph.origins.get(
                            ("environment", category, str(index), *path.split(".")), source
                        )
                        origin = AssetOrigin(kind="scenario", source=str(owner))
                        for leaf in origins:
                            if leaf == path or leaf.startswith(path + "."):
                                origins[leaf] = origin
                link_changed = key.casefold() in retired_links.get(category, set())
                if link_changed:
                    path = "members" if category == "groups" else "assigned_user"
                    origins[path] = AssetOrigin(
                        kind="scenario", source=f"{source} · account retirement"
                    )
                inventory.add(category, key, value, origins)
                row_id = _identifier(category, key)
                counterpart = "stale_accounts" if category == "users" else "users"
                if (
                    category in {"users", "stale_accounts"}
                    and organization
                    and (
                        key.casefold() in inherited
                        or (
                            key.casefold() in transitions
                            and key.casefold() in pack_accounts[counterpart]
                        )
                    )
                    and inventory.rows[category][-1].origin.kind != "pack"
                ):
                    row = inventory.rows[category][-1]
                    row.origin = AssetOrigin(
                        kind="mixed",
                        source=f"{organization.publisher}/{organization.name}@{organization.version} · {source}",
                    )
                    inventory.search_text[row.id] += " " + row.origin.source.casefold()
                if key.casefold() in inherited:
                    baseline = copy.deepcopy(inherited[key.casefold()])
                    if category == "groups":
                        baseline["members"] = [
                            name
                            for name in baseline.get("members", [])
                            if name.casefold() not in retired
                        ]
                    elif (
                        category == "systems"
                        and str(baseline.get("assigned_user", "")).casefold() in retired
                    ):
                        baseline["assigned_user"] = None
                    inventory.inherited_values[row_id] = _model.model_validate(baseline).model_dump(
                        mode="json"
                    )
                if key.casefold() in local:
                    inventory.override_fields[row_id] = [
                        path
                        for path in leaves(local[key.casefold()][1])
                        if path != identity and not path.startswith(identity + ".")
                    ]
        with effective_config_scope(compiled.effective_config, refresh_legacy_globals=False):
            for category in ("dns", "applications"):
                relative, list_name, merge = RUNTIME_FILES[category]
                default = copy.deepcopy(compiled.effective_config.packaged_defaults[relative])
                identity = RUNTIME_MODELS[category][2]
                values = {entry[identity]: entry for entry in default.get(list_name, [])}
                origins_by_key = {
                    key: {path: default_origin for path in leaves(value)}
                    for key, value in values.items()
                }
                layers: list[tuple[dict[str, Any], AssetOrigin]] = []
                packed = pack_overlay_document(relative)
                if packed:
                    layers.append((packed, AssetOrigin(kind="pack", source="Selected packs")))
                selection = select_context(workspace, context_path(source, workspace))
                private_names = {
                    reference.name
                    for reference in selection.overlays
                    if reference.path == scenario_overlay_root(source, workspace)
                }
                configuration_layers = [
                    ("Workspace configuration", compiled.effective_config.project_overlays),
                    *[
                        (layer.name, layer.files)
                        for layer in compiled.effective_config.overlay_layers
                    ],
                ]
                for name, files in configuration_layers:
                    document = files.get(relative)
                    if isinstance(document, dict):
                        layers.append(
                            (
                                document,
                                AssetOrigin(
                                    kind="scenario" if name in private_names else "configuration",
                                    source=f"{name} · {relative}",
                                ),
                            )
                        )
                inherited_document = copy.deepcopy(default)
                authored_paths: dict[str, list[str]] = {}
                for document, origin in layers:
                    if origin.kind != "scenario":
                        inherited_document = merge(inherited_document, document)
                    else:
                        for incoming in document.get(list_name, []):
                            authored_paths.setdefault(incoming[identity], []).extend(
                                path
                                for path in leaves(incoming)
                                if path not in {identity, "_replace"}
                                and "_replace" not in path.split(".")
                            )
                inherited_runtime = {
                    entry[identity]: entry for entry in inherited_document.get(list_name, [])
                }
                for document, generic_origin in layers:
                    before = copy.deepcopy(default)
                    default = merge(default, document)
                    values = {entry[identity]: entry for entry in default.get(list_name, [])}
                    for incoming in document.get(list_name, []):
                        key = incoming[identity]
                        origin = generic_origin
                        if generic_origin.kind == "pack":
                            owner = key.split(":", 1)[0] if category == "applications" else None
                            if category == "dns":
                                owner = next(
                                    (
                                        catalog_key.split(":", 1)[0]
                                        for catalog_key, entry in compiled.effective_config.catalogs.get(
                                            "destination_catalog", {}
                                        ).items()
                                        if any(
                                            endpoint["domain"] == key
                                            for endpoint in entry["data"]["endpoints"]
                                        )
                                    ),
                                    None,
                                )
                            selected = next(
                                (
                                    pack
                                    for pack in compiled.selected_packs
                                    if f"{pack.publisher}/{pack.name}" == owner
                                ),
                                None,
                            )
                            if selected:
                                origin = AssetOrigin(
                                    kind="pack",
                                    source=f"{selected.publisher}/{selected.name}@{selected.version}",
                                )
                        previous = next(
                            (
                                entry
                                for entry in before.get(list_name, [])
                                if entry[identity] == key
                            ),
                            {},
                        )
                        old_origins = origins_by_key.get(key, {})
                        new_origins = {
                            path: old_origins.get(path, origin) for path in leaves(values[key])
                        }

                        # Mirror keyed-list overlay ownership, preserving appended list prefixes.
                        def mark(
                            old: Any,
                            new: Any,
                            prefix: str,
                            replace: bool = False,
                            marked: dict[str, AssetOrigin] = new_origins,
                            owner: AssetOrigin = origin,
                        ) -> None:
                            if isinstance(new, dict):
                                for name, child in new.items():
                                    if name != "_replace":
                                        mark(
                                            old.get(name) if isinstance(old, dict) else None,
                                            child,
                                            f"{prefix}.{name}" if prefix else name,
                                            bool(new.get("_replace")),
                                        )
                            elif isinstance(new, list) and isinstance(old, list) and not replace:
                                for index, child in enumerate(new, len(old)):
                                    for path in leaves(child, f"{prefix}.{index}"):
                                        marked[path] = owner
                            else:
                                for path in leaves(new, prefix):
                                    marked[path] = owner

                        mark(previous, incoming, "")
                        origins_by_key[key] = new_origins
                # Canonical callback output is also checked by the same provider loader.
                actual = load_with_overlay(get_config_directory() / relative, relative, merge)
                if default != actual:
                    raise ValueError("Configuration changed during inspection. Refresh the list")
                inventory.runtime_headers[relative] = {
                    name: copy.deepcopy(actual[name])
                    for name in ("schema_version", "default_deployment")
                    if name in actual
                }
                for value in actual.get(list_name, []):
                    inventory.add(category, value[identity], value, origins_by_key[value[identity]])
                    row_id = _identifier(category, value[identity])
                    if value[identity] in inherited_runtime:
                        inventory.inherited_values[row_id] = to_jsonable_python(
                            inherited_runtime[value[identity]]
                        )
                    inventory.override_fields[row_id] = authored_paths.get(value[identity], [])
                    if category == "applications":
                        for platform, definition in value.get("platforms", {}).items():
                            process_key = f"{value[identity]} · {platform}"
                            inventory.add(
                                "processes", process_key, value, origins_by_key[value[identity]]
                            )
                            inventory.rows["processes"][-1].description = str(
                                definition.get("image_path", "")
                            )
                            process_id = _identifier("processes", process_key)
                            if row_id in inventory.inherited_values:
                                inventory.inherited_values[process_id] = inventory.inherited_values[
                                    row_id
                                ]
                            inventory.override_fields[process_id] = inventory.override_fields[
                                row_id
                            ]
    _build_choices(inventory, workspace)
    if inventory_revision(source, workspace, is_pack) != revision:
        raise FileExistsError("Inputs changed during inspection. Refresh the list")
    for rows in inventory.rows.values():
        rows.sort(key=lambda row: row.key.casefold())
    return inventory


def _build_choices(inventory: Inventory, workspace: Path) -> None:
    """Collect canonical references and open vocabulary suggestions once per revision."""
    for category in ("users", "systems", "groups"):
        inventory.choice_values[category] = [row.key for row in inventory.rows.get(category, [])]
    inventory.choice_values["roles"] = sorted(known_topology_roles())
    for name in ("services", "permissions", "categories", "tags"):
        inventory.choice_values[name] = []
    inventory.choice_values["tags"] = sorted(packaged_builtin_dns_tags())
    for value in inventory.values.values():
        for path, leaf in leaves(value).items():
            parts = path.split(".")
            if (
                len(parts) > 1
                and parts[-2] in {"roles", "services", "permissions", "categories", "tags"}
                and isinstance(leaf, str)
            ):
                inventory.choice_values[parts[-2]].append(leaf)
    inventory.choice_values["application_ids"] = sorted(packaged_builtin_application_ids())
    for name in ("process_refs", "destination_refs"):
        inventory.choice_values[name] = []
    if inventory.pack:
        packs = [*PackRepository(workspace).validate_semantics(inventory.pack), inventory.pack]
        inventory.choice_values["personas"] = sorted(packaged_builtin_persona_ids())
        for pack in packs:
            for category, vocabulary in (
                ("persona_catalog", "personas"),
                ("process_catalog", "process_refs"),
                ("destination_catalog", "destination_refs"),
            ):
                inventory.choice_values[vocabulary].extend(pack.catalogs.get(category, {}))
    for name, values in inventory.choice_values.items():
        inventory.choice_values[name] = sorted(set(values), key=str.casefold)


def _safe_document(path: Path) -> dict[str, Any]:
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Asset files must not contain symbolic links")
    if not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > 8 * 1024**2:
        raise ValueError("Choose a regular YAML file smaller than 8 MiB")
    return load_yaml_text(path.read_text())


def _write_atomic(path: Path, content: bytes) -> None:
    _safe_document(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".asset-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _without_fields(value: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    if "*" in paths:
        return {}
    result = copy.deepcopy(value)
    for path in paths:
        parts = path.split(".")
        node = result
        parents: list[tuple[dict[str, Any], str]] = []
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                break
            parents.append((node, part))
            node = child
        else:
            node.pop(parts[-1], None)
            for parent, part in reversed(parents):
                if set(parent[part]) - {"_replace"}:
                    break
                del parent[part]
    return result


def _restored_value(detail: AssetDetail, edit: AssetEdit) -> dict[str, Any]:
    if not edit.restore_fields:
        return copy.deepcopy(edit.value)
    if detail.inherited_value is None:
        raise ValueError("This asset has no inherited definition to restore")
    if "*" in edit.restore_fields:
        if edit.restore_fields != ["*"]:
            raise ValueError("Restore the whole asset or individual fields, not both")
        return copy.deepcopy(detail.inherited_value)
    result = copy.deepcopy(edit.value)
    for path in edit.restore_fields:
        parts = path.split(".")
        if (
            parts[0] == detail.identity_field
            or parts[0] not in detail.schema_document.get("properties", {})
            or len(path) > 300
            or any(not part for part in parts)
        ):
            raise ValueError("Choose an editable field to restore")
        inherited: Any = detail.inherited_value
        current: Any = detail.value
        target = result
        for part in parts[:-1]:
            inherited = inherited.get(part, {}) if isinstance(inherited, dict) else None
            current = current.get(part, {}) if isinstance(current, dict) else None
            if not isinstance(inherited, dict) or not isinstance(current, dict):
                raise ValueError("Restore the containing list or field instead")
            if not isinstance(target.get(part), dict):
                target[part] = {}
            target = target[part]
        if parts[-1] in inherited:
            target[parts[-1]] = copy.deepcopy(inherited[parts[-1]])
        else:
            target.pop(parts[-1], None)
    return result


def save_asset(source: Path, workspace: Path, inventory: Inventory, edit: AssetEdit) -> AssetSaved:
    """Validate on staged inputs, then publish scenario files or a new pack version."""
    from evidenceforge.artifacts.lifecycle import assert_mutable

    assert_mutable(source)
    is_pack = inventory.pack is not None
    if (
        edit.revision != inventory.revision
        or inventory_revision(source, workspace, is_pack) != edit.revision
    ):
        raise FileExistsError(
            "Inputs changed since you opened this asset. Refresh and review again"
        )
    converting = edit.convert_from is not None
    if edit.preview and not converting:
        raise ValueError("Preflight preview is available for account conversions only")
    if converting:
        if is_pack or not edit.asset_id or edit.restore_fields:
            raise ValueError("Convert an existing account in its scenario workspace")
        detail = inventory.detail(edit.convert_from, edit.asset_id)
        if detail.category != edit.convert_from:
            raise ValueError("Account kind changed. Refresh and review again")
        expected = "stale_accounts" if detail.category == "users" else "users"
        if edit.category != expected:
            raise ValueError("Choose the opposite account kind for conversion")
        if edit.key.casefold() != detail.summary.key.casefold():
            raise ValueError("Conversion must keep the same username")
    else:
        detail = inventory.detail(edit.category, edit.asset_id)
    _label, model, identity = inventory.models[edit.category if converting else detail.category]
    value = copy.deepcopy(edit.value) if converting else _restored_value(detail, edit)
    if identity != "key":
        if edit.asset_id:
            if value.get(identity) != detail.value.get(identity):
                raise ValueError("An existing asset's identity cannot be changed; add a new asset")
        else:
            value[identity] = edit.key
    elif detail.summary and edit.key != detail.summary.key:
        raise ValueError("An existing catalog key cannot be changed; add a new asset")
    elif not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", edit.key):
        raise ValueError(
            "Use a lowercase catalog key containing letters, digits, underscores or hyphens"
        )
    model.model_validate(value)
    key = detail.summary.key if detail.summary else edit.key
    if not edit.asset_id and any(
        str(
            inventory.values[row.id].get(identity, row.key)
            if edit.category == "processes"
            else row.key
        ).casefold()
        == key.casefold()
        for row in inventory.rows.get(edit.category, [])
    ):
        raise ValueError("That asset already exists. Open it to edit its values")
    if not converting and edit.asset_id and value == detail.value and not edit.restore_fields:
        raise ValueError("No values changed")
    if is_pack:
        assert inventory.pack is not None
        pack = inventory.pack
        version = edit.version or detail.next_version
        if pack.manifest.status != "draft" and (
            version is None
            or tuple(map(int, version.split(".")))
            <= tuple(map(int, pack.manifest.version.split(".")))
        ):
            raise ValueError("Choose a version greater than the original pack version")
        if edit.category in ENVIRONMENT_MODELS:
            graph = load_scenario_source_graph(
                pack.root / "model/environment.yaml", allowed_root=pack.root
            )
            prefix = ("environment", edit.category)
        else:
            relative = next(path for name, path, _model in CATALOG_FILES if name == edit.category)
            graph = load_scenario_source_graph(pack.root / relative, allowed_root=pack.root)
            prefix = (edit.category, key)
        target = _raw_owner(graph.origins, prefix, graph.root)
        document = _safe_document(target)
        if edit.category in ENVIRONMENT_MODELS:
            entries = document.setdefault("environment", {}).setdefault(edit.category, [])
            index = next(
                (
                    index
                    for index, entry in enumerate(entries)
                    if str(entry[identity]).casefold() == key.casefold()
                ),
                None,
            )
            if index is None:
                entries.append(value)
            else:
                entries[index] = value
        else:
            document.setdefault(edit.category, {})[key] = value
        if pack.manifest.status == "draft":
            from evidenceforge.artifacts.lifecycle import _write_files

            staged = Path(tempfile.mkdtemp(prefix=".asset-", dir=pack.root.parent)).resolve()
            content = yaml.safe_dump(document, sort_keys=False).encode()
            relative = target.relative_to(pack.root).as_posix()
            try:
                files = dict((*pack.semantic_file_bytes, *pack.companion_file_bytes))
                files[relative] = content
                _write_files(staged, files)
                reference, kind = parse_pack_cli_reference(str(staged))
                repository = PackRepository(workspace)
                repository.validate_semantics(repository.resolve(reference, expected_type=kind))
                if inventory_revision(source, workspace, True) != edit.revision:
                    raise FileExistsError("Draft changed during validation; refresh and review")
                _write_atomic(target, content)
            finally:
                shutil.rmtree(staged)
            return AssetSaved(path=source)
        path = PackRepository(workspace).copy(
            pack,
            name=pack.manifest.name,
            version=version,
            publisher=pack.manifest.publisher,
            publisher_display_name=pack.manifest.publisher_display_name,
            updates={
                target.relative_to(pack.root).as_posix(): yaml.safe_dump(
                    document, sort_keys=False
                ).encode()
            },
        )
        return AssetSaved(path=path / "pack.yaml", version=version)
    graph = load_scenario_source_graph(source)
    changes: dict[Path, bytes] = {}
    context_target = scenario_context_path(source, workspace)
    _safe_document(context_target)
    context_before = context_target.read_bytes() if context_target.exists() else None
    config_edit = edit.category in RUNTIME_MODELS
    if converting:
        # Keep source records/links intact: the portable transition suppresses their
        # effective participation and makes a later restoration possible.
        transition_index = next(
            (
                index
                for index, item in enumerate(graph.data.get("account_transitions", []))
                if item["username"].casefold() == key.casefold()
            ),
            None,
        )
        target = (
            _raw_owner(graph.origins, ("account_transitions", str(transition_index)), source)
            if transition_index is not None
            else source
        )
        document = _safe_document(target)
        target_before = target.read_bytes() if target.exists() else None
        records = document.setdefault("account_transitions", [])
        previous = next(
            (
                record
                for record in account_transitions(graph.data)
                if record.username.casefold() == key.casefold()
            ),
            None,
        )
        records[:] = [
            record for record in records if record["username"].casefold() != key.casefold()
        ]
        record = AccountTransition(
            username=key,
            target=edit.category,
            previous_user=User.model_validate(detail.value)
            if detail.category == "users"
            else previous.previous_user
            if previous
            else None,
        )
        records.append(record.model_dump(mode="json", exclude_none=True))
        changes[target] = yaml.safe_dump(document, sort_keys=False).encode()
        destination_index = next(
            (
                index
                for index, item in enumerate(
                    (graph.data.get("environment") or {}).get(edit.category, [])
                )
                if item["username"].casefold() == key.casefold()
            ),
            None,
        )
        destination = (
            _raw_owner(
                graph.origins, ("environment", edit.category, str(destination_index)), source
            )
            if destination_index is not None
            else source
        )
        destination_document = document if destination == target else _safe_document(destination)
        entries = destination_document.setdefault("environment", {}).setdefault(edit.category, [])
        index = next(
            (
                index
                for index, entry in enumerate(entries)
                if entry["username"].casefold() == key.casefold()
            ),
            None,
        )
        previous_value = inventory.conversion_previous_values.get(edit.asset_id)
        if previous_value is not None:
            from evidenceforge.composition.compiler import _merge_registered

            desired = model.model_validate(value).model_dump(mode="json")
            patch = {
                name: child for name, child in desired.items() if previous_value.get(name) != child
            }
            stored = _merge_registered(
                entries[index] if index is not None else {}, {**patch, identity: key}
            )
        else:
            stored = value
        if index is None:
            entries.append(stored)
        else:
            entries[index] = stored
        changes[destination] = yaml.safe_dump(destination_document, sort_keys=False).encode()
    elif config_edit:
        relative, list_name, merge = RUNTIME_FILES[edit.category]
        target = scenario_overlay_root(source, workspace) / relative
        document = _safe_document(target)
        target_before = target.read_bytes() if target.exists() else None
        headers = inventory.runtime_headers.get(relative, {})
        for name, header in headers.items():
            document.setdefault(name, copy.deepcopy(header))
        runtime_key = value[identity]
        entries = document.setdefault(list_name, [])
        entries[:] = [entry for entry in entries if entry[identity] != runtime_key]
        old = detail.value if detail.summary else {}

        def patch(previous: Any, desired: Any) -> Any:
            if isinstance(previous, dict) and isinstance(desired, dict):
                return {
                    name: patch(previous.get(name), child)
                    for name, child in desired.items()
                    if previous.get(name) != child
                }
            if isinstance(previous, list) and isinstance(desired, list):
                if desired[: len(previous)] != previous:
                    raise ValueError(
                        "Nested lists support appended values only. Use a pack revision for removals or reordering"
                    )
                return desired[len(previous) :]
            return desired

        entry = {identity: runtime_key, "_replace": True}
        for name, desired in _without_fields(value, edit.restore_fields).items():
            if old.get(name) != desired:
                entry[name] = (
                    patch(old.get(name), desired) if isinstance(desired, dict) else desired
                )
        existing = next(
            (
                item
                for item in _safe_document(target).get(list_name, [])
                if item[identity] == runtime_key
            ),
            {},
        )
        existing = _without_fields(existing, edit.restore_fields)
        # Merge author patches with the same family callback used at runtime.
        if existing:
            entry = merge({**headers, list_name: [existing]}, {**headers, list_name: [entry]})[
                list_name
            ][0]
            entry["_replace"] = True
        entry = _without_fields(entry, edit.restore_fields)
        if set(entry) - {identity, "_replace"}:
            entries.append(entry)
        changes[target] = yaml.safe_dump(document, sort_keys=False).encode()
    else:
        prefix = ("environment", edit.category)
        target = _raw_owner(graph.origins, prefix, source)
        document = _safe_document(target)
        target_before = target.read_bytes() if target.exists() else None
        entries = document.setdefault("environment", {}).setdefault(edit.category, [])
        index = next(
            (
                index
                for index, entry in enumerate(entries)
                if str(entry[identity]).casefold() == key.casefold()
            ),
            None,
        )
        if edit.asset_id:
            from evidenceforge.composition.compiler import _merge_registered

            def delta(previous: Any, desired: Any) -> Any:
                if isinstance(previous, dict) and isinstance(desired, dict):
                    return {
                        name: delta(previous.get(name), child)
                        for name, child in desired.items()
                        if previous.get(name) != child
                    }
                return desired

            patch_value = {
                **_without_fields(delta(detail.value, value), edit.restore_fields),
                identity: value[identity],
            }
            existing = entries[index] if index is not None else {}
            existing = _without_fields(existing, edit.restore_fields)
            stored = _merge_registered(existing, patch_value)
        else:
            stored = value
        if detail.inherited_value is not None and set(stored) == {identity}:
            if index is not None:
                entries.pop(index)
        elif index is None:
            entries.append(stored)
        else:
            entries[index] = stored
        changes[target] = yaml.safe_dump(document, sort_keys=False).encode()
    # Validate the actual authoring merge in a temporary source graph, preserving includes.
    selection = select_context(workspace, context_path(source, workspace))
    with tempfile.TemporaryDirectory(prefix="studio-asset-") as directory:
        stage = Path(directory).resolve()
        locations = {
            entry.path: stage / f"source-{index}.yaml" for index, entry in enumerate(graph.sources)
        }
        for captured in graph.sources:
            data = load_yaml_text(changes.get(captured.path, captured.content).decode())
            for include_key in ("include", "includes"):
                if include_key in data:
                    original = data[include_key]
                    names = [original] if isinstance(original, str) else original
                    rewritten = [
                        str(locations[Path(os.path.abspath(captured.path.parent / name))])
                        for name in names
                    ]
                    data[include_key] = rewritten[0] if isinstance(original, str) else rewritten
            composition = data.get("composition") or {}
            for reference in [
                *(composition.get("industries") or []),
                *([composition["organization"]] if composition.get("organization") else []),
            ]:
                if reference.get("source") == "path":
                    reference["path"] = str((captured.path.parent / reference["path"]).absolute())
            email = (data.get("environment") or {}).get("email") or {}
            if email.get("corpus") and not email["corpus"].startswith("embedded:"):
                from evidenceforge.utils.paths import read_text_file_beneath

                corpus = read_text_file_beneath(
                    captured.path.parent,
                    email["corpus"],
                    max_bytes=8 * 1024**2,
                    label="email corpus",
                )
                name = f"corpus-{captured.sha256}.yaml"
                (stage / name).write_text(corpus)
                email["corpus"] = name
            locations[captured.path].write_text(yaml.safe_dump(data, sort_keys=False))
        layers = list(selection.overlays)
        if config_edit:
            private = scenario_overlay_root(source, workspace)
            private_stage = stage / "configuration"
            private_stage.mkdir()
            if private.exists():
                for file in private.rglob("*.yaml"):
                    content = _safe_document(file)
                    output = private_stage / file.relative_to(private)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(yaml.safe_dump(content, sort_keys=False))
            output = private_stage / target.relative_to(private)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(changes[target])
            layers = [
                layer.model_copy(update={"path": private_stage}) if layer.path == private else layer
                for layer in layers
            ]
            if not any(layer.path == private_stage for layer in layers):
                layers.append(OverlayReference(name="Scenario", path=private_stage))
            final_layers = [
                layer.model_copy(update={"path": private}) if layer.path == private_stage else layer
                for layer in layers
            ]
            context = ConfigurationContext(
                project_root=selection.project_root, overlays=final_layers
            )
            changes[scenario_context_path(source, workspace)] = yaml.safe_dump(
                context.model_dump(mode="json"), sort_keys=False
            ).encode()
        staged_context = stage / "context.yaml"
        staged_context.write_text(
            yaml.safe_dump(
                ConfigurationContext(
                    project_root=selection.project_root, overlays=layers
                ).model_dump(mode="json"),
                sort_keys=False,
            )
        )
        try:
            compiled = compile_scenario(locations[source], context=staged_context)
        except SchemaValidationError as exc:
            if not edit.preview:
                raise
            return AssetSaved(
                path=target,
                validation_errors=[str(exc)],
                effects=inventory.conversion_effects.get(edit.asset_id, []) if converting else [],
            )
        from evidenceforge.cli.commands import _validate_compiled_scenario

        validator, issues = _validate_compiled_scenario(compiled, (), source.parent)
        errors = [
            f"{issue.field_path}: {issue.message}" for issue in issues if issue.severity == "error"
        ]
        if validator.has_errors() and not edit.preview:
            raise ValueError("; ".join(errors))
        if not config_edit and (edit.restore_fields or converting):
            actual_entities = compiled.scenario.model_dump(mode="json")["environment"]
            actual = next(
                (
                    entry
                    for entry in actual_entities.get(edit.category, [])
                    if str(entry[identity]).casefold() == key.casefold()
                ),
                None,
            )
            if actual != model.model_validate(value).model_dump(mode="json"):
                raise ValueError("Reviewed values no longer match effective inputs. Refresh assets")
        if config_edit:
            from evidenceforge.config.overlay import overlay_project_root_scope
            from evidenceforge.validation.configuration import validate_config

            with overlay_project_root_scope(
                selection.project_root, tuple(layer.path for layer in layers)
            ):
                checked = validate_config(
                    merged_scope_factory=lambda: effective_config_scope(
                        compiled.effective_config, refresh_legacy_globals=False
                    )
                )
            if checked.errors:
                raise ValueError(
                    "; ".join(f"{issue.file}: {issue.message}" for issue in checked.errors)
                )
            with effective_config_scope(compiled.effective_config, refresh_legacy_globals=False):
                actual = load_with_overlay(get_config_directory() / relative, relative, merge)
                result = next(
                    (entry for entry in actual[list_name] if entry[identity] == value[identity]),
                    None,
                )
                if to_jsonable_python(result) != value:
                    raise ValueError(
                        "This edit cannot be represented by the configuration merge contract. Use a pack revision"
                    )
    if edit.preview:
        return AssetSaved(
            path=target,
            validation_errors=errors,
            effects=inventory.conversion_effects.get(edit.asset_id, []) if converting else [],
        )
    if inventory_revision(source, workspace, False) != edit.revision:
        raise FileExistsError("Inputs changed during validation. Refresh and review again")
    if (target.read_bytes() if target.exists() else None) != target_before or (
        config_edit
        and (context_target.read_bytes() if context_target.exists() else None) != context_before
    ):
        raise FileExistsError("An edited file changed during validation. Refresh and review again")
    originals = {path: path.read_bytes() if path.exists() else None for path in changes}
    published: list[Path] = []
    try:
        for path, content in changes.items():
            published.append(path)
            _write_atomic(path, content)
    except (OSError, ValueError):
        for path in reversed(published):
            if originals[path] is None:
                path.unlink(missing_ok=True)
            else:
                _write_atomic(path, originals[path])
        raise
    return AssetSaved(path=target)
