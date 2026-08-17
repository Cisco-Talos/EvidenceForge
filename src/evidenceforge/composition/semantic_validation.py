# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Whole-pack semantic validation for runtime-effective composition catalogs."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Protocol

import yaml
from pydantic import ValidationError

from evidenceforge.config import get_activity_directory, get_personas_directory
from evidenceforge.config.schemas import ApplicationCatalogConfig, ApplicationEntry
from evidenceforge.models.exceptions import PackError
from evidenceforge.models.scenario import Persona
from evidenceforge.utils.yaml_loader import load_yaml_text

from .models import (
    ApplicationCatalogEntry,
    BaselineActivityFragment,
    DestinationCatalogEntry,
    EnvironmentFragment,
    PackManifest,
    PackSource,
    ProcessCatalogEntry,
    StorageCatalogEntry,
    TrafficCatalogEntry,
)


class SelectedPackForValidation(Protocol):
    """Structural interface accepted from the repository/compiler pack result."""

    manifest: PackManifest
    source: PackSource
    catalogs: Mapping[str, Mapping[str, Any]]
    environment: Mapping[str, Any]
    baseline_activity: Mapping[str, Any]


def _packaged_yaml_mapping(filename: str) -> dict[str, Any]:
    """Read one packaged YAML mapping without ambient provider/project overlays."""

    path = get_activity_directory() / filename
    try:
        document = load_yaml_text(path.read_text(encoding="utf-8"), source=str(path))
    except (OSError, yaml.YAMLError) as exc:
        raise PackError(f"cannot load packaged validation registry {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise PackError(f"packaged validation registry must be a mapping: {path}")
    return document


def _packaged_builtin_applications() -> list[ApplicationEntry]:
    """Return validated application entries from immutable packaged defaults."""

    document = _packaged_yaml_mapping("application_catalog.yaml")
    try:
        catalog = ApplicationCatalogConfig.model_validate(document)
    except ValidationError as exc:
        raise PackError(f"invalid packaged application catalog: {exc}") from exc
    identifiers: set[str] = set()
    for entry in catalog.applications:
        if entry.id in identifiers:
            raise PackError(f"packaged application catalog contains duplicate ID {entry.id!r}")
        identifiers.add(entry.id)
    return catalog.applications


def packaged_builtin_application_ids() -> set[str]:
    """Return validated stable application IDs from packaged defaults only."""

    return {entry.id for entry in _packaged_builtin_applications()}


def _command_executable(command: str) -> str:
    """Return the executable token from one packaged or custom child command."""

    stripped = command.strip()
    if not stripped:
        return ""
    if stripped[0] in {'"', "'"}:
        closing_quote = stripped.find(stripped[0], 1)
        if closing_quote > 1:
            return stripped[1:closing_quote]
    return stripped.split(maxsplit=1)[0]


def packaged_builtin_executable_claims() -> set[str]:
    """Return immutable OS/path/basename claims owned by packaged applications."""

    claims: set[str] = set()
    for entry in _packaged_builtin_applications():
        for os_name, platform in entry.platforms.items():
            if os_name not in {"windows", "linux"}:
                continue
            claims.update(_executable_claims(os_name, platform.image_path))
            for child in platform.children or []:
                executable = _command_executable(child)
                if executable:
                    claims.update(_executable_claims(os_name, executable))
    return claims


def packaged_builtin_dns_tags() -> set[str]:
    """Return runtime DNS-selection tags from packaged defaults only."""

    document = _packaged_yaml_mapping("dns_registry.yaml")
    valid_tags = document.get("valid_tags")
    if isinstance(valid_tags, dict):
        return {str(tag) for tag, description in valid_tags.items() if isinstance(description, str)}
    domains = document.get("domains")
    if not isinstance(domains, list):
        raise PackError("packaged DNS registry must define valid_tags or domains")
    return {
        str(tag) for domain in domains if isinstance(domain, dict) for tag in domain.get("tags", [])
    }


def packaged_builtin_dns_domains() -> set[str]:
    """Return exact normalized domains owned by the packaged DNS registry."""

    document = _packaged_yaml_mapping("dns_registry.yaml")
    domains = document.get("domains")
    if not isinstance(domains, list):
        raise PackError("packaged DNS registry must define a domains list")
    result: set[str] = set()
    for index, raw_entry in enumerate(domains):
        if not isinstance(raw_entry, dict) or not isinstance(raw_entry.get("domain"), str):
            raise PackError(f"packaged DNS registry domains[{index}] must define a string domain")
        domain = raw_entry["domain"].strip().lower().rstrip(".")
        if not domain:
            raise PackError(f"packaged DNS registry domains[{index}] has an empty domain")
        if domain in result:
            raise PackError(f"packaged DNS registry contains duplicate domain {domain!r}")
        result.add(domain)
    return result


def packaged_builtin_persona_ids() -> set[str]:
    """Return validated stable persona IDs from packaged defaults only."""

    directory = get_personas_directory()
    result: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            raw_entry = load_yaml_text(path.read_text(encoding="utf-8"), source=str(path))
        except (OSError, yaml.YAMLError) as exc:
            raise PackError(f"cannot load packaged validation registry {path}: {exc}") from exc
        try:
            entry = Persona.model_validate(raw_entry)
        except ValidationError as exc:
            raise PackError(f"invalid packaged persona {path}: {exc}") from exc
        if entry.name != path.stem:
            raise PackError(
                f"packaged persona {path} declares name {entry.name!r}; expected {path.stem!r}"
            )
        if entry.name in result:
            raise PackError(f"packaged persona registry contains duplicate ID {entry.name!r}")
        result.add(entry.name)
    return result


def packaged_builtin_storage_preset_ids() -> set[str]:
    """Return validated stable storage preset IDs from packaged defaults only."""

    document = _packaged_yaml_mapping("storage_catalog.yaml")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict):
        raise PackError("packaged storage catalog must define a profiles mapping")
    result: set[str] = set()
    for raw_identity, raw_profile in profiles.items():
        if not isinstance(raw_identity, str) or not raw_identity.strip():
            raise PackError("packaged storage catalog profile IDs must be non-empty strings")
        if not isinstance(raw_profile, dict):
            raise PackError(f"packaged storage catalog profile {raw_identity!r} must be a mapping")
        result.add(raw_identity)
    return result


def _pack_label(pack: SelectedPackForValidation) -> str:
    """Return a portable identity for actionable diagnostics."""

    manifest = pack.manifest
    return f"{manifest.type} pack {manifest.name}@{manifest.version} ({pack.source})"


def _qualified_export(owner: str, identity: str, *, context: str) -> str:
    """Normalize one local export key and reject namespace impersonation."""

    if ":" not in identity:
        return f"{owner}:{identity}"
    qualifier, _local_id = identity.split(":", 1)
    if qualifier != owner:
        raise PackError(f"{context} exports identity in another pack namespace: {identity!r}")
    return identity


def _allowed_qualifiers(pack: SelectedPackForValidation) -> set[str]:
    """Return namespaces the pack may reference under its dependency contract."""

    manifest = pack.manifest
    if manifest.type == "industry":
        return {manifest.name}
    dependency_names = [dependency.name for dependency in manifest.industry_dependencies]
    if len(dependency_names) != len(set(dependency_names)):
        raise PackError(
            f"{_pack_label(pack)} declares multiple versions/sources for one industry name; "
            "qualified references cannot disambiguate them"
        )
    return {manifest.name, *dependency_names}


def _qualified_reference(
    reference: str,
    *,
    pack: SelectedPackForValidation,
    context: str,
) -> str:
    """Normalize a local reference and enforce pack dependency ownership."""

    if ":" in reference:
        qualifier, local_id = reference.split(":", 1)
    else:
        qualifier, local_id = pack.manifest.name, reference
    if qualifier not in _allowed_qualifiers(pack):
        allowed = ", ".join(sorted(_allowed_qualifiers(pack)))
        raise PackError(
            f"{context} references undeclared pack namespace {qualifier!r}; allowed: {allowed}"
        )
    return f"{qualifier}:{local_id}"


def _validated_entries(
    pack: SelectedPackForValidation,
    catalog_name: str,
    model: type[Persona]
    | type[ProcessCatalogEntry]
    | type[ApplicationCatalogEntry]
    | type[DestinationCatalogEntry]
    | type[TrafficCatalogEntry]
    | type[StorageCatalogEntry],
) -> dict[str, Any]:
    """Revalidate and normalize a loaded pack catalog for semantic traversal."""

    entries = pack.catalogs.get(catalog_name, {})
    result: dict[str, Any] = {}
    for identity, raw_entry in entries.items():
        context = f"{_pack_label(pack)} {catalog_name}.{identity}"
        qualified = _qualified_export(pack.manifest.name, identity, context=context)
        try:
            entry = model.model_validate(raw_entry)
        except ValidationError as exc:
            raise PackError(f"{context} is invalid: {exc}") from exc
        if qualified in result:
            raise PackError(f"{context} duplicates exported identity {qualified!r}")
        result[qualified] = entry
    return result


def _validate_dependency_selection(packs: Sequence[SelectedPackForValidation]) -> None:
    """Ensure organization dependencies are present with exact selected identities."""

    namespace_owners: dict[str, tuple[PackSource, str, str]] = {}
    for pack in packs:
        manifest = pack.manifest
        identity = (pack.source, manifest.type, manifest.version)
        existing = namespace_owners.get(manifest.name)
        if existing is not None:
            existing_source, existing_type, existing_version = existing
            raise PackError(
                f"selected packs share namespace {manifest.name!r} but have different exact "
                "identities: "
                f"{existing_source}:{existing_type}:{manifest.name}@{existing_version} and "
                f"{pack.source}:{manifest.type}:{manifest.name}@{manifest.version}"
            )
        namespace_owners[manifest.name] = identity

    selected = {
        (pack.source, pack.manifest.type, pack.manifest.name, pack.manifest.version)
        for pack in packs
    }
    organizations = [pack for pack in packs if pack.manifest.type == "organization"]
    if len(organizations) > 1:
        names = ", ".join(pack.manifest.name for pack in organizations)
        raise PackError(f"selected composition contains multiple organization packs: {names}")
    for organization in organizations:
        for dependency in organization.manifest.industry_dependencies:
            identity = (
                dependency.source,
                "industry",
                dependency.name,
                dependency.version,
            )
            if identity not in selected:
                raise PackError(
                    f"{_pack_label(organization)} requires exact industry dependency "
                    f"{dependency.source}:{dependency.name}@{dependency.version}, but it was "
                    "not selected"
                )


def _require_reference(
    reference: str,
    targets: Mapping[str, Any],
    *,
    pack: SelectedPackForValidation,
    context: str,
) -> str:
    """Resolve one reference or raise a provenance-rich pack diagnostic."""

    qualified = _qualified_reference(reference, pack=pack, context=context)
    if qualified not in targets:
        raise PackError(f"{context} references missing export {qualified!r}")
    return qualified


def _require_organization_model_reference(
    reference: str,
    targets: Mapping[str, Any],
    builtin_ids: Collection[str],
    *,
    pack: SelectedPackForValidation,
    context: str,
) -> str:
    """Resolve an organization-local export or packaged built-in shorthand."""

    if ":" not in reference:
        local_reference = f"{pack.manifest.name}:{reference}"
        if local_reference in targets:
            return local_reference
        if reference in builtin_ids:
            return reference
    return _require_reference(reference, targets, pack=pack, context=context)


def _executable_claims(os_name: str, image_path: str) -> set[str]:
    """Return runtime path and basename identities for an executable claim."""

    if os_name == "windows":
        path = str(PureWindowsPath(image_path)).lower()
        basename = PureWindowsPath(path).name
    else:
        path = str(PurePosixPath(image_path))
        basename = PurePosixPath(path).name
    claims = {f"{os_name}:basename:{basename.lower()}"}
    if any(separator in image_path for separator in ("/", "\\")):
        claims.add(f"{os_name}:path:{path}")
    return claims


def validate_selected_pack_semantics(
    packs: Sequence[SelectedPackForValidation],
    *,
    builtin_application_ids: Collection[str],
    builtin_dns_tags: Collection[str],
    builtin_executable_claims: Collection[str],
    builtin_dns_domains: Collection[str],
    builtin_persona_ids: Collection[str],
    builtin_storage_preset_ids: Collection[str],
) -> None:
    """Validate cross-catalog references and collisions for one selected composition.

    Args:
        packs: Resolved industry dependencies and optional organization pack.
        builtin_application_ids: Stable IDs from the packaged application catalog.
        builtin_dns_tags: DNS-selection tags from the packaged DNS registry.
        builtin_executable_claims: Immutable executable identities owned by packaged apps.
        builtin_dns_domains: Immutable exact domains owned by the packaged DNS registry.
        builtin_persona_ids: Stable IDs from the packaged persona registry.
        builtin_storage_preset_ids: Stable IDs from the packaged storage preset registry.

    Raises:
        PackError: A selected pack is semantically incomplete, ambiguous, or violates
            its declared dependency boundary.
    """

    _validate_dependency_selection(packs)
    builtin_ids = set(builtin_application_ids)
    builtin_tags = set(builtin_dns_tags)
    builtin_executables = {str(claim).lower() for claim in builtin_executable_claims}
    builtin_domains = {str(domain).lower().rstrip(".") for domain in builtin_dns_domains}
    builtin_personas = set(builtin_persona_ids)
    builtin_storage_presets = set(builtin_storage_preset_ids)

    by_pack: dict[
        int,
        dict[str, dict[str, Any]],
    ] = {}
    global_catalogs: dict[str, dict[str, Any]] = {
        "persona_catalog": {},
        "process_catalog": {},
        "application_catalog": {},
        "destination_catalog": {},
        "traffic_catalog": {},
        "storage_catalog": {},
    }
    models = {
        "persona_catalog": Persona,
        "process_catalog": ProcessCatalogEntry,
        "application_catalog": ApplicationCatalogEntry,
        "destination_catalog": DestinationCatalogEntry,
        "traffic_catalog": TrafficCatalogEntry,
        "storage_catalog": StorageCatalogEntry,
    }
    for pack in packs:
        pack_catalogs: dict[str, dict[str, Any]] = {}
        for catalog_name, model in models.items():
            entries = _validated_entries(pack, catalog_name, model)
            collisions = sorted(set(entries) & set(global_catalogs[catalog_name]))
            if collisions:
                raise PackError(
                    f"{_pack_label(pack)} collides with another selected pack in "
                    f"{catalog_name}: {', '.join(collisions)}"
                )
            global_catalogs[catalog_name].update(entries)
            pack_catalogs[catalog_name] = entries
        by_pack[id(pack)] = pack_catalogs

    endpoint_owners: dict[str, str] = {}
    executable_owners: dict[str, str] = {}
    custom_process_owners: dict[str, str] = {}
    destination_tags: dict[str, set[str]] = {}
    for pack in packs:
        catalogs = by_pack[id(pack)]
        for identity, process_entry in catalogs["process_catalog"].items():
            context = f"{_pack_label(pack)} process_catalog.{identity}"
            unknown_builtins = sorted(set(process_entry.data.builtins) - builtin_ids)
            if unknown_builtins:
                raise PackError(
                    f"{context} references unknown builtin application ID(s): "
                    + ", ".join(unknown_builtins)
                )
            for custom in process_entry.data.custom:
                runtime_id = f"{pack.manifest.name}:{custom.id}"
                existing_custom = custom_process_owners.get(runtime_id)
                if existing_custom is not None:
                    raise PackError(
                        f"{context} duplicates custom process ID {runtime_id!r}; "
                        f"already owned by {existing_custom}"
                    )
                custom_process_owners[runtime_id] = identity
                for os_name, platform in custom.platforms.items():
                    owner = f"{identity}.data.custom.{custom.id}.platforms.{os_name}"
                    executable_paths = [
                        platform.image_path,
                        *(_command_executable(child) for child in platform.children),
                    ]
                    for executable_path in executable_paths:
                        for claim in _executable_claims(os_name, executable_path):
                            if claim in builtin_executables:
                                raise PackError(
                                    f"{context} collides with packaged builtin executable "
                                    f"claim {claim!r}"
                                )
                            existing = executable_owners.get(claim)
                            if existing is not None and existing != owner:
                                raise PackError(
                                    f"{context} duplicates executable claim {claim!r}; "
                                    f"already owned by {existing}"
                                )
                            executable_owners[claim] = owner

        for identity, destination_entry in catalogs["destination_catalog"].items():
            context = f"{_pack_label(pack)} destination_catalog.{identity}"
            for tag in destination_entry.data.tags:
                qualified_tag = _qualified_export(
                    pack.manifest.name,
                    tag,
                    context=f"{context}.data.tags",
                )
                destination_tags.setdefault(qualified_tag, set()).add(identity)
            for endpoint in destination_entry.data.endpoints:
                if endpoint.domain in builtin_domains:
                    raise PackError(
                        f"{context} collides with packaged DNS domain {endpoint.domain!r}"
                    )
                existing = endpoint_owners.get(endpoint.domain)
                if existing is not None:
                    raise PackError(
                        f"{context} duplicates endpoint domain {endpoint.domain!r}; "
                        f"already owned by {existing}"
                    )
                endpoint_owners[endpoint.domain] = identity

    application_connections: dict[str, set[str]] = {}
    application_connection_targets: dict[tuple[str, str], str] = {}
    application_personas: dict[str, set[str]] = {}
    referenced_processes: set[str] = set()
    referenced_destinations: set[str] = set()
    for pack in packs:
        catalogs = by_pack[id(pack)]
        for identity, application_entry in catalogs["application_catalog"].items():
            context = f"{_pack_label(pack)} application_catalog.{identity}.data"
            resolved_personas = {
                _require_reference(
                    reference,
                    global_catalogs["persona_catalog"],
                    pack=pack,
                    context=f"{context}.personas",
                )
                for reference in application_entry.data.personas
            }
            for reference in application_entry.data.processes:
                referenced_processes.add(
                    _require_reference(
                        reference,
                        global_catalogs["process_catalog"],
                        pack=pack,
                        context=f"{context}.processes",
                    )
                )
            connection_names: set[str] = set()
            for connection_name, connection in application_entry.data.connections.items():
                destination_ref = _require_reference(
                    connection.destination,
                    global_catalogs["destination_catalog"],
                    pack=pack,
                    context=f"{context}.connections.{connection_name}.destination",
                )
                destination = global_catalogs["destination_catalog"][destination_ref]
                if connection.service not in destination.data.services:
                    raise PackError(
                        f"{context}.connections.{connection_name}.service references missing "
                        f"service {connection.service!r} on destination {destination_ref!r}"
                    )
                connection_names.add(connection_name)
                application_connection_targets[(identity, connection_name)] = destination_ref
            application_connections[identity] = connection_names
            application_personas[identity] = resolved_personas

    orphan_processes = sorted(set(global_catalogs["process_catalog"]) - referenced_processes)
    if orphan_processes:
        raise PackError(
            "selected composition contains orphan process profile(s) not referenced by any "
            "application: " + ", ".join(orphan_processes)
        )

    referenced_application_connections: set[tuple[str, str]] = set()
    for pack in packs:
        catalogs = by_pack[id(pack)]
        for identity, traffic_entry in catalogs["traffic_catalog"].items():
            context = f"{_pack_label(pack)} traffic_catalog.{identity}.data"
            audience = {
                _require_reference(
                    reference,
                    global_catalogs["persona_catalog"],
                    pack=pack,
                    context=f"{context}.audience",
                )
                for reference in traffic_entry.data.audience
            }
            for binding in traffic_entry.data.applications:
                application_ref = _require_reference(
                    binding.application,
                    global_catalogs["application_catalog"],
                    pack=pack,
                    context=f"{context}.applications.application",
                )
                if binding.connection not in application_connections[application_ref]:
                    raise PackError(
                        f"{context}.applications references missing connection "
                        f"{binding.connection!r} on application {application_ref!r}"
                    )
                connection_key = (application_ref, binding.connection)
                referenced_application_connections.add(connection_key)
                referenced_destinations.add(application_connection_targets[connection_key])
                disallowed = sorted(audience - application_personas[application_ref])
                if disallowed:
                    raise PackError(
                        f"{context}.applications uses {application_ref!r} for persona(s) not "
                        f"allowed by that application: {', '.join(disallowed)}"
                    )
            for outbound_index, connection in enumerate(traffic_entry.data.outbound):
                for tag_index, tag in enumerate(connection.dns_tags):
                    tag_context = f"{context}.outbound[{outbound_index}].dns_tags[{tag_index}]"
                    if ":" in tag:
                        qualified_tag = _qualified_reference(
                            tag,
                            pack=pack,
                            context=tag_context,
                        )
                        if qualified_tag not in destination_tags:
                            raise PackError(
                                f"{tag_context} references missing custom DNS tag {qualified_tag!r}"
                            )
                        referenced_destinations.update(destination_tags[qualified_tag])
                        continue
                    local_tag = f"{pack.manifest.name}:{tag}"
                    if local_tag in destination_tags:
                        referenced_destinations.update(destination_tags[local_tag])
                    elif tag not in builtin_tags:
                        raise PackError(
                            f"{tag_context} references unknown built-in or visible custom "
                            f"DNS tag {tag!r}"
                        )

        if pack.manifest.type == "industry":
            if pack.environment or pack.baseline_activity:
                raise PackError(f"{_pack_label(pack)} cannot define organization model fragments")
            continue

        try:
            EnvironmentFragment(environment=dict(pack.environment))
            BaselineActivityFragment(baseline_activity=dict(pack.baseline_activity))
        except ValidationError as exc:
            raise PackError(
                f"{_pack_label(pack)} contains an invalid model fragment: {exc}"
            ) from exc

        for collection_name in ("traffic_affinities", "traffic_suppression"):
            for index, raw_rule in enumerate(pack.baseline_activity.get(collection_name, [])):
                rule = (
                    raw_rule.model_dump(mode="python")
                    if hasattr(raw_rule, "model_dump")
                    else raw_rule
                )
                audience = rule.get("audience") if isinstance(rule, Mapping) else None
                audience_data = (
                    audience.model_dump(mode="python")
                    if hasattr(audience, "model_dump")
                    else audience
                )
                if not isinstance(audience_data, Mapping):
                    continue
                for persona_index, persona in enumerate(audience_data.get("personas", [])):
                    _require_organization_model_reference(
                        persona,
                        global_catalogs["persona_catalog"],
                        builtin_personas,
                        pack=pack,
                        context=(
                            f"{_pack_label(pack)} model.baseline_activity.{collection_name}"
                            f"[{index}].audience.personas[{persona_index}]"
                        ),
                    )

        for index, user in enumerate(pack.environment.get("users", [])):
            persona = user.persona if hasattr(user, "persona") else user.get("persona")
            if persona is not None:
                _require_organization_model_reference(
                    persona,
                    global_catalogs["persona_catalog"],
                    builtin_personas,
                    pack=pack,
                    context=f"{_pack_label(pack)} model.environment.users[{index}].persona",
                )
        storage = pack.environment.get("storage")
        storage_data = (
            storage.model_dump(mode="python") if hasattr(storage, "model_dump") else storage
        )
        if isinstance(storage_data, Mapping):
            for server_index, server in enumerate(storage_data.get("servers", [])):
                for share_index, share in enumerate(server.get("shares", [])):
                    preset = share.get("preset")
                    if preset is not None:
                        _require_organization_model_reference(
                            preset,
                            global_catalogs["storage_catalog"],
                            builtin_storage_presets,
                            pack=pack,
                            context=(
                                f"{_pack_label(pack)} model.environment.storage.servers"
                                f"[{server_index}].shares[{share_index}].preset"
                            ),
                        )

    orphan_connections = sorted(
        set(application_connection_targets) - referenced_application_connections
    )
    if orphan_connections:
        formatted = ", ".join(
            f"{application}.{connection}" for application, connection in orphan_connections
        )
        raise PackError(
            "selected composition contains orphan application connection(s) not referenced by "
            f"traffic: {formatted}"
        )

    orphan_destinations = sorted(
        set(global_catalogs["destination_catalog"]) - referenced_destinations
    )
    if orphan_destinations:
        raise PackError(
            "selected composition contains orphan destination export(s) not referenced by an "
            "application connection or low-level traffic tag: " + ", ".join(orphan_destinations)
        )
