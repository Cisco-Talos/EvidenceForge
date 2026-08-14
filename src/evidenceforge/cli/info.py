# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""EvidenceForge installation info command.

Exposes version, config paths, available data inventories, and install type.
Used by Claude Code skills to discover the running configuration and by
humans to inspect their installation.
"""

import json
import os
from pathlib import Path
from typing import Any

import yaml

from evidenceforge import __version__
from evidenceforge.config import (
    get_activity_directory,
    get_config_directory,
    get_evaluation_directory,
    get_formats_directory,
    get_personas_directory,
)


def _detect_install_type(config_path: Path) -> tuple[str, bool]:
    """Detect whether this is an editable or package install.

    Returns:
        Tuple of (install_type, config_writable).
    """
    path_str = str(config_path)
    if "site-packages" in path_str or "dist-packages" in path_str:
        return "package", os.access(config_path, os.W_OK)
    return "editable", True


def _collect_personas() -> list[str]:
    """Collect all persona names (package + overlay).

    Uses the same loader the generation engine uses to guarantee consistency.
    """
    from evidenceforge.utils.personas import load_builtin_personas

    personas = load_builtin_personas()
    return sorted(p["name"] for p in personas if "name" in p)


def _collect_formats(formats_dir: Path) -> list[str]:
    """Collect supported format names from YAML files."""
    if not formats_dir.is_dir():
        return []
    return sorted(f.stem for f in formats_dir.glob("*.yaml"))


def _collect_packs(project_root: Path) -> list[str]:
    """Collect exact package/project pack references for explicit discovery."""

    from evidenceforge.composition.packs import PackRepository

    repository = PackRepository(project_root)
    return sorted(
        f"{pack.source}:{pack.manifest.type}:{pack.manifest.name}@{pack.manifest.version}"
        for pack in repository.list()
    )


def _collect_dns_tags() -> list[str]:
    """Collect defined valid DNS tags from the registry.

    Returns the authoritative list of tags from the valid_tags section
    of dns_registry.yaml. Tags in use on domains but not defined here
    are caught by eforge validate-config, not reported by eforge info.
    """
    from evidenceforge.generation.activity.dns_registry import load_dns_registry

    data = load_dns_registry()
    valid_tags = data.get("valid_tags", {})
    if valid_tags:
        return sorted(valid_tags.keys())
    # Fallback for older configs without valid_tags section
    tags: set[str] = set()
    for entry in data.get("domains", []):
        tags.update(entry.get("tags", []))
    return sorted(tags)


def _collect_application_ids() -> list[str]:
    """Collect all application IDs from the catalog.

    Uses the same loader the generation engine uses to guarantee consistency.
    """
    from evidenceforge.generation.activity.application_catalog import load_catalog

    data = load_catalog()
    return sorted(app["id"] for app in data.get("applications", []) if "id" in app)


def _collect_pack_builtin_application_ids() -> list[str]:
    """Collect stable application IDs allowed by the public pack schema."""

    from evidenceforge.composition.semantic_validation import (
        packaged_builtin_application_ids,
    )

    return sorted(packaged_builtin_application_ids())


def _collect_pack_builtin_dns_tags() -> list[str]:
    """Collect stable packaged DNS tags allowed by the public pack schema."""

    from evidenceforge.composition.semantic_validation import packaged_builtin_dns_tags

    return sorted(packaged_builtin_dns_tags())


def _collect_system_roles() -> list[str]:
    """Collect author-facing system role names from role-aware config.

    Roles can affect generation through multiple paths: traffic profiles,
    host activity multipliers, topology inference, proxy routing, and inbound
    web visitor profiles. This inventory is used by skills and authors, so it
    reports scenario-usable role names rather than only one config file.
    """
    from evidenceforge.generation.activity.host_activity_profiles import (
        load_host_activity_profiles,
    )
    from evidenceforge.generation.activity.traffic_profiles import (
        load_traffic_profiles,
    )
    from evidenceforge.generation.activity.web_session_profiles import (
        load_web_session_profiles,
    )
    from evidenceforge.generation.world_model import known_topology_roles

    pseudo_roles = {"_any", "_any_server", "_default", "_external"}
    roles: set[str] = set()

    traffic_data = load_traffic_profiles()
    role_traffic = traffic_data.get("role_traffic", {})
    if isinstance(role_traffic, dict):
        roles.update(str(role) for role in role_traffic)

    activity_data = load_host_activity_profiles()
    role_profiles = activity_data.get("role_profiles", {})
    if isinstance(role_profiles, dict):
        roles.update(str(role) for role in role_profiles)

    web_session_data = load_web_session_profiles()
    visitor_classes = web_session_data.get("visitor_classes", {})
    if isinstance(visitor_classes, dict):
        for profile in visitor_classes.values():
            if not isinstance(profile, dict):
                continue
            source_roles = profile.get("source_role_any", [])
            if isinstance(source_roles, list):
                roles.update(str(role) for role in source_roles)

    roles.update(known_topology_roles())
    return sorted(role for role in roles if role and role not in pseudo_roles)


def _collect_web_scan_presets() -> list[str]:
    """Collect available web scan preset names."""
    from evidenceforge.config.web_scan_presets import list_preset_names

    return list_preset_names()


def _collect_beacon_profiles() -> list[str]:
    """Collect available beacon behavior profile names."""
    from evidenceforge.config.beacon_profiles import list_profile_names

    return list_profile_names()


def _collect_format_groups() -> dict[str, list[str]]:
    """Collect format group names and their expanded formats."""
    from evidenceforge.events.dispatcher import FORMAT_GROUPS

    return {k: sorted(v) for k, v in FORMAT_GROUPS.items()}


def _collect_config_families() -> dict[str, dict[str, str]]:
    """Expose authoring-grade overlay ownership and merge contracts."""

    from evidenceforge.config.overlay_registry import config_family_inventory

    return config_family_inventory()


def _storyline_event_models() -> dict[str, Any]:
    """Return event-spec models derived from the authoritative runtime union."""

    from typing import get_args

    from evidenceforge.models.scenario import EventSpec

    union = get_args(EventSpec)[0]
    models: dict[str, Any] = {}
    for model in get_args(union):
        event_type = model.model_fields["type"].default
        models[str(event_type)] = model
    return dict(sorted(models.items()))


def _collect_storyline_event_types() -> list[str]:
    """Collect authored storyline event type names from the runtime union."""

    return list(_storyline_event_models())


def _collect_storyline_event_schema(event_type: str) -> dict[str, Any] | None:
    """Return one event model's validation JSON Schema, including nested definitions."""

    model = _storyline_event_models().get(event_type)
    if model is None:
        return None
    return model.model_json_schema(mode="validation")


def _collect_identity_pools() -> dict[str, Any]:
    """Collect counts and overlay paths for data-driven generated identity pools."""
    from evidenceforge.generation.activity.command_parameter_pools import (
        load_command_parameter_pools,
    )
    from evidenceforge.generation.activity.email_background import load_email_background
    from evidenceforge.generation.activity.external_actor_profiles import (
        load_external_actor_profiles,
    )
    from evidenceforge.generation.activity.mail_public_identities import (
        load_mail_public_identities,
    )
    from evidenceforge.generation.activity.suspicious_benign_config import (
        load_suspicious_benign,
    )

    email_background = load_email_background()
    mail_public = load_mail_public_identities()
    external_actor = load_external_actor_profiles()
    suspicious_benign = load_suspicious_benign()
    command_pools = load_command_parameter_pools()
    command_keys = sorted(
        {
            str(key)
            for section in command_pools.values()
            if isinstance(section, dict)
            for key in section
        }
    )
    return {
        "overlay_paths": [
            "activity/email_background.yaml",
            "activity/mail_public_identities.yaml",
            "activity/external_actor_profiles.yaml",
            "activity/suspicious_benign.yaml",
            "activity/command_parameter_pools.yaml",
        ],
        "email_background": {
            "external_domains": len(email_background.get("external_domains", [])),
            "inbound_local_parts": len(email_background.get("inbound_local_parts", [])),
            "outbound_local_parts": len(email_background.get("outbound_local_parts", [])),
        },
        "mail_public_identities": {
            "reserved_replacement_domains": len(
                mail_public.get("reserved_replacement_domains", [])
            ),
            "providers": len(mail_public.get("providers", [])),
        },
        "external_actor_profiles": {
            "logon_source_ips": len(external_actor.get("logon_source_ips", [])),
            "failed_logon_source_ips": len(external_actor.get("failed_logon_source_ips", [])),
            "connection_c2_ips": len(external_actor.get("connection_c2_ips", [])),
        },
        "suspicious_benign": {
            "dns_hosts": len(suspicious_benign.get("dns_hosts", [])),
            "unusual_connections": len(suspicious_benign.get("unusual_connections", [])),
        },
        "command_parameter_pools": {
            "keys": command_keys,
        },
    }


def _gather_lightweight(project_root: Path) -> dict[str, Any]:
    """Gather lightweight fields that don't require overlay-backed loaders.

    These always succeed even if the overlay has broken YAML.
    """
    config_root = get_config_directory()
    install_type, config_writable = _detect_install_type(config_root)

    from evidenceforge.config.overlay import get_overlay_directory, list_overlay_files

    overlay_dir = get_overlay_directory(project_root)
    overlay_files = list_overlay_files(overlay_dir) if overlay_dir else []

    return {
        "version": __version__,
        "install_type": install_type,
        "config_writable": config_writable,
        "project_root": str(project_root),
        "paths": {
            "config_root": str(config_root),
            "activity": str(get_activity_directory()),
            "personas": str(get_personas_directory()),
            "formats": str(get_formats_directory()),
            "evaluation": str(get_evaluation_directory()),
        },
        "overlay": {
            "path": str(project_root / ".eforge" / "config"),
            "exists": overlay_dir is not None,
            "files": overlay_files,
        },
        "pack_roots": {
            "package": str(config_root / "packs"),
            "project": str(project_root / ".eforge" / "packs"),
        },
    }


# Fields that can be resolved from lightweight data alone
_LIGHTWEIGHT_PREFIXES = {
    "version",
    "install_type",
    "config_writable",
    "project_root",
    "paths",
    "overlay",
    "pack_roots",
}


def gather_info(field: str | None = None, project_root: Path | None = None) -> dict[str, Any]:
    """Gather installation info into a single dict.

    If ``field`` is provided and it's a lightweight field (version, paths,
    overlay, etc.), only compute those — no overlay-backed loaders are
    called. This ensures ``eforge info overlay.path`` works even when
    the overlay has broken YAML.

    For inventory fields (personas, dns_tags, etc.) or full output,
    each inventory is loaded with error handling so a single broken
    loader doesn't crash the entire command.
    """
    from evidenceforge.composition.compiler import (
        build_management_effective_config,
        resolve_management_project_root,
    )
    from evidenceforge.config.overlay import overlay_project_root_scope
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.models.exceptions import EvidenceForgeError

    resolved_project_root = resolve_management_project_root(project_root)
    data = _gather_lightweight(resolved_project_root)

    if field and field.startswith("storyline_event_schemas"):
        parts = field.split(".")
        schemas: dict[str, Any] = {}
        if len(parts) == 1:
            schemas = {
                event_type: schema
                for event_type in _collect_storyline_event_types()
                if (schema := _collect_storyline_event_schema(event_type)) is not None
            }
        elif len(parts) == 2:
            schema = _collect_storyline_event_schema(parts[1])
            if schema is not None:
                schemas[parts[1]] = schema
        data["storyline_event_schemas"] = schemas
        return data

    # If requesting a lightweight field, return early — no loaders needed
    if field:
        top_level = field.split(".")[0]
        if top_level in _LIGHTWEIGHT_PREFIXES:
            return data

    # Inventory fields — each wrapped in try/except so one broken
    # overlay doesn't prevent the rest from being reported
    formats_dir = get_formats_directory()
    inventories = {
        "personas": _collect_personas,
        "formats": lambda: _collect_formats(formats_dir),
        "dns_tags": _collect_dns_tags,
        "application_ids": _collect_application_ids,
        "pack_builtin_application_ids": _collect_pack_builtin_application_ids,
        "pack_builtin_dns_tags": _collect_pack_builtin_dns_tags,
        "system_roles": _collect_system_roles,
        "web_scan_presets": _collect_web_scan_presets,
        "beacon_profiles": _collect_beacon_profiles,
        "format_groups": _collect_format_groups,
        "identity_pools": _collect_identity_pools,
        "packs": lambda: _collect_packs(resolved_project_root),
        "config_families": _collect_config_families,
        "storyline_event_types": _collect_storyline_event_types,
    }
    effective_config = build_management_effective_config(resolved_project_root)
    expected_errors = (
        EvidenceForgeError,
        OSError,
        UnicodeError,
        yaml.YAMLError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    )
    with (
        overlay_project_root_scope(resolved_project_root),
        effective_config_scope(effective_config),
    ):
        for key, collector in inventories.items():
            try:
                data[key] = collector()
            except expected_errors as e:
                data[key] = f"<error: {e}>"

    return data


def format_human_readable(data: dict[str, Any]) -> str:
    """Format info data as human-readable text."""
    lines: list[str] = []

    # Header
    lines.append(f"EvidenceForge v{data['version']}")
    lines.append(f"Install type: {data['install_type']}")
    lines.append(f"Config writable: {'yes' if data['config_writable'] else 'no'}")
    lines.append(f"Project root: {data['project_root']}")
    lines.append("")

    pack_roots = data["pack_roots"]
    lines.append("Pack roots:")
    lines.append(f"  Package: {pack_roots['package']}")
    lines.append(f"  Project: {pack_roots['project']}")
    lines.append("")

    # Paths
    lines.append("Config paths:")
    paths = data["paths"]
    lines.append(f"  Root:       {paths['config_root']}")
    lines.append(f"  Activity:   {paths['activity']}")
    lines.append(f"  Personas:   {paths['personas']}")
    lines.append(f"  Formats:    {paths['formats']}")
    lines.append(f"  Evaluation: {paths['evaluation']}")
    lines.append("")

    # Overlay status
    overlay = data["overlay"]
    if overlay["exists"]:
        file_count = len(overlay["files"])
        lines.append(
            f"Overlay config: {overlay['path']} (found, {file_count} file{'s' if file_count != 1 else ''})"
        )
        for f in overlay["files"]:
            lines.append(f"  {f}")
    else:
        lines.append(f"Overlay config: {overlay['path']} (not found — using package defaults only)")
    lines.append("")

    # Data inventories
    def _format_list(items: list[str], indent: str = "  ") -> str:
        """Wrap a comma-separated list of items into 80-char lines."""
        from textwrap import fill

        return fill(", ".join(items), width=80, initial_indent=indent, subsequent_indent=indent)

    personas = data["personas"]
    lines.append(f"Built-in personas ({len(personas)}):")
    lines.append(_format_list(personas))
    lines.append("")

    formats = data["formats"]
    lines.append(f"Supported formats ({len(formats)}):")
    lines.append(_format_list(formats))
    lines.append("")

    dns_tags = data["dns_tags"]
    lines.append(f"DNS tags in use ({len(dns_tags)}):")
    lines.append(_format_list(dns_tags))
    lines.append("")

    app_ids = data["application_ids"]
    lines.append(f"Application IDs ({len(app_ids)}):")
    lines.append(_format_list(app_ids))
    lines.append("")

    pack_app_ids = data["pack_builtin_application_ids"]
    lines.append(f"Pack built-in application IDs ({len(pack_app_ids)}):")
    lines.append(_format_list(pack_app_ids))
    lines.append("")

    pack_dns_tags = data["pack_builtin_dns_tags"]
    lines.append(f"Pack built-in DNS tags ({len(pack_dns_tags)}):")
    lines.append(_format_list(pack_dns_tags))
    lines.append("")

    beacon_profiles = data["beacon_profiles"]
    lines.append(f"Beacon profiles ({len(beacon_profiles)}):")
    lines.append(_format_list(beacon_profiles))
    lines.append("")

    roles = data["system_roles"]
    lines.append(f"System roles ({len(roles)}):")
    lines.append(_format_list(roles))
    lines.append("")

    identity_pools = data["identity_pools"]
    lines.append("Identity pools:")
    if isinstance(identity_pools, dict):
        for overlay_path in identity_pools["overlay_paths"]:
            lines.append(f"  {overlay_path}")
    else:
        lines.append(f"  {identity_pools}")

    packs = data["packs"]
    lines.append("")
    if isinstance(packs, list):
        lines.append(f"Available packs ({len(packs)}):")
        lines.append(_format_list(packs))
    else:
        lines.append(f"Available packs: {packs}")

    event_types = data["storyline_event_types"]
    lines.append("")
    if isinstance(event_types, list):
        lines.append(f"Storyline event types ({len(event_types)}):")
        lines.append(_format_list(event_types))
    else:
        lines.append(f"Storyline event types: {event_types}")

    return "\n".join(lines)


_FIELD_DESCRIPTIONS: dict[str, str] = {
    "application_ids": "Application IDs in the catalog",
    "beacon_profiles": "Available beacon behavior profile names",
    "config_writable": "Whether package config files are directly editable",
    "config_families": "Configuration families and their runtime ownership class",
    "dns_tags": "Defined valid DNS tags (from dns_registry.yaml valid_tags section)",
    "format_groups": "Format group names and their expanded formats (for --formats flag)",
    "formats": "Supported log format names",
    "identity_pools": "Generated identity pool counts and overlay paths",
    "install_type": "Package install type (editable or package)",
    "overlay.exists": "Whether a project-local overlay directory exists",
    "overlay.files": "YAML files in the overlay directory",
    "overlay.path": "Path to the overlay directory",
    "pack_roots.package": "Installed read-only pack repository",
    "pack_roots.project": "Project-local editable pack repository",
    "packs": "Exact packaged and project-local pack references",
    "pack_builtin_application_ids": (
        "Stable packaged application IDs allowed in pack process profiles"
    ),
    "pack_builtin_dns_tags": "Stable packaged DNS tags allowed in pack low-level traffic",
    "paths.activity": "Activity config directory (dns, traffic, apps, etc.)",
    "paths.config_root": "Root config directory",
    "paths.evaluation": "Evaluation rules directory",
    "paths.formats": "Format definitions directory",
    "paths.personas": "Persona definitions directory",
    "personas": "Built-in persona names (package + overlay)",
    "project_root": "Resolved project root used for overlays and project packs",
    "storyline_event_types": "Runtime-derived typed storyline event names",
    "system_roles": "Author-facing system role names from role-aware config",
    "version": "EvidenceForge version",
    "web_scan_presets": "Available web scan preset names (nikto, dirb, etc.)",
}


def list_fields(data: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """List all valid dot-path field names with descriptions.

    Returns:
        Sorted list of (field_name, description) tuples.
    """
    fields: list[tuple[str, str]] = []
    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if full_key == "config_families":
            fields.append((full_key, _FIELD_DESCRIPTIONS[full_key]))
        elif isinstance(value, dict):
            fields.extend(list_fields(value, full_key))
        else:
            desc = _FIELD_DESCRIPTIONS.get(full_key, "")
            fields.append((full_key, desc))
    if not prefix:
        event_types = data.get("storyline_event_types", [])
        if isinstance(event_types, list):
            fields.extend(
                (
                    f"storyline_event_schemas.{event_type}",
                    f"Runtime-derived JSON Schema for the {event_type} event",
                )
                for event_type in event_types
            )
    return sorted(fields)


def resolve_field(data: dict[str, Any], field: str) -> Any:
    """Resolve a dot-path field reference against the info data.

    Examples:
        resolve_field(data, "paths.activity") → "/path/to/config/activity"
        resolve_field(data, "overlay.exists") → True
        resolve_field(data, "personas") → ["accountant", "analyst", ...]
        resolve_field(data, "version") → "0.1.0"

    Returns:
        The resolved value, or None if the field path doesn't exist.
    """
    current: Any = data
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def format_json(data: dict[str, Any]) -> str:
    """Format info data as compact-but-readable JSON.

    Uses a custom format: top-level keys on separate lines for readability,
    but arrays are collapsed to single lines to save tokens when parsed by AI.
    """
    parts: list[str] = ["{"]
    items = list(data.items())
    for i, (key, value) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        if isinstance(value, dict):
            # Nested objects get one line per key
            inner = ", ".join(f'"{k}": {json.dumps(v)}' for k, v in value.items())
            parts.append(f'  "{key}": {{{inner}}}{comma}')
        elif isinstance(value, list):
            # Arrays on a single line
            parts.append(f'  "{key}": {json.dumps(value)}{comma}')
        else:
            parts.append(f'  "{key}": {json.dumps(value)}{comma}')
    parts.append("}")
    return "\n".join(parts)
