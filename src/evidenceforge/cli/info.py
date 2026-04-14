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


def _collect_dns_tags() -> list[str]:
    """Collect all DNS tags in use from the registry.

    Uses the same loader the generation engine uses to guarantee consistency.
    """
    from evidenceforge.generation.activity.dns_registry import load_dns_registry

    data = load_dns_registry()
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


def _collect_system_roles() -> list[str]:
    """Collect all system role names from traffic profiles.

    Uses the same loader the generation engine uses to guarantee consistency.
    """
    from evidenceforge.generation.activity.traffic_profiles import (
        load_traffic_profiles,
    )

    data = load_traffic_profiles()
    return sorted(data.get("role_traffic", {}).keys())


def gather_info() -> dict[str, Any]:
    """Gather all installation info into a single dict.

    Returns:
        Dict with version, install_type, config_writable, paths,
        personas, formats, dns_tags, application_ids, and system_roles.
    """
    config_root = get_config_directory()
    activity_dir = get_activity_directory()
    personas_dir = get_personas_directory()
    formats_dir = get_formats_directory()
    evaluation_dir = get_evaluation_directory()

    install_type, config_writable = _detect_install_type(config_root)

    from evidenceforge.config.overlay import get_overlay_directory, list_overlay_files

    overlay_dir = get_overlay_directory()
    overlay_files = list_overlay_files(overlay_dir) if overlay_dir else []

    return {
        "version": __version__,
        "install_type": install_type,
        "config_writable": config_writable,
        "paths": {
            "config_root": str(config_root),
            "activity": str(activity_dir),
            "personas": str(personas_dir),
            "formats": str(formats_dir),
            "evaluation": str(evaluation_dir),
        },
        "overlay": {
            "path": str(Path.cwd() / ".eforge" / "config"),
            "exists": overlay_dir is not None,
            "files": overlay_files,
        },
        "personas": _collect_personas(),
        "formats": _collect_formats(formats_dir),
        "dns_tags": _collect_dns_tags(),
        "application_ids": _collect_application_ids(),
        "system_roles": _collect_system_roles(),
    }


def format_human_readable(data: dict[str, Any]) -> str:
    """Format info data as human-readable text."""
    lines: list[str] = []

    # Header
    lines.append(f"EvidenceForge v{data['version']}")
    lines.append(f"Install type: {data['install_type']}")
    lines.append(f"Config writable: {'yes' if data['config_writable'] else 'no'}")
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

    roles = data["system_roles"]
    lines.append(f"System roles ({len(roles)}):")
    lines.append(_format_list(roles))

    return "\n".join(lines)


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
