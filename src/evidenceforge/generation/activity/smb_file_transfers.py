# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SMB file-transfer realism configuration loader."""

import random
import string
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "smb_file_transfers.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_smb_file_transfers(default: dict, overlay: dict) -> dict:
    """Merge SMB file-transfer overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_smb_file_transfers() -> dict[str, Any]:
    """Load SMB file-transfer config from YAML, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/smb_file_transfers.yaml",
        _merge_smb_file_transfers,
    )
    return _CACHED_DATA


def reset_smb_file_transfers_cache() -> None:
    """Clear cached SMB file-transfer config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def pick_smb_filename(
    rng: random.Random,
    config: dict[str, Any],
    *,
    mime_type: str,
    server: str,
    user: str = "Public",
) -> str:
    """Pick a data-driven SMB filename/path for a Zeek files.log row."""
    templates = config.get("filename_templates", [])
    if not isinstance(templates, list) or not templates:
        return ""

    eligible: list[dict[str, Any]] = []
    for entry in templates:
        if not isinstance(entry, dict):
            continue
        mime_types = entry.get("mime_types", [])
        if not mime_types or mime_type in {str(value) for value in mime_types}:
            eligible.append(entry)
    if not eligible:
        eligible = [entry for entry in templates if isinstance(entry, dict)]
    if not eligible:
        return ""

    weights = [int(entry.get("weight", 1)) for entry in eligible]
    selected = rng.choices(eligible, weights=weights, k=1)[0]
    candidate_templates = selected.get("templates", [])
    if not isinstance(candidate_templates, list) or not candidate_templates:
        return ""

    pool_defaults = {
        "shares": ["Shared"],
        "departments": ["Operations"],
        "projects": ["Projects"],
        "basenames": ["document"],
        "binary_extensions": ["dat"],
    }
    pools = {}
    for key, defaults in pool_defaults.items():
        values = [str(value) for value in config.get(key, []) if str(value)]
        pools[key] = values or defaults

    def _materialize_filename(local_rng: random.Random, *, add_novelty: bool) -> str:
        lexical_subjects = [str(value) for value in config.get("lexical_subjects", []) if value]
        lexical_kinds = [str(value) for value in config.get("lexical_document_kinds", []) if value]
        lexical_qualifiers = [str(value) for value in config.get("lexical_qualifiers", []) if value]
        composition_probability = float(config.get("lexical_composition_probability", 0.0))
        if lexical_subjects and lexical_kinds and local_rng.random() < composition_probability:
            basename = f"{local_rng.choice(lexical_subjects)}-{local_rng.choice(lexical_kinds)}"
            if lexical_qualifiers and local_rng.random() < 0.45:
                basename = f"{basename}-{local_rng.choice(lexical_qualifiers)}"
        else:
            basename = local_rng.choice(pools["basenames"])
        if add_novelty and local_rng.random() < 0.35:
            basename = f"{basename}-{local_rng.randint(2023, 2026)}"
        if add_novelty and local_rng.random() < 0.15:
            suffix = "".join(
                local_rng.choice(string.ascii_uppercase + string.digits) for _ in range(4)
            )
            basename = f"{basename}-{suffix}"
        placeholders = {
            "server": server.split(".")[0] or "fileserver",
            "share": local_rng.choice(pools["shares"]),
            "department": local_rng.choice(pools["departments"]),
            "project": local_rng.choice(pools["projects"]),
            "basename": basename,
            "ext": local_rng.choice(pools["binary_extensions"]),
            "user": user or "Public",
        }
        return str(local_rng.choice(candidate_templates)).format(**placeholders)

    working_set_probability = float(config.get("working_set_probability", 0.0))
    working_set_size = max(1, int(config.get("working_set_size", 1)))
    if rng.random() < working_set_probability:
        stable_rng = random.Random(
            _stable_seed(f"smb-working-set:{server.lower()}:{user.lower()}:{mime_type}")
        )
        working_set = [
            _materialize_filename(stable_rng, add_novelty=False) for _ in range(working_set_size)
        ]
        return rng.choice(working_set)
    return _materialize_filename(rng, add_novelty=True)
