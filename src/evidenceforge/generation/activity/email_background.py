# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Config-backed identity pools for baseline email traffic."""

from __future__ import annotations

import random
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_CONFIG_PATH = get_activity_directory() / "email_background.yaml"
_CACHED_DATA: dict[str, Any] | None = None

_LOCAL_PART_FIELDS = Literal["inbound_local_parts", "outbound_local_parts"]


def _merge_email_background(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge email background overlay pools with package defaults."""
    result = dict(default)
    if "external_domains" in overlay:
        result["external_domains"] = merge_keyed_list(
            default.get("external_domains", []),
            overlay["external_domains"],
            key_field="domain",
        )
    for field in ("inbound_local_parts", "outbound_local_parts"):
        if field in overlay:
            result[field] = merge_keyed_list(
                default.get(field, []),
                overlay[field],
                key_field="local_part",
            )
    return result


def load_email_background() -> dict[str, Any]:
    """Load baseline email identity pools, merged with local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/email_background.yaml",
        _merge_email_background,
    )
    return _CACHED_DATA


def reset_email_background_cache() -> None:
    """Clear cached baseline email identity pools. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _pick_weighted_value(
    rng: random.Random,
    entries: list[dict[str, Any]],
    value_key: str,
    fallback: str,
) -> str:
    weighted = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and str(entry.get(value_key) or "").strip()
        and int(entry.get("weight", 0)) > 0
    ]
    if not weighted:
        return fallback
    weights = [int(entry.get("weight", 0)) for entry in weighted]
    return str(rng.choices(weighted, weights=weights, k=1)[0][value_key]).strip()


def pick_email_background_domain(rng: random.Random) -> str:
    """Pick a configured external email domain for baseline mail."""
    data = load_email_background()
    return _pick_weighted_value(
        rng,
        list(data.get("external_domains", [])),
        "domain",
        "postrelay.net",
    )


def pick_email_background_local_part(rng: random.Random, field: _LOCAL_PART_FIELDS) -> str:
    """Pick a configured local part for inbound or outbound baseline mail."""
    data = load_email_background()
    fallback = "notifications" if field == "inbound_local_parts" else "contact"
    return _pick_weighted_value(
        rng,
        list(data.get(field, [])),
        "local_part",
        fallback,
    )
