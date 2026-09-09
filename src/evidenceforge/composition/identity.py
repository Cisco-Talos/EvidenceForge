# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical semantic identity for compiled scenarios."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import CompiledScenario

_NON_SEMANTIC_PACKAGED_DEFAULTS = frozenset({"generation_behavior.yaml"})


def is_semantic_packaged_default(relative_path: str) -> bool:
    """Return whether one packaged YAML file belongs to effective run configuration."""

    return relative_path not in _NON_SEMANTIC_PACKAGED_DEFAULTS


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def semantic_resolved_payload(compiled: CompiledScenario) -> dict[str, Any]:
    """Return generation-relevant resolved identity without control-plane metadata.

    The defensive filtering of ``generation_behavior.yaml`` preserves semantic
    comparisons with checkpoints written before that file was removed from
    ``EffectiveConfig.packaged_defaults``.
    """

    effective_config = compiled.effective_config.model_dump(mode="json")
    packaged_defaults = effective_config.get("packaged_defaults")
    if isinstance(packaged_defaults, dict):
        effective_config["packaged_defaults"] = {
            key: value
            for key, value in packaged_defaults.items()
            if is_semantic_packaged_default(key)
        }
    return {
        "assets": {
            name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for name, content in sorted(compiled.assets.items())
        },
        "effective_config": effective_config,
        "scenario": compiled.scenario.model_dump(mode="json"),
    }


def semantic_resolved_sha256(compiled: CompiledScenario) -> str:
    """Hash the canonical generation-relevant resolved identity."""

    return _canonical_sha256(semantic_resolved_payload(compiled))


def semantic_resolved_difference_sections(
    expected: CompiledScenario,
    candidate: CompiledScenario,
) -> tuple[str, ...]:
    """Return resolved sections whose generation-relevant identities differ."""

    expected_payload = semantic_resolved_payload(expected)
    candidate_payload = semantic_resolved_payload(candidate)
    return tuple(
        section
        for section in ("scenario", "effective_config", "assets")
        if _canonical_sha256(expected_payload[section])
        != _canonical_sha256(candidate_payload[section])
    )


__all__ = [
    "is_semantic_packaged_default",
    "semantic_resolved_difference_sections",
    "semantic_resolved_payload",
    "semantic_resolved_sha256",
]
