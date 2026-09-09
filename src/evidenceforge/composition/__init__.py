# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scenario composition, pack resolution, and authoritative artifact APIs."""

from .compiler import compile_scenario, resolve_project_root, with_runtime_scenario
from .identity import (
    semantic_resolved_difference_sections,
    semantic_resolved_payload,
    semantic_resolved_sha256,
)
from .models import (
    CompiledScenario,
    CompositionSpec,
    EffectiveConfig,
    PackManifest,
    PackReference,
    ResolvedScenarioDocument,
    ScenarioV1Document,
    ScenarioV2Document,
)

__all__ = [
    "CompiledScenario",
    "CompositionSpec",
    "EffectiveConfig",
    "PackManifest",
    "PackReference",
    "ResolvedScenarioDocument",
    "ScenarioV1Document",
    "ScenarioV2Document",
    "compile_scenario",
    "resolve_project_root",
    "semantic_resolved_difference_sections",
    "semantic_resolved_payload",
    "semantic_resolved_sha256",
    "with_runtime_scenario",
]
