# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused repository policy for migrated temporal sampling owners."""

from __future__ import annotations

import ast
from pathlib import Path

import evidenceforge.generation as generation_package

_LEGACY_HELPERS = frozenset({"sample_timing_delta", "sample_packet_timing_delta"})
_RAW_TEMPORAL_METHODS = frozenset(
    {
        "betavariate",
        "expovariate",
        "gammavariate",
        "gauss",
        "lognormvariate",
        "normalvariate",
        "paretovariate",
        "randint",
        "randrange",
        "triangular",
        "uniform",
        "vonmisesvariate",
        "weibullvariate",
    }
)


def test_smb_composite_has_no_legacy_temporal_sampler_bypass() -> None:
    """The migrated composite relationship must use the injected runtime only."""

    smb_path = Path(generation_package.__file__).parent / "actions" / "smb_activity.py"
    tree = ast.parse(smb_path.read_text(encoding="utf-8"), filename=str(smb_path))
    imported_legacy_helpers = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name in _LEGACY_HELPERS
    }
    composite = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_execute_composite_transfer"
    )
    offenders: list[tuple[int, str]] = []
    for call in (node for node in ast.walk(composite) if isinstance(node, ast.Call)):
        called = ""
        if isinstance(call.func, ast.Name):
            called = call.func.id
        elif isinstance(call.func, ast.Attribute):
            called = call.func.attr
        if called in _LEGACY_HELPERS or called in _RAW_TEMPORAL_METHODS or called == "_stable_seed":
            offenders.append((call.lineno, called))

    assert imported_legacy_helpers == set()
    assert offenders == []
