# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Keep typed execution independent of the storyline coordinator's helper exports."""

import ast
from pathlib import Path

from evidenceforge.generation.engine import storyline, storyline_helpers, typed_handlers
from evidenceforge.generation.engine.storyline_helpers import http, ids, periodic, process


def _runtime_coordinator_imports(node: ast.AST) -> list[int]:
    if (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    ):
        return []
    if isinstance(node, ast.ImportFrom) and node.module == storyline.__name__:
        return [node.lineno]
    return [
        line for child in ast.iter_child_nodes(node) for line in _runtime_coordinator_imports(child)
    ]


def test_handler_and_helper_execution_has_no_coordinator_imports() -> None:
    for package in (typed_handlers, storyline_helpers):
        for path in Path(package.__file__).parent.glob("*.py"):
            assert _runtime_coordinator_imports(ast.parse(path.read_text())) == [], path.name


def test_coordinator_compatibility_names_reference_the_actual_helper() -> None:
    for owner, name in (
        (ids, "_build_ids_alert_contexts"),
        (http, "_storyline_http_response_body_len"),
        (periodic, "_iter_periodic_ticks"),
        (process, "_normalize_storyline_process_image"),
    ):
        assert getattr(storyline, name) is getattr(owner, name)
