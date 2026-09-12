"""Measure the second-pass dependency and field-forwarding acceptance contracts."""

from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from pathlib import Path
from typing import Any


def tree(source: Path, relative: str) -> ast.Module:
    """Read one source module without importing its runtime."""
    return ast.parse((source / "src/evidenceforge" / relative).read_text())


def runtime_imports(node: ast.AST) -> list[str]:
    """Collect execution imports, excluding annotation-only coordinator references."""
    if (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    ):
        return []
    if (
        isinstance(node, ast.ImportFrom)
        and node.module == "evidenceforge.generation.engine.storyline"
    ):
        return [alias.name for alias in node.names]
    return [name for child in ast.iter_child_nodes(node) for name in runtime_imports(child)]


def measure(source: Path) -> dict[str, Any]:
    """Return comparable counts and named inventories rather than line-count targets."""
    records = tree(source, "generation/actions/network_execution_stages.py")
    fields = {
        cls.name: [
            node.target.id
            for node in cls.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        ]
        for cls in records.body
        if isinstance(cls, ast.ClassDef) and cls.decorator_list
    }
    planner = tree(source, "generation/actions/network_transaction_planner.py")
    stages: dict[str, Any] = {}
    for method in ast.walk(planner):
        if not isinstance(method, ast.FunctionDef) or not any(
            arg.arg == "stage_input" for arg in method.args.args
        ):
            continue
        unpacked = []
        for node in method.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "stage_input"
            ):
                unpacked.append(node.targets[0].id)
        loads = Counter(
            node.id
            for node in ast.walk(method)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        )
        stores = Counter(
            node.id
            for node in ast.walk(method)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        )
        returned = {
            keyword.value.id
            for node in ast.walk(method)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
            for keyword in node.value.keywords
            if isinstance(keyword.value, ast.Name)
        }
        stages[method.name] = {
            "unpacked_fields": unpacked,
            "forwarded_only_fields": [
                name for name in unpacked if loads[name] == stores[name] == 1 and name in returned
            ],
            "branches": sum(isinstance(node, ast.If) for node in ast.walk(method)),
            "returns": sum(isinstance(node, ast.Return) for node in ast.walk(method)),
        }
    services = tree(source, "generation/actions/process_execution_service.py")
    service_dependencies = {
        cls.name: sorted(
            {
                node.attr
                for node in ast.walk(cls)
                if isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "runtime"
            }
        )
        for cls in services.body
        if isinstance(cls, ast.ClassDef)
    }
    handlers = source / "src/evidenceforge/generation/engine/typed_handlers"
    imports = {
        path.stem: runtime_imports(ast.parse(path.read_text()))
        for path in sorted(handlers.glob("*.py"))
    }
    return {
        "network_record_fields": fields,
        "network_field_declarations": sum(map(len, fields.values())),
        "network_stages": stages,
        "network_unpacked_fields": sum(len(stage["unpacked_fields"]) for stage in stages.values()),
        "network_forwarded_only_fields": sum(
            len(stage["forwarded_only_fields"]) for stage in stages.values()
        ),
        "process_broad_runtime_dependencies": service_dependencies,
        "handler_coordinator_runtime_imports": imports,
        "handler_coordinator_imported_names": sum(map(len, imports.values())),
    }


def main() -> None:
    """Write or display one structural inventory for a selected checkout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(measure(args.source), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
