# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Extract a deterministic static inventory for the EvidenceForge realism review.

This utility is intentionally read-only with respect to generator behavior. It parses the source
tree and writes review artifacts describing authored event specifications, internal event kinds,
canonical contexts and plans, action bundles, constructor/call paths, emitter consumers, formats,
tests, and evaluator references.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """One deterministic source-code location."""

    file: str
    line: int
    scope: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {"file": self.file, "line": self.line, "scope": self.scope}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract the EvidenceForge event/context realism-review inventory.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="EvidenceForge repository root.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Inventory JSON output path. Defaults to "
            "docs/design/realism-review/event-context-paths.json."
        ),
    )
    parser.add_argument(
        "--coverage-output",
        type=Path,
        help=(
            "Coverage JSON output path. Defaults to "
            "docs/design/realism-review/coverage-summary.json."
        ),
    )
    parser.add_argument(
        "--classifications",
        type=Path,
        help=(
            "Reviewed path-classification JSON. Defaults to "
            "docs/design/realism-review/path-classifications.json."
        ),
    )
    return parser.parse_args(argv)


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _read_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _call_name(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func)
    except ValueError:
        return ""


def _short_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _string_literals(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "EventKind"
    ):
        return {node.attr.casefold()}
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: set[str] = set()
        for item in node.elts:
            values.update(_string_literals(item))
        return values
    if isinstance(node, ast.Subscript):
        return _string_literals(node.slice)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _string_literals(node.left) | _string_literals(node.right)
    return set()


def _json_expression(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except ValueError:
        return "<unparseable>"


def _decorator_keywords(node: ast.ClassDef, decorator_name: str) -> dict[str, Any]:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == decorator_name:
            return {}
        if isinstance(decorator, ast.Call) and _json_expression(decorator.func) == decorator_name:
            values: dict[str, Any] = {}
            for keyword in decorator.keywords:
                if keyword.arg is not None:
                    try:
                        values[keyword.arg] = ast.literal_eval(keyword.value)
                    except (ValueError, TypeError):
                        values[keyword.arg] = _json_expression(keyword.value)
            return values
    return {}


def _is_dataclass(node: ast.ClassDef) -> bool:
    return any(
        (isinstance(decorator, ast.Name) and decorator.id == "dataclass")
        or (isinstance(decorator, ast.Call) and _json_expression(decorator.func) == "dataclass")
        for decorator in node.decorator_list
    )


def _scope_name(stack: list[str]) -> str:
    return ".".join(stack) if stack else "<module>"


class SourceIndexVisitor(ast.NodeVisitor):
    """Collect source-level paths and event/context references."""

    def __init__(
        self,
        path: Path,
        root: Path,
        event_fields: set[str],
        payload_fields: set[str],
    ) -> None:
        self.path = path
        self.relative_path = _relative(path, root)
        self.event_fields = event_fields
        self.payload_fields = payload_fields
        self.scope: list[str] = []
        self.occurrence_builder_constructors: list[dict[str, Any]] = []
        self.context_constructors: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.bundle_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.generate_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.dispatch_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.state_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.event_field_reads: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.event_type_references: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    def _location(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(self.relative_path, node.lineno, _scope_name(self.scope))

    def _call_record(self, node: ast.Call) -> dict[str, Any]:
        return {
            **self._location(node).as_dict(),
            "call": _call_name(node),
        }

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        short_name = _short_call_name(node)
        record = self._call_record(node)
        if short_name == "OccurrenceBuilder":
            event_type_node: ast.AST | None = None
            for keyword in node.keywords:
                if keyword.arg == "event_type":
                    event_type_node = keyword.value
                    break
            if event_type_node is None and len(node.args) >= 2:
                event_type_node = node.args[1]
            contexts = sorted(
                keyword.arg
                for keyword in node.keywords
                if keyword.arg is not None and keyword.arg in self.payload_fields
            )
            self.occurrence_builder_constructors.append(
                {
                    **record,
                    "event_type_expression": _json_expression(event_type_node),
                    "event_type_literals": sorted(_string_literals(event_type_node)),
                    "contexts_attached_at_construction": contexts,
                }
            )
        elif short_name.endswith("Context"):
            self.context_constructors[short_name].append(record)
        if short_name.endswith("ActionBundle") and short_name != "ActionBundle":
            self.bundle_calls[short_name].append(record)
        if short_name.startswith("generate_"):
            self.generate_calls[short_name].append(record)
        if short_name in {"dispatch", "dispatch_builder", "dispatch_raw"}:
            self.dispatch_calls[short_name].append(record)
        if isinstance(node.func, ast.Attribute):
            receiver = _json_expression(node.func.value)
            if "state_manager" in receiver or receiver in {"sm", "state"}:
                self.state_calls[short_name].append({**record, "receiver": receiver})
        for keyword in node.keywords:
            if keyword.arg == "event_type":
                for value in _string_literals(keyword.value):
                    self.event_type_references[value].append({**record, "kind": "call_keyword"})
        if short_name == "_expand_and_emit" and node.args:
            for value in _string_literals(node.args[0]):
                self.event_type_references[value].append({**record, "kind": "causal_trigger"})
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in {
            "event",
            "event_to_emit",
            "sensor_event",
        }:
            if node.attr in self.event_fields:
                self.event_field_reads[node.attr].append(self._location(node).as_dict())
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        candidates = [node.left, *node.comparators]
        event_type_side = any(
            isinstance(candidate, ast.Attribute) and candidate.attr == "event_type"
            for candidate in candidates
        )
        if event_type_side:
            for candidate in candidates:
                for value in _string_literals(candidate):
                    self.event_type_references[value].append(
                        {**self._location(node).as_dict(), "kind": "comparison"}
                    )
        self.generic_visit(node)


def _dataclass_inventory(path: Path, root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    tree = _read_tree(path)
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not _is_dataclass(node):
            continue
        fields = []
        methods = []
        for child in node.body:
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                fields.append(
                    {
                        "name": child.target.id,
                        "annotation": _json_expression(child.annotation),
                        "default": _json_expression(child.value),
                    }
                )
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(child.name)
        options = _decorator_keywords(node, "dataclass")
        result.append(
            {
                "name": node.name,
                "file": _relative(path, root),
                "line": node.lineno,
                "fields": fields,
                "frozen": bool(options.get("frozen", False)),
                "slots": bool(options.get("slots", False)),
                "validators": sorted(
                    method
                    for method in methods
                    if method == "__post_init__" or method.startswith("validate")
                ),
            }
        )
    return result


def _builder_fields(root: Path) -> list[dict[str, Any]]:
    path = root / "src/evidenceforge/events/base.py"
    tree = _read_tree(path)
    event_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "OccurrenceBuilder"
    )
    fields = []
    for node in event_class.body:
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        fields.append(
            {
                "name": node.target.id,
                "annotation": _json_expression(node.annotation),
                "default": _json_expression(node.value),
                "line": node.lineno,
            }
        )
    return fields


def _authored_event_specs(root: Path) -> list[dict[str, Any]]:
    path = root / "src/evidenceforge/models/scenario.py"
    tree = _read_tree(path)
    result = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not node.name.endswith("EventSpec"):
            continue
        type_field = next(
            (
                child
                for child in node.body
                if isinstance(child, ast.AnnAssign)
                and isinstance(child.target, ast.Name)
                and child.target.id == "type"
            ),
            None,
        )
        if type_field is None:
            continue
        values = _string_literals(type_field.annotation) | _string_literals(type_field.value)
        for value in sorted(values):
            result.append(
                {
                    "event_type": value,
                    "model": node.name,
                    "file": _relative(path, root),
                    "line": node.lineno,
                    "fields": [
                        child.target.id
                        for child in node.body
                        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
                    ],
                    "validators": [
                        child.name
                        for child in node.body
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and child.name.startswith("validate")
                        or (
                            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and any(
                                "model_validator" in _json_expression(dec)
                                or "field_validator" in _json_expression(dec)
                                for dec in child.decorator_list
                            )
                        )
                    ],
                }
            )
    return result


def _spec_type_from_test(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = node.left
    if not (
        isinstance(left, ast.Attribute)
        and left.attr == "type"
        and isinstance(left.value, ast.Name)
        and left.value.id == "spec"
    ):
        return None
    values = _string_literals(node.comparators[0])
    return next(iter(values)) if len(values) == 1 else None


def _calls_in_nodes(nodes: Iterable[ast.stmt]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for statement in nodes:
        for child in ast.walk(statement):
            if not isinstance(child, ast.Call):
                continue
            short = _short_call_name(child)
            if short.startswith("generate_") or short.endswith("ActionBundle"):
                calls.append(
                    {
                        "name": short,
                        "call": _call_name(child),
                        "line": child.lineno,
                    }
                )
    return sorted(calls, key=lambda item: (item["line"], item["call"]))


def _storyline_dispatch(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "src/evidenceforge/generation/engine/storyline.py"
    tree = _read_tree(path)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_execute_typed_event"
    )
    result: dict[str, dict[str, Any]] = {}
    current = next((node for node in function.body if isinstance(node, ast.If)), None)
    while current is not None:
        event_type = _spec_type_from_test(current.test)
        if event_type is not None:
            result[event_type] = {
                "file": _relative(path, root),
                "line": current.lineno,
                "calls": _calls_in_nodes(current.body),
            }
        current = (
            current.orelse[0]
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If)
            else None
        )
    return result


def _class_index(python_files: list[Path], root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in python_files:
        tree = _read_tree(path)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                result.setdefault(
                    node.name,
                    {"file": _relative(path, root), "line": node.lineno, "node": node},
                )
    return result


def _emitter_class_map(root: Path) -> dict[str, str]:
    path = root / "src/evidenceforge/generation/engine/emitter_setup.py"
    tree = _read_tree(path)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_emitter_classes"
    )
    return_node = next(node for node in ast.walk(function) if isinstance(node, ast.Return))
    if not isinstance(return_node.value, ast.Dict):
        return {}
    result = {}
    for key, value in zip(return_node.value.keys, return_node.value.values, strict=True):
        names = _string_literals(key)
        if len(names) == 1:
            result[next(iter(names))] = _json_expression(value)
    return result


def _class_string_set(node: ast.ClassDef, field_name: str) -> list[str]:
    for child in node.body:
        target_name = ""
        value: ast.AST | None = None
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            target_name = child.target.id
            value = child.value
        elif (
            isinstance(child, ast.Assign)
            and len(child.targets) == 1
            and isinstance(child.targets[0], ast.Name)
        ):
            target_name = child.targets[0].id
            value = child.value
        if target_name == field_name:
            return sorted(_string_literals(value))
    return []


def _bundle_inventory(
    root: Path,
    class_index: dict[str, dict[str, Any]],
    bundle_call_sites: dict[str, list[dict[str, Any]]],
    test_names: dict[str, set[str]],
) -> list[dict[str, Any]]:
    result = []
    for name, entry in sorted(class_index.items()):
        if not name.endswith("ActionBundle") or name == "ActionBundle":
            continue
        node: ast.ClassDef = entry["node"]
        methods = {
            child.name: child
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        delegate_calls = []
        dispatch_calls = []
        generation_calls = []
        for child in node.body:
            for item in ast.walk(child):
                if not isinstance(item, ast.Call):
                    continue
                short = _short_call_name(item)
                record = {"call": _call_name(item), "line": item.lineno}
                if short.startswith("_execute_"):
                    delegate_calls.append(record)
                if short in {"dispatch", "dispatch_builder", "dispatch_raw"}:
                    dispatch_calls.append(record)
                if short.startswith("generate_"):
                    generation_calls.append(record)
        execute = methods.get("execute")
        result.append(
            {
                "name": name,
                "file": entry["file"],
                "line": entry["line"],
                "has_anchor": "anchor" in methods,
                "execute_return": (
                    _json_expression(execute.returns) if execute is not None else ""
                ),
                "delegate_calls": sorted(delegate_calls, key=lambda item: item["line"]),
                "dispatch_calls": sorted(dispatch_calls, key=lambda item: item["line"]),
                "generation_calls": sorted(generation_calls, key=lambda item: item["line"]),
                "call_sites": bundle_call_sites.get(name, []),
                "test_files": sorted(test_names.get(name, set())),
                "review_status": "static_inventory_complete",
            }
        )
    return result


def _test_references(
    test_files: list[Path], root: Path
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    string_files: defaultdict[str, set[str]] = defaultdict(set)
    name_files: defaultdict[str, set[str]] = defaultdict(set)
    for path in test_files:
        relative = _relative(path, root)
        tree = _read_tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                string_files[node.value].add(relative)
            elif isinstance(node, ast.Name):
                name_files[node.id].add(relative)
    return string_files, name_files


def _source_text_references(
    files: Iterable[Path], root: Path, terms: Iterable[str]
) -> dict[str, list[str]]:
    terms_list = list(terms)
    result: defaultdict[str, list[str]] = defaultdict(list)
    for path in files:
        text = path.read_text(encoding="utf-8")
        relative = _relative(path, root)
        for term in terms_list:
            if term in text:
                result[term].append(relative)
    return {key: sorted(set(value)) for key, value in sorted(result.items())}


def _git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _dynamic_constructor_types(
    constructor: dict[str, Any],
    emitter_event_types: set[str],
) -> set[str]:
    """Resolve the finite event-type domain for known dynamic constructor expressions."""

    expression = constructor["event_type_expression"]
    scope = constructor["scope"]
    if "_FILE_ACTION_EVENT_TYPES" in expression or scope.endswith(
        ("_execute_process_create_bundle", "_emit_smb_file_operations", "_emit_ecar_file_churn")
    ):
        return {"file_create", "file_delete", "file_modify", "file_read"}
    if scope.endswith("_execute_scheduled_task_bundle"):
        return {name for name in emitter_event_types if name.startswith("scheduled_task_")}
    if scope.endswith("_execute_group_membership_change_bundle"):
        return {name for name in emitter_event_types if name.startswith("group_member_")}
    if scope.endswith("SmbActivityActionBundle._emit_phase"):
        return {name for name in emitter_event_types if name.startswith("smb_")} | {
            "smb_directory_enumeration"
        }
    if scope.endswith("NetworkTransactionPlanner._deferred_session_dependent_builders"):
        if "process" in constructor["contexts_attached_at_construction"]:
            return {"process_create", "system_process_create"}
        return {"logon", "rdp_reconnect", "ssh_session"}
    return set()


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _classification_index(
    data: dict[str, Any],
    section: str,
) -> dict[str, dict[str, Any]]:
    """Expand grouped review decisions into one entry per reviewed row."""

    result: dict[str, dict[str, Any]] = {}
    for group in data.get(section, []):
        decision = {key: value for key, value in group.items() if key != "names"}
        for name in group.get("names", []):
            if name in result:
                raise ValueError(f"duplicate {section} path classification for {name}")
            result[name] = decision
    return result


def _apply_classifications(
    rows: list[dict[str, Any]],
    *,
    key: str,
    section: str,
    data: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Attach reviewed decisions and return missing and unknown classification keys."""

    index = _classification_index(data, section)
    row_names = {row[key] for row in rows}
    for row in rows:
        decision = index.get(row[key])
        if decision is None:
            row["path_classification"] = "pending_manual_trace"
            continue
        row["path_review"] = decision
        row["path_classification"] = decision["classification"]
        row["review_status"] = "path_review_complete"
    return sorted(row_names - set(index)), sorted(set(index) - row_names)


def _build_inventory(
    root: Path,
    classifications_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    src_files = sorted((root / "src/evidenceforge").rglob("*.py"))
    test_files = sorted((root / "tests").rglob("*.py"))
    all_python_files = [*src_files, *test_files]
    fields = _builder_fields(root)
    field_names = {field["name"] for field in fields}
    payload_field_names = {
        field["name"]
        for field in fields
        if field["name"]
        not in {
            "timestamp",
            "event_type",
            "local_only",
            "storyline_origin",
            "storyline_cluster_id",
            "event_id",
            "occurrence_key",
            "contract_seal",
            "network_observations_planned",
        }
        and not field["name"].startswith("_")
    }

    visitors: list[SourceIndexVisitor] = []
    for path in all_python_files:
        visitor = SourceIndexVisitor(path, root, field_names, payload_field_names)
        visitor.visit(_read_tree(path))
        visitors.append(visitor)

    constructors = [
        item
        for visitor in visitors
        if visitor.path in src_files
        for item in visitor.occurrence_builder_constructors
    ]
    context_constructors: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    bundle_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    generate_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    dispatch_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    state_calls: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    field_reads: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    event_type_refs: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for visitor in visitors:
        if visitor.path not in src_files:
            continue
        for target, destination in (
            (visitor.context_constructors, context_constructors),
            (visitor.bundle_calls, bundle_calls),
            (visitor.generate_calls, generate_calls),
            (visitor.dispatch_calls, dispatch_calls),
            (visitor.state_calls, state_calls),
            (visitor.event_field_reads, field_reads),
            (visitor.event_type_references, event_type_refs),
        ):
            for key, values in target.items():
                destination[key].extend(values)

    class_index = _class_index(src_files, root)
    string_tests, name_tests = _test_references(test_files, root)
    authored = _authored_event_specs(root)
    storyline = _storyline_dispatch(root)

    emitter_map = _emitter_class_map(root)
    emitter_rows = []
    emitter_formats_by_type: defaultdict[str, list[str]] = defaultdict(list)
    emitter_formats_by_field: defaultdict[str, list[str]] = defaultdict(list)
    evaluation_files = [path for path in src_files if "/evaluation/" in path.as_posix()]
    evaluation_refs = _source_text_references(evaluation_files, root, emitter_map)
    for format_name, class_name in sorted(emitter_map.items()):
        entry = class_index.get(class_name)
        supported_types: list[str] = []
        consumed_fields: list[str] = []
        if entry is not None:
            node = entry["node"]
            supported_types = _class_string_set(node, "_supported_types")
            class_lines = range(node.lineno, (node.end_lineno or node.lineno) + 1)
            consumed_fields = sorted(
                field
                for field, locations in field_reads.items()
                if any(
                    location["file"] == entry["file"] and location["line"] in class_lines
                    for location in locations
                )
            )
        for event_type in supported_types:
            emitter_formats_by_type[event_type].append(format_name)
        for field in consumed_fields:
            emitter_formats_by_field[field].append(format_name)
        emitter_rows.append(
            {
                "format": format_name,
                "definition": f"src/evidenceforge/config/formats/{format_name}.yaml",
                "emitter_class": class_name,
                "emitter_file": entry["file"] if entry is not None else None,
                "emitter_line": entry["line"] if entry is not None else None,
                "supported_event_types": supported_types,
                "occurrence_builder_fields_consumed": consumed_fields,
                "evaluator_files": evaluation_refs.get(format_name, []),
                "test_files": sorted(string_tests.get(format_name, set())),
                "review_status": "static_inventory_complete",
            }
        )

    emitter_contract_event_types = set(emitter_formats_by_type)
    constructor_types: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    dynamic_constructors = []
    resolved_dynamic_constructors = []
    for constructor in constructors:
        values = constructor["event_type_literals"]
        if values:
            for value in values:
                constructor_types[value].append(constructor)
        else:
            dynamic_constructors.append(constructor)
            resolved_types = _dynamic_constructor_types(constructor, emitter_contract_event_types)
            if resolved_types:
                resolved = {**constructor, "resolved_dynamically": True}
                for value in resolved_types:
                    constructor_types[value].append(resolved)
                resolved_dynamic_constructors.append(
                    {**constructor, "resolved_event_types": sorted(resolved_types)}
                )

    producer_event_types = set(constructor_types) | set(event_type_refs)
    internal_event_types = sorted(producer_event_types | emitter_contract_event_types)
    event_rows = []
    authored_by_type = {row["event_type"]: row for row in authored}
    all_event_types = sorted(set(internal_event_types) | set(authored_by_type))
    for event_type in all_event_types:
        authored_row = authored_by_type.get(event_type)
        constructor_rows = constructor_types.get(event_type, [])
        storyline_row = storyline.get(event_type)
        contexts = sorted(
            {
                context
                for row in constructor_rows
                for context in row["contexts_attached_at_construction"]
            }
        )
        event_rows.append(
            {
                "event_type": event_type,
                "kind": (
                    "authored_and_internal"
                    if authored_row is not None and event_type in producer_event_types
                    else "authored_intent"
                    if authored_row is not None
                    else "emitter_only_contract"
                    if event_type not in producer_event_types
                    else "internal_occurrence"
                ),
                "authored_spec": authored_row,
                "storyline_dispatch": storyline_row,
                "constructors": constructor_rows,
                "contexts_attached_at_literal_constructors": contexts,
                "emitter_consumers": sorted(emitter_formats_by_type.get(event_type, [])),
                "static_references": event_type_refs.get(event_type, []),
                "test_files": sorted(string_tests.get(event_type, set())),
                "review_status": "static_inventory_complete",
                "path_classification": "pending_manual_trace",
            }
        )

    context_path = root / "src/evidenceforge/events/contexts.py"
    context_dataclasses = _dataclass_inventory(context_path, root)
    contexts = []
    for row in context_dataclasses:
        event_slots = sorted(
            field["name"] for field in fields if row["name"] in field["annotation"]
        )
        consumers = sorted(
            {location["file"] for slot in event_slots for location in field_reads.get(slot, [])}
        )
        contexts.append(
            {
                **row,
                "occurrence_builder_slots": event_slots,
                "constructors": context_constructors.get(row["name"], []),
                "emitter_consumers": sorted(
                    {
                        format_name
                        for slot in event_slots
                        for format_name in emitter_formats_by_field.get(slot, [])
                    }
                ),
                "source_consumer_files": consumers,
                "test_files": sorted(name_tests.get(row["name"], set())),
                "review_status": "static_inventory_complete",
                "path_classification": "pending_manual_trace",
            }
        )

    plan_paths = [
        root / "src/evidenceforge/events/identity.py",
        root / "src/evidenceforge/events/lifecycle.py",
        root / "src/evidenceforge/events/network.py",
        root / "src/evidenceforge/events/authentication.py",
        root / "src/evidenceforge/events/cryptography.py",
        root / "src/evidenceforge/events/proxy.py",
        root / "src/evidenceforge/events/protocol.py",
        root / "src/evidenceforge/generation/world_model.py",
        root / "src/evidenceforge/generation/timing/constraint_graph.py",
        root / "src/evidenceforge/generation/source_timing.py",
        root / "src/evidenceforge/generation/causal/timing.py",
        root / "src/evidenceforge/generation/actions/base.py",
    ]
    plans = []
    for path in plan_paths:
        for row in _dataclass_inventory(path, root):
            if not (
                row["name"].endswith("Plan")
                or row["name"].endswith("Identity")
                or row["name"]
                in {
                    "ActionAnchor",
                    "DirectionalTrafficLedger",
                    "NetworkTrafficLedger",
                    "NetworkTuple",
                    "NetworkSensorObservation",
                    "TemporalConstraint",
                    "TemporalNode",
                    "HostWorld",
                    "UserWorld",
                    "DatabaseEndpoint",
                    "SessionBootstrapResult",
                    "TimingSpec",
                }
            ):
                continue
            event_slots = sorted(
                field["name"] for field in fields if row["name"] in field["annotation"]
            )
            plans.append(
                {
                    **row,
                    "occurrence_builder_slots": event_slots,
                    "constructors": context_constructors.get(row["name"], []),
                    "test_files": sorted(name_tests.get(row["name"], set())),
                    "review_status": "static_inventory_complete",
                    "path_classification": "pending_manual_trace",
                }
            )

    bundles = _bundle_inventory(root, class_index, bundle_calls, name_tests)
    generated_call_counts = Counter(
        {name: len(locations) for name, locations in generate_calls.items()}
    )
    high_fanout = [
        {"method": name, "static_call_sites": count, "locations": generate_calls[name]}
        for name, count in generated_call_counts.most_common()
    ]

    classification_data = (
        json.loads(classifications_path.read_text(encoding="utf-8"))
        if classifications_path.exists()
        else {}
    )
    classification_gaps: dict[str, dict[str, list[str]]] = {}
    for section, rows, key in (
        ("events", event_rows, "event_type"),
        ("contexts", contexts, "name"),
        ("plans_and_identities", plans, "name"),
        ("action_bundles", bundles, "name"),
        ("formats", emitter_rows, "format"),
    ):
        missing, unknown = _apply_classifications(
            rows,
            key=key,
            section=section,
            data=classification_data,
        )
        classification_gaps[section] = {"missing": missing, "unknown": unknown}

    inventory = {
        "schema_version": "evidenceforge-realism-review-paths/v2",
        "baseline_commit": _git_commit(root),
        "method": "python-ast-static-inventory",
        "review_scope": {
            "source_python_files": len(src_files),
            "test_python_files": len(test_files),
            "phase_1_skills": "excluded_except_schema_contract",
            "raw_cross_source_guarantee": "excluded",
        },
        "occurrence_builder": {
            "file": "src/evidenceforge/events/base.py",
            "fields": fields,
            "payload_field_names": sorted(payload_field_names),
            "constructors": constructors,
            "dynamic_event_type_constructors": dynamic_constructors,
        },
        "authored_events": authored,
        "events": event_rows,
        "contexts": contexts,
        "plans_and_identities": sorted(plans, key=lambda row: (row["file"], row["line"])),
        "action_bundles": bundles,
        "formats": emitter_rows,
        "orchestration": {
            "generate_method_call_sites": high_fanout,
            "dispatch_call_sites": {key: value for key, value in sorted(dispatch_calls.items())},
            "state_manager_call_sites": {key: value for key, value in sorted(state_calls.items())},
        },
    }

    unresolved = {
        "authored_without_storyline_dispatch": sorted(
            row["event_type"] for row in authored if row["event_type"] not in storyline
        ),
        "internal_consumer_without_literal_constructor": sorted(
            event_type for event_type in internal_event_types if event_type not in constructor_types
        ),
        "emitter_contract_types_without_producer": sorted(
            event_type
            for event_type in emitter_contract_event_types
            if event_type not in producer_event_types
        ),
        "contexts_without_source_constructor": sorted(
            row["name"] for row in contexts if not row["constructors"]
        ),
        "contexts_without_emitter_consumer": sorted(
            row["name"] for row in contexts if not row["emitter_consumers"]
        ),
        "bundles_without_anchor": sorted(row["name"] for row in bundles if not row["has_anchor"]),
        "bundles_without_static_call_site": sorted(
            row["name"] for row in bundles if not row["call_sites"]
        ),
        "formats_without_emitter_class": sorted(
            row["format"] for row in emitter_rows if row["emitter_file"] is None
        ),
        "formats_without_test_reference": sorted(
            row["format"] for row in emitter_rows if not row["test_files"]
        ),
        "dynamic_event_type_constructor_count": len(dynamic_constructors),
        "resolved_dynamic_event_type_constructors": resolved_dynamic_constructors,
        "unresolved_dynamic_event_type_constructors": [
            constructor
            for constructor in dynamic_constructors
            if not _dynamic_constructor_types(constructor, emitter_contract_event_types)
        ],
    }
    coverage = {
        "schema_version": "evidenceforge-realism-review-coverage/v2",
        "baseline_commit": inventory["baseline_commit"],
        "counts": {
            "authored_event_specs": len(authored),
            "discovered_event_types": len(event_rows),
            "literal_internal_event_types": len(constructor_types),
            "dynamic_occurrence_builder_constructors": len(dynamic_constructors),
            "occurrence_builder_constructors": len(constructors),
            "occurrence_builder_fields": len(fields),
            "mutable_context_dataclasses": len(contexts),
            "plans_and_identities": len(plans),
            "concrete_action_bundles": len(bundles),
            "concrete_formats": len(emitter_rows),
            "generate_methods_with_call_sites": len(generate_calls),
            "state_manager_methods_with_call_sites": len(state_calls),
        },
        "coverage": {
            "authored_with_storyline_dispatch": sum(
                row["event_type"] in storyline for row in authored
            ),
            "authored_with_tests": sum(
                bool(string_tests.get(row["event_type"])) for row in authored
            ),
            "internal_with_literal_constructor": len(constructor_types),
            "contexts_with_source_constructor": sum(bool(row["constructors"]) for row in contexts),
            "contexts_with_emitter_consumer": sum(
                bool(row["emitter_consumers"]) for row in contexts
            ),
            "contexts_with_tests": sum(bool(row["test_files"]) for row in contexts),
            "bundles_with_anchor": sum(bool(row["has_anchor"]) for row in bundles),
            "bundles_with_call_site": sum(bool(row["call_sites"]) for row in bundles),
            "bundles_with_tests": sum(bool(row["test_files"]) for row in bundles),
            "formats_with_emitter_class": sum(
                row["emitter_file"] is not None for row in emitter_rows
            ),
            "formats_with_tests": sum(bool(row["test_files"]) for row in emitter_rows),
            "formats_with_evaluator_reference": sum(
                bool(row["evaluator_files"]) for row in emitter_rows
            ),
        },
        "unresolved_static_inventory": unresolved,
        "path_classification_gaps": classification_gaps,
        "review_state": {
            "static_inventory": "complete",
            "manual_path_classification": (
                "complete"
                if classification_data
                and not any(
                    gaps[status]
                    for gaps in classification_gaps.values()
                    for status in ("missing", "unknown")
                )
                else "pending"
            ),
            "dynamic_probe_coverage": "pending",
            "source_reference_coverage": "pending",
        },
    }
    return inventory, coverage


def main(argv: list[str] | None = None) -> int:
    """Run the review inventory extractor."""

    args = _parse_args(sys.argv[1:] if argv is None else argv)
    root = args.repo_root.resolve()
    output = (
        args.output.resolve()
        if args.output is not None
        else root / "docs/design/realism-review/event-context-paths.json"
    )
    coverage_output = (
        args.coverage_output.resolve()
        if args.coverage_output is not None
        else root / "docs/design/realism-review/coverage-summary.json"
    )
    classifications_path = (
        args.classifications.resolve()
        if args.classifications is not None
        else root / "docs/design/realism-review/path-classifications.json"
    )
    inventory, coverage = _build_inventory(root, classifications_path)
    _write_json(output, inventory)
    _write_json(coverage_output, coverage)
    print(f"Wrote {output}")
    print(f"Wrote {coverage_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
