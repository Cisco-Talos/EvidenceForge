"""Case loading and deterministic completeness oracles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import CaseDefinition, OracleRequirement

EXPERIMENT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = EXPERIMENT_ROOT.parents[1]
CASES_PATH = EXPERIMENT_ROOT / "cases.yaml"


def load_cases(suite: str) -> list[CaseDefinition]:
    """Load cases for one suite in stable file order."""

    if suite not in {"smoke", "full"}:
        raise ValueError(f"unknown suite: {suite}")
    payload = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("cases.yaml must contain a cases list")
    cases = [CaseDefinition.model_validate(item) for item in payload["cases"]]
    selected = [case for case in cases if suite in case.suites]
    if not selected:
        raise ValueError(f"suite has no cases: {suite}")
    identifiers = [case.id for case in selected]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"duplicate case identifiers in suite: {suite}")
    return selected


def load_yaml_document(path: Path) -> dict[str, Any]:
    """Load a YAML mapping for completeness analysis."""

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return value


def _values_at_path(value: Any, parts: list[str]) -> list[Any]:
    if not parts:
        return [value]
    head, *tail = parts
    if head == "*":
        if not isinstance(value, list):
            return []
        return [found for item in value for found in _values_at_path(item, tail)]
    if not isinstance(value, dict) or head not in value:
        return []
    return _values_at_path(value[head], tail)


def requirement_satisfied(document: dict[str, Any], requirement: OracleRequirement) -> bool:
    """Evaluate a declarative completeness predicate."""

    values = _values_at_path(document, requirement.path.split("."))
    if requirement.predicate == "exists":
        return bool(values) and all(value is not None for value in values)
    if requirement.predicate == "equals":
        return bool(values) and any(value == requirement.expected for value in values)
    if requirement.predicate == "any_equals":
        return any(value == requirement.expected for value in values)
    if requirement.predicate == "contains":
        return any(
            requirement.expected in value
            for value in values
            if isinstance(value, (str, list, tuple, set, dict))
        )
    if requirement.predicate == "min_items":
        minimum = int(requirement.expected)
        return bool(values) and any(
            isinstance(value, list) and len(value) >= minimum for value in values
        )
    raise ValueError(f"unsupported predicate: {requirement.predicate}")


def incomplete_requirements(document: dict[str, Any], case: CaseDefinition) -> list[str]:
    """Return stable identifiers for unmet case requirements."""

    return [
        requirement.id
        for requirement in case.requirements
        if not requirement_satisfied(document, requirement)
    ]


def resolve_fixture(relative: str) -> Path:
    """Resolve a case fixture beneath the repository without allowing escape."""

    candidate = (REPOSITORY_ROOT / relative).resolve()
    if REPOSITORY_ROOT.resolve() not in candidate.parents:
        raise ValueError(f"fixture escapes repository: {relative}")
    return candidate
