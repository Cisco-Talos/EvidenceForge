"""Review and save exact pack choices in mutable scenario sources."""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import (
    _publication_lock,
    _safe_path,
    assert_mutable,
    canonical_bytes,
)
from evidenceforge.composition.compiler import compile_scenario_graph
from evidenceforge.composition.models import (
    CompiledScenario,
    CompositionSpec,
    PackReference,
    SelectedPack,
)
from evidenceforge.composition.packs import parse_pack_cli_reference
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.schema import identify_document
from evidenceforge.schema.upgrades import update_top_level
from evidenceforge.studio.contexts import context_path
from evidenceforge.studio.state_io import atomic_write
from evidenceforge.utils import LoadedSourceGraph, load_scenario_source_graph


class ScenarioPackEdit(BaseModel):
    """An exact selection, with a revision supplied only when applying."""

    model_config = ConfigDict(extra="forbid")
    references: list[str] = Field(max_length=100)
    revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ScenarioPackReview(BaseModel):
    """Pack and environment changes with findings from ordinary scenario validation."""

    model_config = ConfigDict(extra="forbid")
    revision: str
    changed: bool
    can_apply: bool
    current_references: list[str]
    proposed_packs: list[SelectedPack] = Field(default_factory=list)
    changes: list[str] = Field(default_factory=list)
    overrides: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    error_count: int = 0
    current_error: str = ""


def _exact_reference(ref: PackReference, kind: str) -> str:
    if ref.path:
        return ref.path
    return f"{ref.source}:{ref.publisher}:{kind}:{ref.name}@{ref.version}"


def _declared_references(graph: LoadedSourceGraph) -> list[str]:
    composition = CompositionSpec.model_validate(graph.data.get("composition") or {})
    if composition.organization is not None:
        return [_exact_reference(composition.organization, "organization")]
    return [_exact_reference(ref, "industry") for ref in composition.industries]


def scenario_has_pack(source: Path, reference: str) -> bool:
    """Compare the project suggestion to the scenario's direct declarations."""
    try:
        return reference in _declared_references(load_scenario_source_graph(source))
    except (EvidenceForgeError, OSError, ValueError, yaml.YAMLError):
        return False


def _selection(references: list[str]) -> CompositionSpec:
    organizations: list[PackReference] = []
    industries: list[PackReference] = []
    for reference in references:
        if not re.fullmatch(
            r"(?:package|project):[a-z0-9][a-z0-9.-]*:(?:industry|organization):"
            r"[a-z0-9][a-z0-9-]*@\d+\.\d+\.\d+",
            reference,
        ):
            raise ValueError("Choose an exact installed or bundled release, or prepare in chat")
        ref, kind = parse_pack_cli_reference(reference)
        if kind == "organization":
            organizations.append(ref)
        else:
            industries.append(ref)
    if len(organizations) > 1:
        raise ValueError("Choose one organization pack")
    return CompositionSpec(
        industries=industries, organization=organizations[0] if organizations else None
    )


def _effective_changes(current: CompiledScenario | None, proposed: CompiledScenario) -> list[str]:
    if current is None:
        return []
    before = current.scenario.model_dump(mode="json")
    after = proposed.scenario.model_dump(mode="json")
    changes: list[str] = []
    for category, key in (("users", "username"), ("systems", "hostname"), ("groups", "name")):
        old = {str(row[key]): row for row in before["environment"].get(category) or []}
        new = {str(row[key]): row for row in after["environment"].get(category) or []}
        for label, names in (
            ("Added", new.keys() - old.keys()),
            ("Removed", old.keys() - new.keys()),
            ("Changed", {name for name in old.keys() & new.keys() if old[name] != new[name]}),
        ):
            if names:
                sample = ", ".join(sorted(names)[:12])
                suffix = f" and {len(names) - 12} more" if len(names) > 12 else ""
                changes.append(f"{label} {len(names)} {category} · {sample}{suffix}")
    for field in sorted(before["environment"].keys() | after["environment"].keys()):
        if field not in {"users", "systems", "groups"} and before["environment"].get(
            field
        ) != after["environment"].get(field):
            changes.append(f"Changed environment.{field}")
    if before.get("baseline_activity") != after.get("baseline_activity"):
        changes.append("Changed baseline activity")
    if current.effective_config.catalogs != proposed.effective_config.catalogs:
        changes.append("Changed pack catalogs")
    return changes


def _review(
    source: Path, workspace: Path, references: list[str]
) -> tuple[ScenarioPackReview, LoadedSourceGraph, Path, bytes]:
    from evidenceforge.cli.commands import _validate_compiled_scenario

    assert_mutable(source)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    if contract.family != "scenario" or contract.schema_version not in {"2.0", "3.0"}:
        raise ValueError(
            "Pack changes require an editable Scenario 2.0 or 3.0. Prepare in chat to convert it."
        )
    selection = _selection(references)
    owner = _safe_path(graph.top_level_owner("composition"))
    if not owner.is_relative_to(graph.root.parent):
        raise ValueError(
            "Composition is declared outside the scenario folder. Prepare in chat to review it."
        )
    try:
        current_references = _declared_references(graph)
        changed = references != current_references
    except ValueError:
        current_references = []
        changed = True
    original = next(entry for entry in graph.sources if entry.path == owner)
    composition = selection.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
    edited = (
        update_top_level(
            original.content, {"composition": composition} if composition else {}, {"composition"}
        )
        if changed
        else original.content
    )
    candidate = graph
    if changed:
        candidate = load_scenario_source_graph(source, source_override=(owner, edited))
        if candidate.data.get("composition", {}) != composition or {
            key: value for key, value in candidate.data.items() if key != "composition"
        } != {key: value for key, value in graph.data.items() if key != "composition"}:
            raise ValueError(
                "Could not isolate the composition change. Prepare in chat to review the YAML."
            )
    context = context_path(source, workspace)
    project_root = None if context else workspace
    review = ScenarioPackReview(
        revision="",
        changed=changed,
        can_apply=False,
        current_references=current_references,
    )
    current: CompiledScenario | None = None
    proposed: CompiledScenario | None = None
    try:
        current = compile_scenario_graph(graph, project_root=project_root, context=context)
    except (EvidenceForgeError, OSError, ValueError, yaml.YAMLError) as exc:
        review.current_error = str(exc)
    try:
        proposed = compile_scenario_graph(candidate, project_root=project_root, context=context)
        review.proposed_packs = list(proposed.selected_packs)
        review.changes = _effective_changes(current, proposed)
        review.overrides = list(
            dict.fromkeys(
                row["path"]
                for row in proposed.provenance.get("merge_decisions", [])
                if row.get("winner") == "scenario"
                and row["path"].startswith(("environment", "baseline_activity"))
            )
        )
        _, issues = _validate_compiled_scenario(proposed, (), source.parent)
        actionable = [issue for issue in issues if issue.severity in {"error", "warning"}]
        actionable.sort(key=lambda issue: issue.severity != "error")
        review.error_count = sum(issue.severity == "error" for issue in actionable)
        review.findings = [
            f"[{issue.severity}] {issue.field_path} · {issue.message}"
            + (f" {issue.suggestion}" if issue.suggestion else "")
            for issue in actionable[:40]
        ]
        if len(actionable) > 40:
            review.findings.append(f"{len(actionable) - 40} additional findings")
    except (EvidenceForgeError, OSError, ValueError, yaml.YAMLError) as exc:
        review.error_count = 1
        review.findings = [str(exc)]
    review.can_apply = changed and not review.error_count
    review.revision = hashlib.sha256(
        canonical_bytes(
            {
                "sources": [(str(entry.path), entry.sha256) for entry in graph.sources],
                "refs": references,
                "before": current.digests if current else None,
                "after": proposed.digests if proposed else None,
                "context": str(context) if context else None,
                "review": review.model_dump(mode="json", exclude={"revision"}),
            }
        )
    ).hexdigest()
    return review, graph, owner, edited


def change_scenario_packs(
    source: Path, workspace: Path, edit: ScenarioPackEdit
) -> ScenarioPackReview:
    """Compile and validate a proposal, then write only an unchanged reviewed revision."""
    source = _safe_path(source)
    if not source.is_relative_to(workspace.resolve()):
        raise ValueError("Choose a mutable scenario in this workspace")
    if edit.revision is None:
        return _review(source, workspace, edit.references)[0]

    with _publication_lock(workspace):
        review, graph, owner, content = _review(source, workspace, edit.references)
        if (
            edit.revision != review.revision
            or graph.sources != load_scenario_source_graph(source).sources
        ):
            raise FileExistsError("Scenario inputs changed. Review the pack selection again.")
        if not review.can_apply:
            raise ValueError("Review a valid pack change before applying it.")
        atomic_write(owner, content, mode=stat.S_IMODE(owner.stat().st_mode))
    return review
