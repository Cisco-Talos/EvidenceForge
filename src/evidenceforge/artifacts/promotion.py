"""Reviewed draft dependency promotion, including qualified namespace rewrites."""

from __future__ import annotations

import difflib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.schema import identify_document
from evidenceforge.utils import load_scenario_source_graph

from .lifecycle import (
    ArtifactError,
    _capture_sources,
    _edit_envelope,
    _publication_lock,
    _receipt_root,
    _remap_namespace,
    _write_files,
    resolve_reference,
    verify_release,
)


def promote_dependency(
    source: Path, release: Path, *, project_root: Path, draft_id: str, apply: bool = False
) -> dict[str, Any]:
    """Preview or explicitly accept an exact published dependency and its catalog remapping."""
    source = resolve_reference(source, project_root)
    release = resolve_reference(release, project_root)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    if not contract.lifecycle or contract.lifecycle.status != "draft":
        raise ArtifactError("dependency promotion requires an editable Schema 3 draft")
    root = _receipt_root(release)
    if root is None:
        raise ArtifactError("select a published pack with an integrity receipt")
    receipt = verify_release(root)
    if receipt.kind == "scenario":
        raise ArtifactError("a scenario cannot serve as a pack dependency")
    changes: dict[str, Any] = {}
    references: list[dict[str, Any]]
    if contract.family == "scenario":
        composition = json.loads(json.dumps(graph.data.get("composition") or {}))
        references = [
            *composition.get("industries", []),
            *([composition["organization"]] if composition.get("organization") else []),
        ]
        changes["composition"] = composition
    else:
        references = json.loads(json.dumps(graph.data.get("industry_dependencies") or []))
        changes["industry_dependencies"] = references
    old_name: str | None = None
    for reference in references:
        if reference.get("source") != "draft" or reference.get("draft_id") != draft_id:
            continue
        old_name = reference["name"]
        reference.clear()
        reference.update(
            {
                "source": "path",
                "publisher": receipt.lifecycle.publisher,
                "name": receipt.name,
                "path": str(release.parent),
            }
        )
        if contract.family == "scenario":
            reference["version"] = receipt.lifecycle.version
        else:
            reference["type"] = "industry"
            reference["version_constraint"] = f"=={receipt.lifecycle.version}"
    if old_name is None:
        raise ArtifactError("the selected draft dependency is not referenced by this artifact")
    files, entry, base = _capture_sources(source, contract.family)
    edited = _edit_envelope(files, entry, graph, base, changes)
    edited = _remap_namespace(
        edited, f"draft-{draft_id}/{old_name}", f"{receipt.lifecycle.publisher}/{receipt.name}"
    )
    staging = Path(tempfile.mkdtemp(prefix=".promotion-", dir=source.parent.parent)).resolve()
    try:
        _write_files(staging, edited)
        if contract.family == "pack":
            from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference

            # A sibling staging directory has different relative origins. Resolve unchanged
            # references against their original declaring files for validation only.
            validation_dependencies = json.loads(json.dumps(references))
            for index, dependency in enumerate(validation_dependencies):
                if dependency.get("source") in {"path", "draft"} and dependency.get("path"):
                    owner = graph.origins.get(("industry_dependencies", str(index), "path"), source)
                    dependency["path"] = str((owner.parent / dependency["path"]).resolve())
            validation_files = _edit_envelope(
                edited, entry, graph, base, {"industry_dependencies": validation_dependencies}
            )
            for name, content in validation_files.items():
                if content != edited[name]:
                    (staging / name).write_bytes(content)
            reference, kind = parse_pack_cli_reference(str(staging / entry))
            repository = PackRepository(project_root)
            loaded = repository.resolve(reference, expected_type=kind)
            lock = repository.proposed_lock(loaded)
            edited["pack.lock.yaml"] = yaml.safe_dump(
                lock.model_dump(mode="json"), sort_keys=False
            ).encode()
        diffs = {
            name: "".join(
                difflib.unified_diff(
                    files.get(name, b"").decode().splitlines(True),
                    content.decode().splitlines(True),
                    fromfile=name,
                    tofile=name,
                )
            )
            for name, content in edited.items()
            if files.get(name) != content
        }
        if apply:
            with _publication_lock(project_root):
                current, _, _ = _capture_sources(source, contract.family)
                if current != files:
                    raise ArtifactError(
                        "draft changed after promotion preview; review the new comparison"
                    )
                originals: dict[Path, bytes | None] = {}
                try:
                    for name in diffs:
                        target = base / name
                        originals[target] = target.read_bytes() if target.exists() else None
                        temporary = target.with_name(f".{target.name}.promotion")
                        with temporary.open("xb") as stream:
                            stream.write(edited[name])
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(temporary, target)
                except OSError:
                    for target, content in originals.items():
                        if content is None:
                            target.unlink(missing_ok=True)
                        else:
                            target.write_bytes(content)
                    raise
        return {"applied": apply, "release": receipt.model_dump(mode="json"), "diffs": diffs}
    finally:
        shutil.rmtree(staging)
