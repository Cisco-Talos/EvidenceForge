# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical resolved-scenario and generation-manifest artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from evidenceforge import __version__
from evidenceforge.models.exceptions import GenerationError, SchemaValidationError

from .models import (
    CompiledScenario,
    EffectiveConfig,
    GenerationManifestDocument,
    ResolvedScenarioDocument,
)

RESOLVED_SCENARIO_FILENAME = "RESOLVED_SCENARIO.yaml"
GENERATION_MANIFEST_FILENAME = "GENERATION_MANIFEST.json"


class _NoAliasDumper(yaml.SafeDumper):
    """Safe canonical dumper that never emits machine-dependent aliases."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


def _represent_readable_string(
    dumper: _NoAliasDumper,
    value: str,
) -> yaml.ScalarNode:
    """Render multiline strings literally so physical lines match their value."""

    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_NoAliasDumper.add_representer(str, _represent_readable_string)


def _canonical_json_bytes(value: Any) -> bytes:
    """Encode a JSON-compatible value canonically for integrity hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _resolved_integrity_payload(document: ResolvedScenarioDocument) -> dict[str, Any]:
    """Return the non-self-referential resolved-document integrity payload."""

    payload = document.model_dump(mode="json")
    payload["digests"] = {
        key: value for key, value in payload["digests"].items() if key != "resolved_document_sha256"
    }
    return payload


def build_resolved_document(compiled: CompiledScenario) -> ResolvedScenarioDocument:
    """Build the authoritative document and its canonical content digest."""

    document = ResolvedScenarioDocument(
        scenario=compiled.scenario.model_dump(mode="json"),
        effective_config=compiled.effective_config.model_dump(mode="json"),
        assets=compiled.assets,
        provenance={
            **compiled.provenance,
            "selected_packs": [pack.model_dump(mode="json") for pack in compiled.selected_packs],
        },
        digests=dict(compiled.digests),
    )
    digest = hashlib.sha256(
        _canonical_json_bytes(_resolved_integrity_payload(document))
    ).hexdigest()
    return document.model_copy(
        update={"digests": {**document.digests, "resolved_document_sha256": digest}}
    )


def verify_resolved_document(document: ResolvedScenarioDocument) -> None:
    """Reject a resolved document whose authoritative payload was modified."""

    expected = document.digests.get("resolved_document_sha256")
    if not expected:
        raise SchemaValidationError("resolved document is missing resolved_document_sha256")
    actual = hashlib.sha256(
        _canonical_json_bytes(_resolved_integrity_payload(document))
    ).hexdigest()
    if actual != expected:
        raise SchemaValidationError(
            "resolved document digest mismatch; the authoritative input was modified"
        )


def serialize_resolved_document(document: ResolvedScenarioDocument) -> bytes:
    """Serialize canonical UTF-8/LF YAML without aliases or timestamps."""

    text = yaml.dump(
        document.model_dump(mode="json"),
        Dumper=_NoAliasDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=100,
    )
    return text.replace("\r\n", "\n").encode("utf-8")


def write_resolved_scenario(compiled: CompiledScenario, output_root: Path) -> Path:
    """Write or verify the authoritative resolved scenario in one output bundle."""

    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / RESOLVED_SCENARIO_FILENAME
    if destination.is_symlink():
        raise GenerationError(f"refusing to write resolved scenario through symlink: {destination}")
    content = serialize_resolved_document(build_resolved_document(compiled))
    if destination.exists():
        existing = destination.read_bytes()
        if existing == content:
            return destination
        raise GenerationError(
            f"authoritative resolved scenario already exists with different content: {destination}"
        )
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_bytes(content)
    temporary.replace(destination)
    return destination


def _bundle_file_hashes(output_root: Path) -> dict[str, str]:
    """Hash the central registry's engine-owned bundle payload."""

    from .sidecars import SIDECAR_REGISTRY

    try:
        return SIDECAR_REGISTRY.hashes(output_root)
    except PermissionError as exc:
        raise GenerationError(str(exc)) from exc


def write_generation_manifest(
    compiled: CompiledScenario,
    output_root: Path,
    *,
    output_target: str,
    formats: list[str],
    oob_hosts: tuple[str, ...] = (),
    overrides: dict[str, Any] | None = None,
    effect_reconciliation: dict[str, int | str | bool] | None = None,
) -> Path:
    """Write the run identity last, after hashing every other bundle file."""

    destination = output_root / GENERATION_MANIFEST_FILENAME
    if destination.is_symlink():
        raise GenerationError(
            f"refusing to write generation manifest through symlink: {destination}"
        )
    resolved_path = output_root / RESOLVED_SCENARIO_FILENAME
    if not resolved_path.is_file():
        raise GenerationError(
            f"resolved scenario is missing before manifest write: {resolved_path}"
        )
    payload = {
        "kind": "evidenceforge.generation-manifest",
        "schema_version": "1.0",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "evidenceforge_version": __version__,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.system().lower(),
        },
        "scenario": compiled.scenario.name,
        "generation_seed": compiled.scenario.generation_seed,
        "output_target": output_target,
        "formats": sorted(formats),
        "oob_hosts": list(oob_hosts),
        "overrides": overrides or {},
        "selected_packs": [pack.model_dump(mode="json") for pack in compiled.selected_packs],
        "compiled_sha256": compiled.digests.get("compiled_sha256"),
        "resolved_file_sha256": hashlib.sha256(resolved_path.read_bytes()).hexdigest(),
        "files": _bundle_file_hashes(output_root),
    }
    if effect_reconciliation is not None:
        payload["effect_reconciliation"] = effect_reconciliation
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(destination)
    return destination


def verify_generation_bundle(output_root: Path) -> dict[str, Any]:
    """Verify the adjacent manifest and resolved scenario before evaluation."""

    manifest_path = output_root / GENERATION_MANIFEST_FILENAME
    resolved_path = output_root / RESOLVED_SCENARIO_FILENAME
    if not manifest_path.is_file() or not resolved_path.is_file():
        raise FileNotFoundError("authoritative generation artifacts are not present")
    try:
        manifest_document = GenerationManifestDocument.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    except (ValidationError, ValueError) as exc:
        raise SchemaValidationError(f"invalid generation manifest: {exc}") from exc
    manifest = manifest_document.model_dump(mode="json")
    actual_resolved_hash = hashlib.sha256(resolved_path.read_bytes()).hexdigest()
    if manifest.get("resolved_file_sha256") != actual_resolved_hash:
        raise SchemaValidationError(
            "resolved scenario file hash does not match generation manifest"
        )
    expected_files = manifest.get("files")
    if not isinstance(expected_files, dict):
        raise SchemaValidationError("generation manifest files must be a mapping")
    actual_files = _bundle_file_hashes(output_root)
    if RESOLVED_SCENARIO_FILENAME not in expected_files:
        raise SchemaValidationError("generation manifest does not hash the resolved scenario")
    if actual_files != expected_files:
        missing = sorted(set(expected_files) - set(actual_files))
        changed = sorted(
            path
            for path in set(expected_files) & set(actual_files)
            if expected_files[path] != actual_files[path]
        )
        unexpected = sorted(set(actual_files) - set(expected_files))
        raise SchemaValidationError(
            "generation bundle hash verification failed: "
            f"missing={missing}, changed={changed}, unexpected={unexpected}"
        )
    from evidenceforge.events.ground_truth import (
        GROUND_TRUTH_JSON_FILENAME,
        GroundTruthDocument,
    )

    ground_truth_path = output_root / GROUND_TRUTH_JSON_FILENAME
    if ground_truth_path.is_file():
        try:
            ground_truth = GroundTruthDocument.model_validate_json(
                ground_truth_path.read_text(encoding="utf-8")
            )
        except (ValidationError, ValueError) as exc:
            raise SchemaValidationError(f"invalid ground truth document: {exc}") from exc
        ground_truth_effects = (
            ground_truth.effect_reconciliation.model_dump(mode="json")
            if ground_truth.effect_reconciliation is not None
            else None
        )
        if manifest.get("effect_reconciliation") != ground_truth_effects:
            raise SchemaValidationError(
                "generation manifest and ground truth effect reconciliation disagree"
            )
    return manifest


def minimal_compiled_scenario(scenario: Any) -> CompiledScenario:
    """Build a self-contained compiled wrapper for direct GenerationEngine callers."""

    scenario_payload = scenario.model_dump(mode="json")
    effective = EffectiveConfig(project_root=".", ambient_overlay_compat=True)
    scenario_hash = hashlib.sha256(_canonical_json_bytes(scenario_payload)).hexdigest()
    effective_hash = hashlib.sha256(
        _canonical_json_bytes(effective.model_dump(mode="json"))
    ).hexdigest()
    compiled_hash = hashlib.sha256(
        _canonical_json_bytes(
            {"scenario": scenario_payload, "effective_config": effective.model_dump(mode="json")}
        )
    ).hexdigest()
    return CompiledScenario(
        scenario=scenario,
        effective_config=effective,
        provenance={"authored_kind": "direct-runtime-scenario"},
        digests={
            "scenario_sha256": scenario_hash,
            "effective_config_sha256": effective_hash,
            "compiled_sha256": compiled_hash,
        },
        authored_kind="scenario-1.0" if scenario.version == "1.0" else "scenario-2.0",
    )
