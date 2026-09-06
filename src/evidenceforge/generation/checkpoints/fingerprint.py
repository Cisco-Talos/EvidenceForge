"""Output-affecting compatibility fingerprints for generation recovery."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from evidenceforge import __version__
from evidenceforge.composition.artifacts import build_resolved_document
from evidenceforge.composition.models import CompiledScenario

from .behavior import (
    BehaviorChange,
    BehaviorClassification,
    behavior_fingerprint_components,
    classify_behavior_change,
)
from .models import CHECKPOINT_SCHEMA_VERSION

_RUNTIME_DISTRIBUTIONS = (
    "jinja2",
    "json-logic-qubit",
    "pydantic",
    "pytz",
    "pyyaml",
    "typer",
)
_OUTPUT_RESOURCE_SUFFIXES = {".json", ".j2", ".jinja", ".py", ".yaml", ".yml"}
_BUILD_FIELDS = frozenset({"evidenceforge_build_sha256", "evidenceforge_version"})
_RUNTIME_FIELDS = frozenset(
    {
        "dependencies",
        "interpreter_cache_tag",
        "machine",
        "platform",
        "python",
        "python_compiler",
        "python_implementation",
        "sys_byteorder",
    }
)
_BEHAVIOR_FIELDS = frozenset(
    {
        "behavior_history_sha256",
        "behavior_history_start_revision",
        "behavior_manifest_schema",
        "behavior_revision",
        "behavior_surface_sha256",
    }
)
_RUN_IDENTITY_FIELDS = frozenset(
    {"checkpoint_schema", "formats", "oob_hosts", "output_target", "resolved_sha256"}
)


@dataclass(frozen=True)
class ResumeCompatibility:
    """Classified relationship between one checkpoint and the current runtime."""

    level: Literal["exact", "load-compatible", "incompatible"]
    output_equivalence: Literal["exact", "not-guaranteed", "incompatible"]
    component_mismatches: dict[str, dict[str, object]]
    hard_mismatches: tuple[str, ...] = ()
    run_identity: Literal["matched", "mismatched", "not-checked"] = "not-checked"
    behavior_change: BehaviorChange = "unknown"
    confirmation_required: bool = False
    behavior_change_ids: tuple[str, ...] = ()
    behavior_domains: tuple[str, ...] = ()
    behavior_formats: tuple[str, ...] = ()
    behavior_summaries: tuple[str, ...] = ()
    run_differences: dict[str, dict[str, object]] = field(default_factory=dict)
    runtime_differences: dict[str, dict[str, object]] = field(default_factory=dict)
    behavior_differences: dict[str, dict[str, object]] = field(default_factory=dict)
    state_contract_differences: dict[str, dict[str, object]] = field(default_factory=dict)
    reason: str | None = None

    @property
    def can_resume(self) -> bool:
        """Return whether the current runtime may hydrate this checkpoint."""

        return self.level != "incompatible"


def classify_resume_compatibility(
    *,
    stored_fingerprint: str,
    current_fingerprint: str,
    stored_components: object,
    current_components: dict[str, object],
    authoritative_resolved_scenario: bool = False,
) -> ResumeCompatibility:
    """Classify immutable identity, attemptable drift, and behavior risk."""

    if type(stored_components) is not dict:
        if stored_fingerprint == current_fingerprint:
            return ResumeCompatibility(
                level="exact",
                output_equivalence="exact",
                component_mismatches={},
                run_identity="matched",
                behavior_change="exact",
            )
        return ResumeCompatibility(
            level="load-compatible",
            output_equivalence="not-guaranteed",
            component_mismatches={},
            behavior_change="unknown",
            confirmation_required=True,
            reason="checkpoint lacks fingerprint components required for compatibility checking",
        )
    mismatches = {
        key: {
            "stored": stored_components.get(key),
            "current": current_components.get(key),
        }
        for key in sorted(set(stored_components) | set(current_components))
        if stored_components.get(key) != current_components.get(key)
    }
    run_differences = {
        key: value
        for key, value in mismatches.items()
        if key in _RUN_IDENTITY_FIELDS
        and not (authoritative_resolved_scenario and key == "resolved_sha256")
    }
    runtime_differences = {
        key: value for key, value in mismatches.items() if key in _RUNTIME_FIELDS
    }
    behavior_differences = {
        key: value
        for key, value in mismatches.items()
        if key in _BEHAVIOR_FIELDS or key in _BUILD_FIELDS
    }
    known = _RUN_IDENTITY_FIELDS | _RUNTIME_FIELDS | _BEHAVIOR_FIELDS | _BUILD_FIELDS
    state_contract_differences = {
        key: value for key, value in mismatches.items() if key not in known
    }
    hard = tuple(sorted(set(run_differences) | set(state_contract_differences)))
    same_build = stored_components.get("evidenceforge_build_sha256") == current_components.get(
        "evidenceforge_build_sha256"
    )
    behavior: BehaviorClassification = classify_behavior_change(
        same_build=same_build,
        stored_components=stored_components,
    )
    categories = {
        "run_differences": run_differences,
        "runtime_differences": runtime_differences,
        "behavior_differences": behavior_differences,
        "state_contract_differences": state_contract_differences,
    }
    if stored_fingerprint == current_fingerprint:
        if mismatches:
            return ResumeCompatibility(
                level="incompatible",
                output_equivalence="incompatible",
                component_mismatches=mismatches,
                hard_mismatches=tuple(sorted(mismatches)),
                run_identity="mismatched",
                behavior_change="unknown",
                **categories,
                reason="checkpoint fingerprint and component metadata disagree",
            )
        return ResumeCompatibility(
            level="exact",
            output_equivalence="exact",
            component_mismatches={},
            run_identity="matched",
            behavior_change="exact",
            run_differences={},
            runtime_differences={},
            behavior_differences={},
            state_contract_differences={},
        )
    if hard:
        return ResumeCompatibility(
            level="incompatible",
            output_equivalence="incompatible",
            component_mismatches=mismatches,
            hard_mismatches=hard,
            run_identity="mismatched" if run_differences else "matched",
            behavior_change=behavior.change,
            behavior_change_ids=behavior.change_ids,
            behavior_domains=behavior.domains,
            behavior_formats=behavior.formats,
            behavior_summaries=behavior.summaries,
            **categories,
            reason="checkpoint immutable run identity or state contracts differ",
        )
    if not mismatches:
        return ResumeCompatibility(
            level="incompatible",
            output_equivalence="incompatible",
            component_mismatches={},
            run_identity="not-checked",
            behavior_change="unknown",
            confirmation_required=True,
            **categories,
            reason="checkpoint fingerprint changed without a diagnosable component difference",
        )
    return ResumeCompatibility(
        level="load-compatible",
        output_equivalence="not-guaranteed",
        component_mismatches=mismatches,
        run_identity="matched",
        behavior_change=behavior.change,
        confirmation_required=behavior.change in {"material", "unknown"},
        behavior_change_ids=behavior.change_ids,
        behavior_domains=behavior.domains,
        behavior_formats=behavior.formats,
        behavior_summaries=behavior.summaries,
        **categories,
        reason=behavior.reason,
    )


def installed_build_digest() -> str:
    """Hash installed EvidenceForge source and bundled output resources."""

    package_root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for path in sorted(package_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _OUTPUT_RESOURCE_SUFFIXES:
            continue
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for distribution in _RUNTIME_DISTRIBUTIONS:
        try:
            versions[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            versions[distribution] = "missing"
    return versions


def _resolved_payload(compiled: CompiledScenario) -> dict[str, Any]:
    document = build_resolved_document(compiled)
    return {
        "assets": {
            name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for name, content in sorted(document.assets.items())
        },
        "effective_config": document.effective_config,
        "scenario": document.scenario,
    }


def run_fingerprint(
    compiled: CompiledScenario,
    *,
    output_target: str,
    formats: list[str],
    oob_hosts: tuple[str, ...],
) -> str:
    """Return the exact compatibility identity, excluding paths and cadence."""

    payload = run_fingerprint_payload(
        compiled,
        output_target=output_target,
        formats=formats,
        oob_hosts=oob_hosts,
    )
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_fingerprint_payload(
    compiled: CompiledScenario,
    *,
    output_target: str,
    formats: list[str],
    oob_hosts: tuple[str, ...],
) -> dict[str, Any]:
    """Return the canonical compatibility inputs used by ``run_fingerprint``."""

    return {
        **behavior_fingerprint_components(),
        "checkpoint_schema": CHECKPOINT_SCHEMA_VERSION,
        "dependencies": _dependency_versions(),
        "evidenceforge_build_sha256": installed_build_digest(),
        "evidenceforge_version": __version__,
        "formats": sorted(formats),
        "interpreter_cache_tag": sys.implementation.cache_tag,
        "machine": platform.machine().lower(),
        "oob_hosts": list(oob_hosts),
        "output_target": output_target,
        "platform": platform.system().lower(),
        "python": platform.python_version(),
        "python_compiler": platform.python_compiler(),
        "python_implementation": platform.python_implementation(),
        "resolved": _resolved_payload(compiled),
        "sys_byteorder": sys.byteorder,
    }


def run_fingerprint_components(
    compiled: CompiledScenario,
    *,
    output_target: str,
    formats: list[str],
    oob_hosts: tuple[str, ...],
) -> dict[str, Any]:
    """Return compact, non-path compatibility diagnostics for checkpoint manifests."""

    payload = run_fingerprint_payload(
        compiled,
        output_target=output_target,
        formats=formats,
        oob_hosts=oob_hosts,
    )
    resolved = json.dumps(
        payload.pop("resolved"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload["resolved_sha256"] = hashlib.sha256(resolved).hexdigest()
    return payload
