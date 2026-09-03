"""Output-affecting compatibility fingerprints for generation recovery."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path
from typing import Any

from evidenceforge import __version__
from evidenceforge.composition.artifacts import build_resolved_document
from evidenceforge.composition.models import CompiledScenario

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

    payload = {
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
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
