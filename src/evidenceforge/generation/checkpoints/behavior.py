"""Declared EvidenceForge generation-behavior compatibility metadata."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from evidenceforge.config import get_config_directory
from evidenceforge.models.exceptions import ConfigurationError

BehaviorImpact = Literal["none", "localized", "material"]
BehaviorChange = Literal["exact", "none-declared", "localized", "material", "unknown"]

_MANIFEST_PATH = get_config_directory() / "generation_behavior.yaml"
_SURFACE_SUFFIXES = {".json", ".j2", ".jinja", ".py", ".yaml", ".yml"}
_CHECKPOINT_CONTROL_START = "# behavior-surface: checkpoint-control-start"
_CHECKPOINT_CONTROL_END = "# behavior-surface: checkpoint-control-end"


class GenerationBehaviorChange(BaseModel):
    """One ordered declaration of an output-affecting behavior revision."""

    revision: int = Field(ge=1)
    id: str = Field(min_length=1, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    impact: BehaviorImpact
    domains: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    summary: str = Field(min_length=1, max_length=240)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("domains", "formats")
    @classmethod
    def _unique_sorted_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("behavior change domains and formats cannot contain empty values")
        if len(set(values)) != len(values):
            raise ValueError("behavior change domains and formats must be unique")
        return tuple(sorted(values))


class GenerationBehaviorManifest(BaseModel):
    """Validated monotonic history for output-affecting generator behavior."""

    schema_version: Literal["1.0"] = "1.0"
    current_revision: int = Field(ge=1)
    history_start_revision: int = Field(ge=1)
    behavior_surface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    changes: tuple[GenerationBehaviorChange, ...]

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def _validate_history(self) -> GenerationBehaviorManifest:
        revisions = [change.revision for change in self.changes]
        expected = list(range(self.history_start_revision, self.current_revision + 1))
        if revisions != sorted(revisions) or sorted(set(revisions)) != expected:
            raise ValueError(
                "behavior changes must contain ordered, gap-free entries for every retained "
                "revision"
            )
        identifiers = [change.id for change in self.changes]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("behavior change IDs must be unique")
        return self


class BehaviorClassification(BaseModel):
    """Behavior risk inferred from checkpoint and current manifest metadata."""

    change: BehaviorChange
    change_ids: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    summaries: tuple[str, ...] = ()
    reason: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


def _surface_paths(package_root: Path) -> tuple[Path, ...]:
    roots = (
        package_root / "composition",
        package_root / "config",
        package_root / "events",
        package_root / "formats",
        package_root / "generation",
    )
    explicit = (
        package_root / "models" / "scenario.py",
        package_root / "output_targets.py",
        package_root / "utils" / "ids.py",
        package_root / "utils" / "rng.py",
        package_root / "utils" / "time.py",
        package_root / "utils" / "timing.py",
        package_root / "utils" / "ua_template.py",
        package_root / "utils" / "windows_ids.py",
    )
    paths: set[Path] = {path for path in explicit if path.is_file()}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SURFACE_SUFFIXES:
                continue
            relative = path.relative_to(package_root)
            if relative.parts[:2] == ("generation", "checkpoints"):
                continue
            if relative == Path("config/generation_behavior.yaml"):
                continue
            paths.add(path)
    return tuple(sorted(paths))


def _surface_content(path: Path) -> bytes:
    payload = path.read_bytes()
    if path.suffix != ".py" or _CHECKPOINT_CONTROL_START.encode() not in payload:
        return payload
    retained: list[bytes] = []
    skipping = False
    for line in payload.splitlines(keepends=True):
        if _CHECKPOINT_CONTROL_START.encode() in line:
            if skipping:
                raise ConfigurationError(f"nested checkpoint-control marker in {path}")
            skipping = True
            continue
        if _CHECKPOINT_CONTROL_END.encode() in line:
            if not skipping:
                raise ConfigurationError(f"unmatched checkpoint-control marker in {path}")
            skipping = False
            continue
        if not skipping:
            retained.append(line)
    if skipping:
        raise ConfigurationError(f"unterminated checkpoint-control marker in {path}")
    return b"".join(retained)


def generation_behavior_surface_digest(package_root: Path | None = None) -> str:
    """Hash files that can change resolved or rendered generation behavior."""

    root = Path(__file__).resolve().parents[2] if package_root is None else package_root
    digest = hashlib.sha256()
    for path in _surface_paths(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = _surface_content(path)
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def load_generation_behavior_manifest() -> GenerationBehaviorManifest:
    """Load and validate the packaged generation-behavior history."""

    try:
        document = yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8"))
        return GenerationBehaviorManifest.model_validate(document)
    except (OSError, yaml.YAMLError, ValidationError) as error:
        raise ConfigurationError(f"generation behavior manifest is invalid: {error}") from error


def validate_generation_behavior_surface() -> GenerationBehaviorManifest:
    """Require the packaged declaration to match the current behavior surface."""

    manifest = load_generation_behavior_manifest()
    actual = generation_behavior_surface_digest()
    if actual != manifest.behavior_surface_sha256:
        raise ConfigurationError(
            "generation behavior surface changed without a matching manifest revision: "
            f"declared={manifest.behavior_surface_sha256}, actual={actual}"
        )
    return manifest


def _history_digest(changes: tuple[GenerationBehaviorChange, ...]) -> str:
    payload = json.dumps(
        [change.model_dump(mode="json") for change in changes],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def behavior_fingerprint_components() -> dict[str, object]:
    """Return bounded validated behavior metadata for checkpoint fingerprints."""

    manifest = validate_generation_behavior_surface()
    return {
        "behavior_manifest_schema": manifest.schema_version,
        "behavior_revision": manifest.current_revision,
        "behavior_history_start_revision": manifest.history_start_revision,
        "behavior_history_sha256": _history_digest(manifest.changes),
        "behavior_surface_sha256": manifest.behavior_surface_sha256,
    }


def classify_behavior_change(
    *,
    same_build: bool,
    stored_components: dict[str, object],
) -> BehaviorClassification:
    """Classify declared behavior changes since one checkpoint was written."""

    if same_build:
        return BehaviorClassification(change="exact")
    manifest = load_generation_behavior_manifest()
    stored_revision = stored_components.get("behavior_revision")
    stored_schema = stored_components.get("behavior_manifest_schema")
    stored_start = stored_components.get("behavior_history_start_revision")
    stored_history_digest = stored_components.get("behavior_history_sha256")
    stored_surface_digest = stored_components.get("behavior_surface_sha256")
    digests_valid = all(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
        for value in (stored_history_digest, stored_surface_digest)
    )
    if (
        type(stored_revision) is not int
        or stored_schema != manifest.schema_version
        or not digests_valid
    ):
        return BehaviorClassification(
            change="unknown",
            reason="checkpoint build lineage predates or lacks behavior metadata",
        )
    if stored_revision > manifest.current_revision:
        return BehaviorClassification(
            change="unknown",
            reason="checkpoint behavior revision is newer than this runtime",
        )
    if stored_revision == manifest.current_revision:
        current = behavior_fingerprint_components()
        if (
            stored_history_digest != current["behavior_history_sha256"]
            or stored_surface_digest != current["behavior_surface_sha256"]
        ):
            return BehaviorClassification(
                change="unknown",
                reason="same behavior revision has conflicting history or surface metadata",
            )
        return BehaviorClassification(change="none-declared")
    if (
        type(stored_start) is not int
        or stored_start != manifest.history_start_revision
        or stored_revision < manifest.history_start_revision
    ):
        return BehaviorClassification(
            change="unknown",
            reason="retained behavior history does not cover the checkpoint revision",
        )
    expected_stored_history = tuple(
        change for change in manifest.changes if change.revision <= stored_revision
    )
    if stored_history_digest != _history_digest(expected_stored_history):
        return BehaviorClassification(
            change="unknown",
            reason="checkpoint behavior history does not match the retained lineage",
        )
    changes = tuple(change for change in manifest.changes if change.revision > stored_revision)
    expected = tuple(range(stored_revision + 1, manifest.current_revision + 1))
    if tuple(sorted({change.revision for change in changes})) != expected:
        return BehaviorClassification(change="unknown", reason="behavior history has a gap")
    impact: BehaviorChange = "localized"
    if any(change.impact == "material" for change in changes):
        impact = "material"
    return BehaviorClassification(
        change=impact,
        change_ids=tuple(change.id for change in changes),
        domains=tuple(sorted({domain for change in changes for domain in change.domains})),
        formats=tuple(sorted({fmt for change in changes for fmt in change.formats})),
        summaries=tuple(change.summary for change in changes),
    )


__all__ = [
    "BehaviorChange",
    "BehaviorClassification",
    "GenerationBehaviorChange",
    "GenerationBehaviorManifest",
    "behavior_fingerprint_components",
    "classify_behavior_change",
    "generation_behavior_surface_digest",
    "load_generation_behavior_manifest",
    "validate_generation_behavior_surface",
]
