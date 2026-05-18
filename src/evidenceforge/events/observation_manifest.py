# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Machine-readable source-observation manifest for generated datasets."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text
from evidenceforge.utils.time import resolve_time_window

logger = logging.getLogger(__name__)

OBSERVATION_MANIFEST_FILENAME = "OBSERVATION_MANIFEST.json"
MAX_OBSERVATION_MANIFEST_BYTES = 1_048_576
_OBSERVATION_STATUSES = frozenset({"visible", "delayed", "dropped", "filtered", "out_of_window"})

ObservationManifestKind = Literal["storyline", "red_herring"]
ObservationStatusCounts = dict[str, dict[str, int]]
SourceEvidenceStatus = dict[str, ObservationStatusCounts]


class ObservationManifestEvent(BaseModel):
    """Observation status for one storyline or red-herring cluster."""

    kind: ObservationManifestKind
    storyline_id: str
    index: int = Field(ge=0)
    actor: str
    system: str
    activity: str
    event_types: list[str] = Field(default_factory=list)
    source_status: ObservationStatusCounts = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    @field_validator("source_status")
    @classmethod
    def validate_source_status(cls, value: ObservationStatusCounts) -> ObservationStatusCounts:
        """Validate source observation status counters are known and non-negative."""
        for source, statuses in value.items():
            for status, count in statuses.items():
                if status not in _OBSERVATION_STATUSES:
                    raise ValueError(
                        f"source_status[{source!r}] contains unknown status {status!r}"
                    )
                if count < 0:
                    raise ValueError(f"source_status[{source!r}][{status!r}] must be non-negative")
        return value

    @property
    def visible_or_delayed_count(self) -> int:
        """Return visible/delayed source-attempt count for this cluster."""
        return sum(
            statuses.get("visible", 0) + statuses.get("delayed", 0)
            for statuses in self.source_status.values()
        )

    @property
    def non_visible_count(self) -> int:
        """Return dropped/filtered/out-of-window source-attempt count for this cluster."""
        return sum(
            statuses.get("dropped", 0)
            + statuses.get("filtered", 0)
            + statuses.get("out_of_window", 0)
            for statuses in self.source_status.values()
        )


class ObservationManifest(BaseModel):
    """Sidecar manifest describing source observation decisions for eval."""

    schema_version: int = 1
    scenario_name: str
    observation_profile: str
    collection_window: dict[str, str | None]
    source_summary: ObservationStatusCounts = Field(default_factory=dict)
    storyline_events: list[ObservationManifestEvent] = Field(default_factory=list)
    red_herring_events: list[ObservationManifestEvent] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    def storyline_by_id(self) -> dict[str, ObservationManifestEvent]:
        """Return storyline events keyed by scenario storyline ID."""
        return {event.storyline_id: event for event in self.storyline_events}


def build_observation_manifest(
    scenario: Scenario,
    source_evidence_status: SourceEvidenceStatus,
) -> ObservationManifest:
    """Build the observation manifest for a generated scenario."""
    return ObservationManifest(
        scenario_name=scenario.name,
        observation_profile=scenario.observation_profile,
        collection_window=_collection_window(scenario),
        source_summary=_source_summary(source_evidence_status),
        storyline_events=[
            ObservationManifestEvent(
                kind="storyline",
                storyline_id=event.id,
                index=index,
                actor=event.actor,
                system=event.system,
                activity=event.activity,
                event_types=sorted({spec.type for spec in event.events}),
                source_status=source_evidence_status.get(event.id, {}),
            )
            for index, event in enumerate(scenario.storyline or [])
        ],
        red_herring_events=[
            ObservationManifestEvent(
                kind="red_herring",
                storyline_id=event.id,
                index=index,
                actor=event.actor,
                system=event.system,
                activity=event.activity,
                event_types=sorted({spec.type for spec in event.events}),
                source_status=source_evidence_status.get(f"red_herring:{event.id}", {}),
            )
            for index, event in enumerate(scenario.red_herrings or [])
        ],
    )


def write_observation_manifest(
    output_path: Path,
    scenario: Scenario,
    source_evidence_status: SourceEvidenceStatus,
) -> None:
    """Write OBSERVATION_MANIFEST.json next to GROUND_TRUTH.md."""
    manifest = build_observation_manifest(scenario, source_evidence_status)
    safe_write_text(output_path, manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")


def find_observation_manifest(output_dir: Path) -> Path | None:
    """Find a trusted observation manifest for an eval output directory."""
    output_root = output_dir.resolve()
    allowed_parents = {output_root, output_root.parent}
    candidates = [
        output_dir / OBSERVATION_MANIFEST_FILENAME,
        output_dir.parent / OBSERVATION_MANIFEST_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_symlink():
            logger.warning("Ignoring symlinked observation manifest %s", candidate)
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.parent not in allowed_parents:
            logger.warning("Ignoring out-of-root observation manifest %s", candidate)
            continue
        if not resolved.is_file():
            continue
        if resolved.stat().st_size > MAX_OBSERVATION_MANIFEST_BYTES:
            logger.warning("Ignoring oversized observation manifest %s", candidate)
            continue
        return resolved
    return None


def load_observation_manifest(
    output_dir: Path,
    scenario: Scenario | None = None,
) -> ObservationManifest | None:
    """Load an observation manifest for eval, returning None if absent/invalid."""
    if scenario is not None and scenario.observation_profile == "complete":
        return None
    path = find_observation_manifest(output_dir)
    if path is None:
        return None
    try:
        manifest = ObservationManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        logger.warning("Ignoring invalid observation manifest %s: %s", path, exc)
        return None
    if scenario is not None and not observation_manifest_matches_scenario(manifest, scenario):
        logger.warning("Ignoring observation manifest %s because it does not match scenario", path)
        return None
    return manifest


def observation_manifest_matches_scenario(
    manifest: ObservationManifest,
    scenario: Scenario,
) -> bool:
    """Return whether a manifest is bound to the supplied scenario metadata."""
    if scenario.observation_profile == "complete":
        return False
    if manifest.scenario_name != scenario.name:
        return False
    if manifest.observation_profile != scenario.observation_profile:
        return False
    if manifest.collection_window != _collection_window(scenario):
        return False
    return _manifest_events_match_scenario(
        manifest.storyline_events, scenario.storyline or [], "storyline"
    ) and _manifest_events_match_scenario(
        manifest.red_herring_events, scenario.red_herrings or [], "red_herring"
    )


def _manifest_events_match_scenario(
    manifest_events: list[ObservationManifestEvent],
    scenario_events: list[Any],
    expected_kind: ObservationManifestKind,
) -> bool:
    if len(manifest_events) != len(scenario_events):
        return False
    for index, (manifest_event, scenario_event) in enumerate(
        zip(manifest_events, scenario_events, strict=True)
    ):
        if manifest_event.index != index or manifest_event.kind != expected_kind:
            return False
        expected_event_types = sorted({spec.type for spec in scenario_event.events})
        if (
            manifest_event.storyline_id != scenario_event.id
            or manifest_event.actor != scenario_event.actor
            or manifest_event.system != scenario_event.system
            or manifest_event.activity != scenario_event.activity
            or manifest_event.event_types != expected_event_types
        ):
            return False
    return True


def _collection_window(scenario: Scenario) -> dict[str, str | None]:
    try:
        start, end = resolve_time_window(scenario.time_window)
    except ValueError:
        start = scenario.time_window.start
        end = None
    return {
        "start": _format_dt(start),
        "end": _format_dt(end) if end else None,
    }


def _format_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat().replace("+00:00", "Z")


def _source_summary(source_evidence_status: SourceEvidenceStatus) -> ObservationStatusCounts:
    summary: dict[str, dict[str, int]] = {}
    for source_status in source_evidence_status.values():
        for source, counts in source_status.items():
            target = summary.setdefault(source, {})
            for status, count in counts.items():
                target[status] = target.get(status, 0) + count
    return summary
