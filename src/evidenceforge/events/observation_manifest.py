# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Machine-readable source-observation manifest for generated datasets."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.time import resolve_time_window

logger = logging.getLogger(__name__)

OBSERVATION_MANIFEST_FILENAME = "OBSERVATION_MANIFEST.json"

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
    output_path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")


def find_observation_manifest(output_dir: Path) -> Path | None:
    """Find an observation manifest for an eval output directory."""
    candidates = [
        output_dir / OBSERVATION_MANIFEST_FILENAME,
        output_dir.parent / OBSERVATION_MANIFEST_FILENAME,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def load_observation_manifest(output_dir: Path) -> ObservationManifest | None:
    """Load an observation manifest for eval, returning None if absent/invalid."""
    path = find_observation_manifest(output_dir)
    if path is None:
        return None
    try:
        return ObservationManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        logger.warning("Ignoring invalid observation manifest %s: %s", path, exc)
        return None


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
