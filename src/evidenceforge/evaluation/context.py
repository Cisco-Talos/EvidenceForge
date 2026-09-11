# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared context passed to evaluation pillar scorers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.observation_manifest import ObservationManifest

if TYPE_CHECKING:
    from evidenceforge.composition.models import EffectiveConfig


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Additional dataset metadata available to scorers."""

    observation_manifest: ObservationManifest | None = None
    ground_truth: GroundTruthDocument | None = None
    # storyline_id -> {"values": [rendered on-disk credentials], "time": datetime},
    # from GROUND_TRUTH.json. Lets the causality pillar match spillage events
    # without re-running synthesis, anchored to the actual emitted time.
    spillage_ground_truth: dict[str, dict] | None = None
    # storyline_id -> {"records": [{"value": rendered_payload, "expected_sources": [...]}]},
    # from GROUND_TRUTH.json (kind:"adversarial_payload"). Lets the causality pillar
    # verify each labeled payload landed in the expected source without re-running
    # synthesis (matched against the source's raw text so a CRLF split still matches).
    adversarial_payload_ground_truth: dict[str, dict] | None = None
    # storyline_id -> generated email identifiers from GROUND_TRUTH.json. Lets the
    # causality pillar match email artifacts without leaking storyline labels into
    # ARTIFACTS_MANIFEST.json.
    email_ground_truth: dict[str, dict] | None = None
    effective_config: EffectiveConfig | None = None
