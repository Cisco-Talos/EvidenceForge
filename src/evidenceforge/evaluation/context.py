# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared context passed to evaluation pillar scorers."""

from __future__ import annotations

from dataclasses import dataclass

from evidenceforge.events.observation_manifest import ObservationManifest


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Additional dataset metadata available to scorers."""

    observation_manifest: ObservationManifest | None = None
