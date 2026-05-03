# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Threshold configuration loader for the evaluation framework.

Loads minimum/aspirational thresholds from config/evaluation/thresholds.yaml
and provides typed access so the engine can consume them without hard-coding
any numeric values.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache

from evidenceforge.evaluation.rules import load_rules_file

logger = logging.getLogger(__name__)

_FILE = "thresholds.yaml"


@dataclass
class SubScoreThreshold:
    minimum: float
    aspirational: float
    hard_gate: bool = False


@dataclass
class PillarThresholds:
    weight: float
    sub_scores: dict[str, SubScoreThreshold] = field(default_factory=dict)


@dataclass
class EvalThresholds:
    overall_minimum: float
    overall_aspirational: float
    pillars: dict[str, PillarThresholds] = field(default_factory=dict)

    def sub_score(self, pillar: str, key: str) -> SubScoreThreshold | None:
        """Return threshold for a sub-score, or None if not configured."""
        p = self.pillars.get(pillar)
        if p is None:
            return None
        return p.sub_scores.get(key)

    def hard_gates(self) -> list[tuple[str, str, SubScoreThreshold]]:
        """Return (pillar, key, threshold) for every hard-gated sub-score."""
        result = []
        for pillar_name, pillar in self.pillars.items():
            for key, thresh in pillar.sub_scores.items():
                if thresh.hard_gate:
                    result.append((pillar_name, key, thresh))
        return result


@lru_cache(maxsize=1)
def load_thresholds() -> EvalThresholds:
    """Load and cache thresholds from thresholds.yaml."""
    raw = load_rules_file(_FILE)
    if not raw:
        logger.warning("thresholds.yaml not found or empty; using built-in defaults")
        return _defaults()

    overall = raw.get("overall", {})
    pillars_raw = raw.get("pillars", {})

    pillars: dict[str, PillarThresholds] = {}
    for pillar_name, pillar_data in pillars_raw.items():
        sub_scores: dict[str, SubScoreThreshold] = {}
        for key, ss in (pillar_data.get("sub_scores") or {}).items():
            sub_scores[key] = SubScoreThreshold(
                minimum=float(ss.get("minimum", 0.0)),
                aspirational=float(ss.get("aspirational", 100.0)),
                hard_gate=bool(ss.get("hard_gate", False)),
            )
        pillars[pillar_name] = PillarThresholds(
            weight=float(pillar_data.get("weight", 0.0)),
            sub_scores=sub_scores,
        )

    return EvalThresholds(
        overall_minimum=float(overall.get("minimum", 70.0)),
        overall_aspirational=float(overall.get("aspirational", 85.0)),
        pillars=pillars,
    )


def _defaults() -> EvalThresholds:
    """Minimal safe defaults when the YAML is absent."""
    return EvalThresholds(
        overall_minimum=70.0,
        overall_aspirational=85.0,
    )
