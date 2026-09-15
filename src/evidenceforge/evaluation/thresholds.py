# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Threshold configuration loader for the evaluation framework.

Loads minimum/aspirational thresholds from config/evaluation/thresholds.yaml
and provides typed access so the engine can consume them without hard-coding
any numeric values.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.models.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

_FILE = "thresholds.yaml"


class SubScoreThreshold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minimum: float = Field(ge=0, le=100)
    aspirational: float = Field(ge=0, le=100)
    hard_gate: bool = Field(default=False, strict=True)


class PillarThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    weight: float = Field(ge=0, le=1)
    sub_scores: dict[str, SubScoreThreshold] = Field(default_factory=dict)


class EvalThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overall_minimum: float
    overall_aspirational: float
    pillars: dict[str, PillarThresholds] = Field(default_factory=dict)

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


class OverallThresholds(BaseModel):
    """Package-owned overall scoring thresholds."""

    model_config = ConfigDict(extra="forbid")
    minimum: float = Field(ge=0, le=100)
    aspirational: float = Field(ge=0, le=100)


class ThresholdDocument(BaseModel):
    """Strict on-disk scoring policy with mandatory exact source gates."""

    model_config = ConfigDict(extra="forbid")
    overall: OverallThresholds
    pillars: dict[str, PillarThresholds]

    @model_validator(mode="after")
    def validate_gates(self) -> ThresholdDocument:
        """Prevent missing correctness gates from weakening acceptance."""
        for key in ("spec_conformance", "format_constraints"):
            pillar = self.pillars.get("parseability")
            threshold = pillar.sub_scores.get(key) if pillar else None
            if threshold is None or not threshold.hard_gate or threshold.minimum != 100:
                raise ValueError(f"parseability.{key} requires a 100% hard gate")
        return self


@lru_cache(maxsize=1)
def load_thresholds() -> EvalThresholds:
    """Load validated package policy; missing policy is an explicit configuration error."""
    try:
        document = ThresholdDocument.model_validate(load_rules_file(_FILE))
    except (ValidationError, OSError, ValueError) as exc:
        raise ConfigurationError(f"Invalid packaged thresholds.yaml: {exc}") from exc
    return EvalThresholds(
        overall_minimum=document.overall.minimum,
        overall_aspirational=document.overall.aspirational,
        pillars=document.pillars,
    )


_register_trusted_derived_cache(
    __name__,
    "load_thresholds",
    globals(),
    load_thresholds,
)
