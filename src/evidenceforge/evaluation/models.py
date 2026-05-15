# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data models for the evaluation framework.

Pydantic models for quality scores, acceptance criteria, and evaluation reports.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class SubScore(BaseModel):
    """A sub-score within a quality pillar."""

    name: str
    key: str
    weight: float = Field(ge=0.0, le=1.0)
    score: float | None = Field(None, ge=0.0, le=100.0)
    raw_score: float | None = Field(None, ge=0.0, le=100.0)
    """Unadjusted score when profile-aware scoring changes the displayed score."""
    adjusted: bool = False
    """True when the score excludes expected observation-profile gaps."""
    details: str = ""
    sample_failures: list[str] = Field(default_factory=list)
    failure_summary: dict[str, dict[str, int]] = Field(default_factory=dict)
    """Aggregated failure counts by format and category.
    e.g. {"windows_event_security": {"parse_error": 2, "missing_field": 1}}"""
    skipped: bool = False
    """If true, this sub-score is excluded from the pillar's weighted mean and
    its weight is redistributed proportionally across the remaining sub-scores."""


class AcceptanceCriterion(BaseModel):
    """A pass/fail acceptance criterion checked against a sub-score."""

    name: str
    pillar: str
    sub_score_key: str
    threshold: float
    aspirational: float | None = None
    actual: float | None = None
    passed: bool | None = None
    meets_aspirational: bool | None = None
    level: Literal["hard", "target"]


class PillarScore(BaseModel):
    """Score for a single quality pillar."""

    number: int = Field(ge=1)
    name: str
    weight: float = Field(ge=0.0, le=1.0)
    score: float | None = Field(None, ge=0.0, le=100.0)
    sub_scores: list[SubScore] = Field(default_factory=list)
    supplementary: dict[str, Any] = Field(default_factory=dict)
    """Per-pillar diagnostic data merged into QualityReport.supplementary."""


# Backward-compat alias — removed once all scorer modules are migrated
DimensionScore = PillarScore


class LLMSpotCheck(BaseModel):
    """Result of an optional LLM spot-check."""

    check_type: Literal["record_realism", "narrative_coherence", "hunting_feasibility"]
    commentary: str
    sample_records: list[str] = Field(default_factory=list)


class QualityReport(BaseModel):
    """Complete quality evaluation report."""

    scenario_name: str
    generated_at: datetime | None = None
    evaluated_at: datetime
    total_records: int = 0
    source_counts: dict[str, int] = Field(default_factory=dict)
    overall_score: float | None = Field(None, ge=0.0, le=100.0)
    pillars: list[PillarScore] = Field(default_factory=list)
    acceptance_passed: bool | None = None
    acceptance_criteria: list[AcceptanceCriterion] = Field(default_factory=list)
    aspirational_met: int | None = None
    """Number of aspirational targets met (out of total gated sub-scores)."""
    aspirational_total: int | None = None
    flags: list[str] = Field(default_factory=list)
    supplementary: dict[str, Any] = Field(default_factory=dict)
    llm_spot_checks: list[LLMSpotCheck] | None = None

    @property
    def dimensions(self) -> list[PillarScore]:
        """Backward-compat alias for pillars."""
        return self.pillars
