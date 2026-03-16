"""Data models for the evaluation framework.

Pydantic models for quality scores, acceptance criteria, and evaluation reports.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class SubScore(BaseModel):
    """A sub-score within a quality dimension."""

    name: str
    key: str
    weight: float = Field(ge=0.0, le=1.0)
    score: float | None = Field(None, ge=0.0, le=100.0)
    details: str = ""
    sample_failures: list[str] = Field(default_factory=list)


class AcceptanceCriterion(BaseModel):
    """A pass/fail acceptance criterion checked against a sub-score."""

    name: str
    dimension: int
    sub_score_key: str
    threshold: float
    actual: float | None = None
    passed: bool | None = None
    level: Literal["hard", "target"]


class DimensionScore(BaseModel):
    """Score for a single quality dimension."""

    number: int = Field(ge=1, le=5)
    name: str
    weight: float = Field(ge=0.0, le=1.0)
    score: float | None = Field(None, ge=0.0, le=100.0)
    sub_scores: list[SubScore] = Field(default_factory=list)


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
    dimensions: list[DimensionScore] = Field(default_factory=list)
    acceptance_passed: bool | None = None
    acceptance_criteria: list[AcceptanceCriterion] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    supplementary: dict[str, Any] = Field(default_factory=dict)
    llm_spot_checks: list[LLMSpotCheck] | None = None
