# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

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
    failure_summary: dict[str, dict[str, int]] = Field(default_factory=dict)
    """Aggregated failure counts by format and category.
    e.g. {"windows_event_security": {"parse_error": 2, "missing_field": 1}}"""


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
