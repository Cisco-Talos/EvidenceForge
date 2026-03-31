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

"""Tests for evaluation data models."""

import json
from datetime import UTC, datetime

from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    DimensionScore,
    QualityReport,
    SubScore,
)


class TestSubScore:
    def test_basic_creation(self):
        s = SubScore(name="Test", key="test", weight=0.5, score=85.0)
        assert s.score == 85.0
        assert s.weight == 0.5

    def test_none_score(self):
        s = SubScore(name="Test", key="test", weight=0.5)
        assert s.score is None


class TestDimensionScore:
    def test_basic_creation(self):
        d = DimensionScore(
            number=1,
            name="Record-Level Fidelity",
            weight=0.15,
            score=92.0,
            sub_scores=[
                SubScore(name="Parsability", key="parsability", weight=0.4, score=100.0),
                SubScore(name="Co-occurrence", key="co_occurrence", weight=0.35, score=88.0),
            ],
        )
        assert d.number == 1
        assert len(d.sub_scores) == 2


class TestQualityReport:
    def test_json_serialization(self):
        report = QualityReport(
            scenario_name="test-scenario",
            evaluated_at=datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC),
            total_records=1000,
            source_counts={"windows_event_security": 500, "zeek_conn": 500},
            overall_score=78.0,
            dimensions=[
                DimensionScore(
                    number=1,
                    name="Record-Level Fidelity",
                    weight=0.15,
                    score=92.0,
                ),
            ],
            acceptance_passed=True,
            acceptance_criteria=[
                AcceptanceCriterion(
                    name="Parsability",
                    dimension=1,
                    sub_score_key="parsability",
                    threshold=98.0,
                    actual=100.0,
                    passed=True,
                    level="hard",
                ),
            ],
        )
        json_str = report.model_dump_json()
        data = json.loads(json_str)
        assert data["scenario_name"] == "test-scenario"
        assert data["overall_score"] == 78.0
        assert len(data["dimensions"]) == 1
        assert data["acceptance_passed"] is True

    def test_empty_report(self):
        report = QualityReport(
            scenario_name="empty",
            evaluated_at=datetime.now(UTC),
        )
        assert report.total_records == 0
        assert report.overall_score is None
        assert report.acceptance_passed is None
