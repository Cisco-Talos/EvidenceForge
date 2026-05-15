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

"""Pillar scoring base class for the evaluation framework."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from typing import Any

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario

# Progress callback: (event_type, data) -> None
ProgressCallback = Callable[[str, dict[str, Any]], None]


def _noop_callback(event_type: str, data: dict[str, Any]) -> None:
    pass


def aggregate_sub_scores(sub_scores: Iterable[SubScore]) -> float:
    """Compute a pillar score from sub-scores, excluding skipped ones.

    Skipped sub-scores (score=None or skipped=True) are dropped and the
    remaining sub-score weights are proportionally renormalized so the pillar
    score stays on a 0–100 scale regardless of how many sub-scores were skipped.
    Returns 100.0 if every sub-score is skipped.
    """
    active = [s for s in sub_scores if s.score is not None and not s.skipped]
    if not active:
        return 100.0
    total_weight = sum(s.weight for s in active)
    if total_weight <= 0:
        return 100.0
    return sum(s.score * s.weight for s in active) / total_weight


class DimensionScorer(ABC):
    """Base class for quality pillar scorers.

    The class is named DimensionScorer for backward compatibility; new
    subclasses should treat 'dimension' as synonymous with 'pillar'.
    """

    number: int = 0
    name: str = ""
    weight: float = 0.0

    @abstractmethod
    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        """Score a dataset on this pillar.

        Args:
            records: Parsed records grouped by format name.
            scenario: The scenario used to generate the dataset.
            context: Optional metadata sidecars discovered for the dataset.
            progress: Optional callback for reporting sub-score progress.

        Returns:
            PillarScore with sub-scores populated.
        """
        ...
