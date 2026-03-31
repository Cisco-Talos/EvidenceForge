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

"""Dimension scoring base class for the evaluation framework."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from evidenceforge.evaluation.models import DimensionScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario

# Progress callback: (event_type, data) -> None
ProgressCallback = Callable[[str, dict[str, Any]], None]


def _noop_callback(event_type: str, data: dict[str, Any]) -> None:
    pass


class DimensionScorer(ABC):
    """Base class for quality dimension scorers."""

    number: int = 0
    name: str = ""
    weight: float = 0.0

    @abstractmethod
    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        """Score a dataset on this dimension.

        Args:
            records: Parsed records grouped by format name.
            scenario: The scenario used to generate the dataset.
            progress: Optional callback for reporting sub-score progress.

        Returns:
            DimensionScore with sub-scores populated.
        """
        ...
