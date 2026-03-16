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
