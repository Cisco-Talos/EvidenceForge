"""Bounded deterministic examples that do not hide later failure families."""

from __future__ import annotations

from collections import defaultdict


class FindingSamples:
    """Retain at most the output limit per package-defined rule/format family."""

    def __init__(self, limit: int = 100) -> None:
        self.limit = limit
        self._families: dict[tuple[str, str], list[dict]] = defaultdict(list)

    def add(self, code: str, format_name: str, finding: dict) -> None:
        """Retain bounded examples; callers keep complete counters separately."""
        family = self._families[(code, format_name)]
        if len(family) < self.limit:
            family.append(finding)

    def examples(self) -> list[dict]:
        """Select families round-robin in stable order, up to the global limit."""
        result: list[dict] = []
        families = [iter(items) for _, items in sorted(self._families.items())]
        while families and len(result) < self.limit:
            remaining = []
            for family in families:
                if len(result) == self.limit:
                    break
                item = next(family, None)
                if item is not None:
                    result.append(item)
                    remaining.append(family)
            families = remaining
        return result
