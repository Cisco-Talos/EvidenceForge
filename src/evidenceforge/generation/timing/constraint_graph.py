# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic temporal constraint graph.

The graph is intentionally small and internal. It gives action bundles,
lifecycle planners, and source timing code a shared way to express ordering
relationships across more than one evidence timestamp without pushing that
logic into emitters.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Self

from evidenceforge.models.exceptions import GenerationError

_DEFAULT_GAP = timedelta(milliseconds=1)


class TemporalConstraintError(GenerationError):
    """Temporal constraint graph cannot be resolved."""


@dataclass(frozen=True, slots=True)
class TemporalConstraint:
    """Directed ordering constraint between two temporal nodes."""

    before_key: str
    after_key: str
    min_gap: timedelta = _DEFAULT_GAP

    @property
    def normalized_gap(self) -> timedelta:
        """Return a non-negative gap for this ordering edge."""

        return max(self.min_gap, timedelta(0))


@dataclass(slots=True)
class TemporalNode:
    """One timestamp candidate in a temporal constraint graph."""

    key: str
    preferred_time: datetime
    not_before: datetime | None = None
    not_after: datetime | None = None
    resolved_time: datetime | None = None


class TemporalConstraintGraph:
    """Resolve deterministic source or lifecycle timestamps from constraints."""

    def __init__(self) -> None:
        self._nodes: dict[str, TemporalNode] = {}
        self._constraints: list[TemporalConstraint] = []
        self._resolved = False

    def add_node(
        self,
        key: str,
        preferred_time: datetime,
        *,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> Self:
        """Add a timestamp node with optional hard bounds."""

        if key in self._nodes:
            raise TemporalConstraintError(f"Duplicate temporal node '{key}'")
        lower = not_before
        upper = not_after
        if within is not None:
            start, end = within
            lower = start if lower is None else max(lower, start)
            upper = end if upper is None else min(upper, end)
        self._nodes[key] = TemporalNode(
            key=key,
            preferred_time=preferred_time,
            not_before=lower,
            not_after=upper,
        )
        self._resolved = False
        return self

    def constrain_after(
        self,
        after_key: str,
        before_key: str,
        *,
        min_gap: timedelta = _DEFAULT_GAP,
    ) -> Self:
        """Require ``after_key`` to resolve after ``before_key`` by ``min_gap``."""

        self._constraints.append(
            TemporalConstraint(
                before_key=before_key,
                after_key=after_key,
                min_gap=min_gap,
            )
        )
        self._resolved = False
        return self

    def resolve(self) -> dict[str, datetime]:
        """Resolve all node timestamps and return them by key."""

        self._validate_constraints()
        order = self._topological_order()
        incoming = self._incoming_constraints()
        for key in order:
            node = self._nodes[key]
            lower = node.not_before
            for constraint in incoming.get(key, ()):
                before_time = self._nodes[constraint.before_key].resolved_time
                if before_time is None:
                    raise TemporalConstraintError(
                        f"Temporal dependency '{constraint.before_key}' was not resolved"
                    )
                edge_lower = before_time + constraint.normalized_gap
                lower = edge_lower if lower is None else max(lower, edge_lower)
            node.resolved_time = self._clamp(
                node.preferred_time,
                not_before=lower,
                not_after=node.not_after,
            )
        self._resolved = True
        return {key: node.resolved_time for key, node in self._nodes.items() if node.resolved_time}

    def resolved_time(self, key: str) -> datetime:
        """Return one resolved timestamp, resolving the graph if needed."""

        if key not in self._nodes:
            raise TemporalConstraintError(f"Unknown temporal node '{key}'")
        if not self._resolved:
            self.resolve()
        resolved = self._nodes[key].resolved_time
        if resolved is None:
            raise TemporalConstraintError(f"Temporal node '{key}' was not resolved")
        return resolved

    def _validate_constraints(self) -> None:
        """Ensure every constraint references known nodes."""

        for constraint in self._constraints:
            missing = [
                key
                for key in (constraint.before_key, constraint.after_key)
                if key not in self._nodes
            ]
            if missing:
                joined = ", ".join(f"'{key}'" for key in missing)
                raise TemporalConstraintError(f"Unknown temporal node(s): {joined}")

    def _topological_order(self) -> list[str]:
        """Return deterministic topological order or raise on cycles."""

        outgoing: dict[str, list[str]] = defaultdict(list)
        in_degree = {key: 0 for key in self._nodes}
        for constraint in self._constraints:
            outgoing[constraint.before_key].append(constraint.after_key)
            in_degree[constraint.after_key] += 1

        ready = deque(sorted(key for key, degree in in_degree.items() if degree == 0))
        order: list[str] = []
        while ready:
            key = ready.popleft()
            order.append(key)
            for after_key in sorted(outgoing.get(key, ())):
                in_degree[after_key] -= 1
                if in_degree[after_key] == 0:
                    ready.append(after_key)

        if len(order) != len(self._nodes):
            cyclic = sorted(key for key, degree in in_degree.items() if degree > 0)
            raise TemporalConstraintError(
                "Temporal constraint cycle detected involving: " + ", ".join(cyclic)
            )
        return order

    def _incoming_constraints(self) -> dict[str, list[TemporalConstraint]]:
        """Return incoming constraints keyed by dependent node."""

        incoming: dict[str, list[TemporalConstraint]] = defaultdict(list)
        for constraint in self._constraints:
            incoming[constraint.after_key].append(constraint)
        return incoming

    @staticmethod
    def _clamp(
        preferred_time: datetime,
        *,
        not_before: datetime | None,
        not_after: datetime | None,
    ) -> datetime:
        """Clamp preferred time to hard bounds; lower wins on conflicts."""

        if not_before is not None and not_after is not None and not_after < not_before:
            return not_before
        result = preferred_time
        if not_before is not None and result < not_before:
            result = not_before
        if not_after is not None and result > not_after:
            result = not_after
        return result
