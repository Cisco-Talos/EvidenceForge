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

from evidenceforge.generation.timing.distributions import (
    TimingDistributionError,
    TimingScope,
    TruncatedLognormalDistribution,
)
from evidenceforge.generation.timing.runtime import TimingRuntime
from evidenceforge.models.exceptions import GenerationError

_DEFAULT_GAP = timedelta(milliseconds=1)
_DEFAULT_REPAIR_MAX_US = 25_001


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

    def __init__(
        self,
        *,
        timing_runtime: TimingRuntime | None = None,
        scope: TimingScope | None = None,
        relationship_key: str = "temporal.constraint.repair",
    ) -> None:
        if not relationship_key:
            raise TemporalConstraintError("Temporal repair relationship key must not be empty")
        self._nodes: dict[str, TemporalNode] = {}
        self._constraints: list[TemporalConstraint] = []
        self._timing_runtime = timing_runtime or TimingRuntime.compatibility_default()
        self._scope = scope
        self._relationship_key = relationship_key
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
            node.resolved_time = self._resolve_node(
                node,
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

    def _resolve_node(
        self,
        node: TemporalNode,
        *,
        not_before: datetime | None,
        not_after: datetime | None,
    ) -> datetime:
        """Resolve one node, sampling interior slack when a bound repairs it."""

        preferred_time = node.preferred_time
        if not_before is not None and not_after is not None and not_after < not_before:
            self._raise_saturated_window(node.key, not_before, not_after)
        if not_before is not None and preferred_time < not_before:
            return self._sample_inside_bound(
                node,
                anchor=not_before,
                opposite_bound=not_after,
                direction="after",
            )
        if not_after is not None and preferred_time > not_after:
            return self._sample_inside_bound(
                node,
                anchor=not_after,
                opposite_bound=not_before,
                direction="before",
            )
        return preferred_time

    def _sample_inside_bound(
        self,
        node: TemporalNode,
        *,
        anchor: datetime,
        opposite_bound: datetime | None,
        direction: str,
    ) -> datetime:
        """Sample deterministic microsecond slack strictly inside an admissible window."""

        available_us = _DEFAULT_REPAIR_MAX_US
        if opposite_bound is not None:
            available_us = round(abs((opposite_bound - anchor).total_seconds()) * 1_000_000)
            if available_us <= 1:
                lower = anchor if direction == "after" else opposite_bound
                upper = opposite_bound if direction == "after" else anchor
                self._raise_saturated_window(node.key, lower, upper)

        maximum_us = float(min(_DEFAULT_REPAIR_MAX_US, available_us))
        median_us = min(2_400.0, max(1.5, maximum_us * 0.18))
        distribution = TruncatedLognormalDistribution(
            median=median_us,
            sigma=0.78,
            minimum=0.0,
            maximum=maximum_us,
        )
        scope = self._scope or TimingScope(
            stable_id=(
                f"constraint:{node.key}:{node.preferred_time.isoformat()}:"
                f"{anchor.isoformat()}:{opposite_bound.isoformat() if opposite_bound else ''}"
            ),
            lifecycle_id=node.key,
        )
        sample_key = (
            f"{node.key}:{direction}:{anchor.isoformat()}:"
            f"{opposite_bound.isoformat() if opposite_bound else ''}"
        )
        try:
            slack = self._timing_runtime.sampler.sample_timedelta(
                distribution,
                relationship_key=self._relationship_key,
                scope=scope,
                sample_key=sample_key,
            )
        except TimingDistributionError as exc:
            self._timing_runtime.audit.record_saturation(self._relationship_key)
            raise TemporalConstraintError(
                f"Temporal node '{node.key}' has no sampleable interior repair window"
            ) from exc
        self._timing_runtime.audit.record_repair(self._relationship_key)
        return anchor + slack if direction == "after" else anchor - slack

    def _raise_saturated_window(
        self,
        key: str,
        lower: datetime | None,
        upper: datetime | None,
    ) -> None:
        """Record and reject one impossible temporal window."""

        self._timing_runtime.audit.record_saturation(self._relationship_key)
        raise TemporalConstraintError(
            f"Temporal node '{key}' has an impossible window: "
            f"not_before={lower!r}, not_after={upper!r}"
        )
