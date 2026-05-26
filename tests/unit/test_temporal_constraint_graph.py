# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for temporal constraint graph resolution."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.timing import TemporalConstraintError, TemporalConstraintGraph


def _base_time() -> datetime:
    return datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def test_graph_preserves_preferred_time_without_constraints() -> None:
    """Unconstrained nodes should resolve to their preferred timestamps."""
    base = _base_time()
    graph = TemporalConstraintGraph()
    graph.add_node("event", base + timedelta(milliseconds=12))

    resolved = graph.resolve()

    assert resolved["event"] == base + timedelta(milliseconds=12)


def test_graph_orders_cross_event_lifecycle_chain() -> None:
    """Dependent evidence should move after prerequisite evidence by its gap."""
    base = _base_time()
    graph = TemporalConstraintGraph()
    graph.add_node("connection", base + timedelta(milliseconds=50))
    graph.add_node("auth", base + timedelta(milliseconds=5))
    graph.add_node("shell", base + timedelta(milliseconds=20))
    graph.constrain_after("auth", "connection", min_gap=timedelta(milliseconds=100))
    graph.constrain_after("shell", "auth", min_gap=timedelta(milliseconds=25))

    resolved = graph.resolve()

    assert resolved["connection"] == base + timedelta(milliseconds=50)
    assert resolved["auth"] == base + timedelta(milliseconds=150)
    assert resolved["shell"] == base + timedelta(milliseconds=175)


def test_graph_lower_bound_wins_when_upper_conflicts_with_causality() -> None:
    """Impossible upper bounds should not invert a required causal edge."""
    base = _base_time()
    graph = TemporalConstraintGraph()
    graph.add_node("before", base)
    graph.add_node(
        "after",
        base + timedelta(milliseconds=1),
        not_after=base + timedelta(milliseconds=5),
    )
    graph.constrain_after("after", "before", min_gap=timedelta(milliseconds=25))

    assert graph.resolved_time("after") == base + timedelta(milliseconds=25)


def test_graph_resolves_deterministically_regardless_of_insertion_order() -> None:
    """Resolution should not depend on dictionary insertion accidents."""
    base = _base_time()

    def resolve_with_order(order: tuple[str, ...]) -> dict[str, datetime]:
        graph = TemporalConstraintGraph()
        for key in order:
            graph.add_node(key, base)
        graph.constrain_after("b", "a", min_gap=timedelta(milliseconds=2))
        graph.constrain_after("c", "b", min_gap=timedelta(milliseconds=3))
        return graph.resolve()

    assert resolve_with_order(("a", "b", "c")) == resolve_with_order(("c", "a", "b"))


def test_graph_rejects_unknown_constraint_nodes() -> None:
    """Constraints should fail fast when they reference missing evidence."""
    graph = TemporalConstraintGraph()
    graph.add_node("known", _base_time())
    graph.constrain_after("missing", "known")

    with pytest.raises(TemporalConstraintError, match="Unknown temporal node"):
        graph.resolve()


def test_graph_rejects_cycles() -> None:
    """Cycles represent impossible lifecycle ownership and should fail clearly."""
    graph = TemporalConstraintGraph()
    graph.add_node("a", _base_time())
    graph.add_node("b", _base_time())
    graph.constrain_after("b", "a")
    graph.constrain_after("a", "b")

    with pytest.raises(TemporalConstraintError, match="cycle"):
        graph.resolve()
