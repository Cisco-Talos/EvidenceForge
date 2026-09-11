# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contracts for the mutually exclusive routine, slow, and soak test tiers."""

from types import SimpleNamespace
from typing import cast

import pytest

from tests.conftest import (
    _partition_slow_items,
    _slow_shard_index,
    _validate_slow_shard_coordinates,
    _validate_test_tiers,
)


def _item(nodeid: str, *markers: str) -> pytest.Item:
    """Build the minimal collected-item shape required by the tier validator."""

    return cast(
        pytest.Item,
        SimpleNamespace(nodeid=nodeid, keywords={marker: True for marker in markers}),
    )


def test_distinct_cost_tiers_are_accepted() -> None:
    """Routine, slow, and soak tests may each occupy exactly one tier."""

    _validate_test_tiers(
        [
            _item("test_routine"),
            _item("test_release", "slow"),
            _item("test_soak", "soak"),
        ]
    )


def test_slow_and_soak_overlap_is_rejected() -> None:
    """A test cannot leak an occasional diagnostic into the release gate."""

    with pytest.raises(pytest.UsageError, match="test_overlap"):
        _validate_test_tiers([_item("test_overlap", "slow", "soak")])


def test_slow_shards_are_complete_disjoint_and_deterministic() -> None:
    """Every slow node belongs to exactly one stable shard."""

    slow_items = [
        _item(f"tests/unit/test_example.py::test_case_{index}", "slow") for index in range(200)
    ]
    routine_item = _item("tests/unit/test_example.py::test_routine")
    selected_nodeids: list[set[str]] = []

    for shard_index in range(4):
        retained, deselected = _partition_slow_items(
            [*slow_items, routine_item],
            shard_count=4,
            shard_index=shard_index,
        )
        assert routine_item in retained
        assert routine_item not in deselected
        selected_nodeids.append({item.nodeid for item in retained if "slow" in item.keywords})

    expected_nodeids = {item.nodeid for item in slow_items}
    assert set().union(*selected_nodeids) == expected_nodeids
    assert sum(len(shard) for shard in selected_nodeids) == len(expected_nodeids)
    assert _slow_shard_index(slow_items[0].nodeid, 4) == _slow_shard_index(
        slow_items[0].nodeid,
        4,
    )


@pytest.mark.parametrize(
    ("shard_count", "shard_index"),
    [(0, 0), (4, -1), (4, 4)],
)
def test_invalid_slow_shard_coordinates_are_rejected(
    shard_count: int,
    shard_index: int,
) -> None:
    """Invalid shard coordinates fail collection instead of dropping tests."""

    with pytest.raises(pytest.UsageError):
        _validate_slow_shard_coordinates(
            shard_count=shard_count,
            shard_index=shard_index,
        )
