# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contracts for the mutually exclusive routine, slow, and soak test tiers."""

from types import SimpleNamespace
from typing import cast

import pytest

from tests.conftest import _validate_test_tiers


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
