# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Midstream transport sampling cannot invent known absent application data."""

import random
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner


@pytest.mark.parametrize("budgets", [(1000, 0), (0, 1000), (0, 0), (7, 9), (None, 0), (0, None)])
def test_midstream_respects_each_explicit_direction_and_preserves_draws(
    budgets: tuple[int | None, int | None],
) -> None:
    original, response = budgets
    request = SimpleNamespace(orig_bytes=original, resp_bytes=response)
    owner = SimpleNamespace(_failed_transport_duration_seconds=lambda *args, **kwargs: 0.1)
    rng = random.Random(52)
    control = random.Random(52)
    control.choices([("OTH", 1, "DdA")], weights=[1], k=1)
    control.choice(("DAd", "DdA", "ADad"))
    samples = (control.randint(0, 200), control.randint(0, 200))
    # Existing candidate-selection semantics classify simplex requests as False.
    with patch(
        "evidenceforge.generation.actions.network_transaction_planner.connection_state_distribution",
        return_value=[("OTH", 1, "DdA")],
    ):
        state, _history, _duration, outgoing, incoming = (
            NetworkTransactionPlanner._plan_sampled_tcp_state(
                owner,
                request,
                caller_provided_payload=False,
                duration=1.0,
                orig_bytes=original,
                resp_bytes=response,
                rng=rng,
            )
        )
    assert state == "OTH"
    assert outgoing == (min(original, samples[0]) if original is not None else samples[0])
    assert incoming == (min(response, samples[1]) if response is not None else samples[1])
    assert rng.getstate() == control.getstate()
