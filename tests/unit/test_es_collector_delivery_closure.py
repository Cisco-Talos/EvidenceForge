# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorClosure, ESDeliveryRequest
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _START, _prepare, _registry


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("commit", [False, True])
def test_exact_delivery_then_closure_share_rollback_and_terminal_counters(
    batch: bool, commit: bool
) -> None:
    registry = _registry()
    profile = registry.connection("mac-a:es-client")
    if batch:
        token = registry.prepare_batch(
            source_instance=profile.source_instance,
            generation=1,
            delivery=0,
            requests=(
                ESDeliveryRequest(
                    occurrence_id="invented-batch",
                    event_type=1,
                    observed_at=_START + timedelta(seconds=5),
                    decision=ObservationDecision("visible"),
                ),
            ),
        )
        scope = registry.prepared_batch(token)
    else:
        token = _prepare(registry)
        scope = registry.prepared_delivery(token)
    with scope as delivery:
        closure = ESCollectorClosure(before=profile, closed_at=_START + timedelta(seconds=10))
        with registry.prepared_closures((closure,), after_deliveries=(delivery,)) as terminal:
            expected = terminal.expected_result
            assert expected[0].next_delivery == 1
            terminal.certify_composite_commit(expected)
            with pytest.raises(StateError, match="apply first"):
                terminal.apply_provisional()
            delivery.apply_provisional()
            terminal.apply_provisional()
            assert registry.connection(profile.source_instance) == expected[0]
            if commit:
                delivery.finalize_no_fail()
                terminal.finalize_no_fail()
    if commit:
        assert registry.connection(profile.source_instance).closed_at == closure.closed_at
        assert registry.connection(profile.source_instance).next_delivery == 1
    else:
        assert registry.connection(profile.source_instance) == profile
        registry.cancel_batch(token) if batch else registry.cancel(token)


@pytest.mark.parametrize("damage", ["unlisted", "copy", "duplicate", "equal_time", "before_time"])
def test_delivery_closure_rejects_unowned_or_out_of_order_composition(damage: str) -> None:
    registry = _registry()
    profile = registry.connection("mac-a:es-client")
    token = _prepare(registry)
    with registry.prepared_delivery(token) as delivery:
        handles = (delivery,)
        at = _START + timedelta(seconds=10)
        if damage == "unlisted":
            handles = ()
        elif damage == "copy":
            handles = (replace(delivery),)
        elif damage == "duplicate":
            handles = (delivery, delivery)
        elif damage == "equal_time":
            at = token.observation.observed_at
        else:
            at = token.observation.observed_at - timedelta(microseconds=1)
        with pytest.raises((StateError, ValueError)):
            with registry.prepared_closures(
                (ESCollectorClosure(before=profile, closed_at=at),), after_deliveries=handles
            ):
                pass
    assert registry.connection(profile.source_instance) == profile
    registry.cancel(token)
