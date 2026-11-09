# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native groups bind one ordered row set to a single collector counter transaction."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry, PreparedESDeliveryBatchCommit
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile, _registry
from tests.unit.test_es_collector_batch import _prepare, _requests
from tests.unit.test_process_execution_state import _START

_ROWS = ('{"invented":1}\n', '{"invented":"literal\u2028separator"}\n', '{"invented":3}\n')
_TOKEN = "a" * 64


def test_batch_freezes_order_and_recovers_after_commit_and_connection_restart() -> None:
    registry = _registry()
    delivery = _prepare(registry)
    before = registry.connection("mac-a:es-client")
    with registry.prepared_batch(delivery) as claim:
        assert claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN) == _ROWS
    assert registry.connection("mac-a:es-client") == before
    assert registry.retained_native_batch_projection(delivery, canonical_token=_TOKEN) == _ROWS
    with registry.prepared_batch(delivery) as claim:
        assert claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN) == _ROWS
        with pytest.raises(StateError, match="changed"):
            claim.freeze_native_projections(tuple(reversed(_ROWS)), canonical_token=_TOKEN)
        with pytest.raises(StateError, match="changed"):
            claim.freeze_native_projections(_ROWS, canonical_token="b" * 64)
        claim.commit_no_fail()
    assert registry.completed_batch(delivery) == delivery.observations
    assert registry.connection("mac-a:es-client").next_delivery == 3
    registry.open(
        _profile(
            generation=2,
            opened_at=_START + timedelta(seconds=4),
            last_delivery_at=_START + timedelta(seconds=4),
        )
    )
    assert registry.retained_native_batch_projection(delivery, canonical_token=_TOKEN) == _ROWS
    assert registry.commit_batch(delivery) == delivery.observations
    assert registry.connection("mac-a:es-client").next_delivery == 0


@pytest.mark.parametrize(
    "rows",
    [
        (),
        _ROWS[:-1],
        list(_ROWS),
        (_ROWS[0], "bad\nrow\n", _ROWS[2]),
        (_ROWS[0], "\ud800\n", _ROWS[2]),
    ],
)
def test_bad_count_container_or_later_row_does_not_bind_a_prefix(rows: object) -> None:
    registry = _registry()
    delivery = _prepare(registry)
    before = registry.connection("mac-a:es-client")
    with registry.prepared_batch(delivery) as claim:
        with pytest.raises(StateError):
            claim.freeze_native_projections(rows, canonical_token=_TOKEN)
    assert registry.retained_native_batch_projection(delivery) is None
    assert registry.connection("mac-a:es-client") == before
    registry.cancel_batch(delivery)


def test_group_byte_budget_rejects_before_retaining_any_row() -> None:
    registry = _registry()
    request = _requests()[0]
    requests = tuple(
        request.model_copy(
            update={
                "occurrence_id": f"bounded-{index}",
                "observed_at": _START + timedelta(seconds=index + 1),
            }
        )
        for index in range(17)
    )
    delivery = _prepare(registry, requests=requests)
    row = "x" * (1024 * 1024 - 1) + "\n"
    with registry.prepared_batch(delivery) as claim:
        with pytest.raises(StateError, match="16 MiB"):
            claim.freeze_native_projections((row,) * 17)
    assert registry.retained_native_batch_projection(delivery) is None
    registry.cancel_batch(delivery)


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize(
    "damage", ["copy", "rows", "proof", "canonical", "observations", "missing"]
)
def test_changed_or_copied_batch_cannot_recover_or_recommit(committed: bool, damage: str) -> None:
    registry = _registry()
    delivery = _prepare(registry)
    with registry.prepared_batch(delivery) as claim:
        claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
        if committed:
            claim.commit_no_fail()
    before = registry.connection("mac-a:es-client")
    native = delivery._native_projection
    observations = delivery.observations
    candidate = delivery
    if damage == "copy":
        candidate = replace(delivery)
    elif damage == "observations":
        object.__setattr__(delivery, "observations", tuple(reversed(observations)))
    elif damage == "missing":
        object.__setattr__(delivery, "_native_projection", None)
    else:
        changed = {"ndjson": "different\n"} if damage == "rows" else {"proof": b"forged"}
        if damage == "canonical":
            changed = {"canonical_token": "b" * 64}
        object.__setattr__(delivery, "_native_projection", replace(native, **changed))
    with pytest.raises(StateError):
        registry.retained_native_batch_projection(candidate)
    with pytest.raises(StateError):
        registry.commit_batch(candidate)
    assert registry.connection("mac-a:es-client") == before
    object.__setattr__(delivery, "observations", observations)
    object.__setattr__(delivery, "_native_projection", native)
    assert registry.retained_native_batch_projection(delivery) == _ROWS
    if not committed:
        registry.cancel_batch(delivery)


def test_batch_native_scope_is_exact_same_thread_and_cannot_reseal_tampering() -> None:
    registry = _registry()
    delivery = _prepare(registry)
    with registry.prepared_batch(delivery) as claim:
        claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
        with pytest.raises(StateError, match="active preparation"):
            replace(claim).freeze_native_projections(_ROWS)
        with ThreadPoolExecutor(max_workers=1) as worker:
            future = worker.submit(claim.freeze_native_projections, _ROWS)
            with pytest.raises(StateError, match="active preparation"):
                future.result(timeout=5)
        native = delivery._native_projection
        original = native.ndjson
        object.__setattr__(native, "ndjson", "".join(reversed(_ROWS)))
        with pytest.raises(StateError, match="counter observations"):
            claim.freeze_native_projections(tuple(reversed(_ROWS)), canonical_token=_TOKEN)
        object.__setattr__(native, "ndjson", original)
        observations = delivery.observations
        object.__setattr__(delivery, "observations", tuple(reversed(observations)))
        with pytest.raises(StateError, match="counter observations"):
            claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
        object.__setattr__(delivery, "observations", observations)
    with pytest.raises(StateError, match="active preparation"):
        claim.freeze_native_projections(_ROWS)
    registry.cancel_batch(delivery)


def test_lost_counter_return_preserves_whole_native_batch_without_duplicate_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry()
    delivery = _prepare(registry)
    original = PreparedESDeliveryBatchCommit.commit_no_fail

    def lost_return(claim: PreparedESDeliveryBatchCommit) -> None:
        original(claim)
        raise RuntimeError("invented lost return")

    monkeypatch.setattr(PreparedESDeliveryBatchCommit, "commit_no_fail", lost_return)
    with pytest.raises(RuntimeError, match="invented lost"):
        with registry.prepared_batch(delivery) as claim:
            claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
            claim.commit_no_fail()
    assert registry.completed_batch(delivery) == delivery.observations
    assert registry.retained_native_batch_projection(delivery, canonical_token=_TOKEN) == _ROWS
    monkeypatch.setattr(PreparedESDeliveryBatchCommit, "commit_no_fail", original)
    registry.commit_batch(delivery)
    assert registry.connection("mac-a:es-client").next_delivery == 3


def test_cancelled_and_foreign_groups_cannot_resurrect_rows() -> None:
    registry = _registry()
    delivery = _prepare(registry)
    with registry.prepared_batch(delivery) as claim:
        claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
    with pytest.raises(StateError, match="stale or foreign"):
        ESCollectorRegistry().retained_native_batch_projection(delivery)
    registry.cancel_batch(delivery)
    with pytest.raises(StateError, match="stale or foreign"):
        registry.retained_native_batch_projection(delivery)
    replacement = _prepare(registry)
    with registry.prepared_batch(replacement) as claim:
        claim.freeze_native_projections(tuple(reversed(_ROWS)), canonical_token=_TOKEN)
    registry.cancel_batch(replacement)


def test_counter_only_batch_cannot_acquire_native_rows_after_completion() -> None:
    registry = _registry()
    delivery = _prepare(registry)
    registry.commit_batch(delivery)
    with registry.prepared_batch(delivery) as claim:
        with pytest.raises(StateError, match="before counter publication"):
            claim.freeze_native_projections(_ROWS, canonical_token=_TOKEN)
    assert registry.retained_native_batch_projection(delivery) is None
    with pytest.raises(StateError, match="another canonical"):
        registry.retained_native_batch_projection(delivery, canonical_token=_TOKEN)


@pytest.mark.parametrize("token", ["", "A" * 64, "a" * 63, 1])
def test_native_batch_canonical_token_is_an_exact_bounded_value(token: object) -> None:
    registry = _registry()
    delivery = _prepare(registry)
    with registry.prepared_batch(delivery) as claim:
        with pytest.raises(StateError, match="canonical publication token"):
            claim.freeze_native_projections(_ROWS, canonical_token=token)
    with pytest.raises(StateError, match="canonical publication token"):
        registry.retained_native_batch_projection(delivery, canonical_token=token)
    registry.cancel_batch(delivery)
