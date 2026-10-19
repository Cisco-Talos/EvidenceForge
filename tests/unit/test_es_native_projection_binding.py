# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry, PreparedESDeliveryCommit
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector_ownership import _prepare, _setup
from tests.unit.test_process_execution_state import _START

_LINE = '{"invented":"source-owned-native-bytes"}\n'


def test_reserved_bytes_are_frozen_once_then_recovered_after_commit_and_restart() -> None:
    _, process, owner, profile = _setup()
    delivery = _prepare(owner, process)
    assert owner.collectors.retained_native_projection(delivery) is None
    with owner.prepared_commit(delivery, process) as claimed:
        assert claimed.freeze_native_projection(_LINE) == _LINE
        assert claimed.freeze_native_projection(_LINE) == _LINE
    assert owner.collectors.connection(profile.source_instance) == profile
    assert owner.collectors.retained_native_projection(delivery) == _LINE
    with owner.prepared_commit(delivery, process) as claimed:
        with pytest.raises(StateError, match="changed"):
            claimed.freeze_native_projection('{"changed":true}\n')
        claimed.commit_no_fail()
    assert owner.collectors.retained_native_projection(delivery) == _LINE
    assert owner.commit(delivery, process) == delivery.observation
    owner.open(
        profile.model_copy(
            update={
                "generation": 2,
                "opened_at": _START + timedelta(seconds=10),
                "last_delivery_at": _START + timedelta(seconds=10),
            }
        ),
        process,
    )
    assert owner.collectors.retained_native_projection(delivery) == _LINE
    assert owner.collectors.connection(profile.source_instance).next_delivery == 0


def test_cancelled_bytes_and_foreign_registry_cannot_be_resurrected() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        claimed.freeze_native_projection(_LINE)
    with pytest.raises(StateError, match="stale or foreign"):
        ESCollectorRegistry().retained_native_projection(delivery)
    owner.collectors.cancel(delivery)
    with pytest.raises(StateError, match="stale or foreign"):
        owner.collectors.retained_native_projection(delivery)
    replacement = _prepare(owner, process)
    with owner.prepared_commit(replacement, process) as claimed:
        assert claimed.freeze_native_projection('{"new-reservation":true}\n')
    owner.collectors.cancel(replacement)


@pytest.mark.parametrize(
    "damage", ["copy", "payload", "proof", "observation", "unicode", "missing", "canonical"]
)
@pytest.mark.parametrize("committed", [False, True])
def test_changed_binding_rejects_without_counter_replay(damage: str, committed: bool) -> None:
    _, process, owner, profile = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        claimed.freeze_native_projection(_LINE)
        if committed:
            claimed.commit_no_fail()
    before = owner.collectors.connection(profile.source_instance)
    original = delivery._native_projection
    observation = delivery.observation
    checked = delivery
    if damage == "copy":
        checked = replace(delivery)
    elif damage == "observation":
        object.__setattr__(delivery, "observation", observation.model_copy(update={"seq_num": 42}))
    elif damage == "missing":
        object.__setattr__(delivery, "_native_projection", None)
    else:
        changes = {"ndjson": "different\n"} if damage == "payload" else {"proof": b"forged"}
        if damage == "unicode":
            changes = {"ndjson": "\ud800\n"}
        elif damage == "canonical":
            changes = {"canonical_token": "b" * 64}
        object.__setattr__(delivery, "_native_projection", replace(original, **changes))
    with pytest.raises(StateError):
        owner.collectors.retained_native_projection(checked)
    with pytest.raises(StateError):
        owner.commit(checked, process)
    assert owner.collectors.connection(profile.source_instance) == before
    object.__setattr__(delivery, "observation", observation)
    object.__setattr__(delivery, "_native_projection", original)
    assert owner.collectors.retained_native_projection(delivery) == _LINE
    if not committed:
        owner.collectors.cancel(delivery)


def test_in_scope_observation_tampering_cannot_reseal_replacement_counter_facts() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    original = delivery.observation
    with owner.prepared_commit(delivery, process) as claimed:
        object.__setattr__(delivery, "observation", original.model_copy(update={"seq_num": 42}))
        with pytest.raises(StateError, match="counter observation"):
            claimed.freeze_native_projection(_LINE)
        object.__setattr__(delivery, "observation", original)
        assert claimed.freeze_native_projection(_LINE) == _LINE
    owner.collectors.cancel(delivery)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "\n",
        "no newline",
        "one\ntwo\n",
        "cr\r\n",
        "\ud800\n",
        "x" * (1024 * 1024) + "\n",
        "é" * (600 * 1024) + "\n",
    ],
)
def test_invalid_or_oversized_native_rows_do_not_bind_or_advance(payload: str) -> None:
    _, process, owner, profile = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        with pytest.raises(StateError):
            claimed.freeze_native_projection(payload)
    assert owner.collectors.retained_native_projection(delivery) is None
    assert owner.collectors.connection(profile.source_instance) == profile
    owner.collectors.cancel(delivery)


def test_counter_only_completion_cannot_acquire_new_native_bytes_later() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    owner.commit(delivery, process)
    with owner.prepared_commit(delivery, process) as claimed:
        with pytest.raises(StateError, match="before counter publication"):
            claimed.freeze_native_projection(_LINE)
    assert owner.collectors.retained_native_projection(delivery) is None


def test_native_binding_requires_exact_active_same_thread_handle() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        with pytest.raises(StateError):
            replace(claimed).freeze_native_projection(_LINE)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(claimed.freeze_native_projection, _LINE)
            with pytest.raises(StateError):
                future.result(timeout=2)
        assert claimed.freeze_native_projection(_LINE) == _LINE
    with pytest.raises(StateError):
        claimed.freeze_native_projection(_LINE)
    owner.collectors.cancel(delivery)


def test_lost_counter_commit_return_keeps_the_original_authenticated_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    original = PreparedESDeliveryCommit.commit_no_fail

    def lost_return(handle: PreparedESDeliveryCommit) -> None:
        original(handle)
        raise RuntimeError("invented lost counter return")

    with owner.prepared_commit(delivery, process) as claimed:
        claimed.freeze_native_projection(_LINE)
        monkeypatch.setattr(PreparedESDeliveryCommit, "commit_no_fail", lost_return)
        with pytest.raises(RuntimeError, match="lost counter"):
            claimed.commit_no_fail()
    monkeypatch.undo()
    assert owner.commit(delivery, process) == delivery.observation
    assert owner.collectors.retained_native_projection(delivery) == _LINE


def test_native_bytes_are_bound_to_the_exact_canonical_publication_token() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    token = "a" * 64
    with owner.prepared_commit(delivery, process) as claimed:
        claimed.freeze_native_projection(_LINE, canonical_token=token)
        with pytest.raises(StateError, match="changed"):
            claimed.freeze_native_projection(_LINE, canonical_token="b" * 64)
        with pytest.raises(StateError, match="changed"):
            claimed.freeze_native_projection(_LINE)
    assert owner.collectors.retained_native_projection(delivery, canonical_token=token) == _LINE
    with pytest.raises(StateError, match="another canonical"):
        owner.collectors.retained_native_projection(delivery, canonical_token="b" * 64)
    owner.commit(delivery, process)
    assert owner.collectors.retained_native_projection(delivery, canonical_token=token) == _LINE


@pytest.mark.parametrize("token", ["", "a", "g" * 64, "A" * 64, True, b"a" * 64])
def test_malformed_canonical_binding_is_rejected_before_freezing(token: object) -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        with pytest.raises(StateError, match="canonical publication token"):
            claimed.freeze_native_projection(_LINE, canonical_token=token)
    assert owner.collectors.retained_native_projection(delivery) is None
    owner.collectors.cancel(delivery)


@pytest.mark.parametrize("family", ["fork", "exec", "exit"])
def test_prepared_native_families_retain_proven_bytes_after_canonical_transition(
    family: str,
) -> None:
    from tests.unit import test_macos_es_exec_preparation as exec_preparation
    from tests.unit import test_macos_es_exit_preparation as exit_preparation
    from tests.unit import test_macos_es_fork_preparation as fork_preparation

    module = {"fork": fork_preparation, "exec": exec_preparation, "exit": exit_preparation}[family]
    fixture = module._fixture()
    with module._prepare(fixture) as prepared:
        frozen = prepared.ndjson
        fixture.owner.state.materialize_action_cohort(fixture.cohort)
        prepared.collector.commit_no_fail()
    assert (
        fixture.owner.collectors.retained_native_projection(
            fixture.delivery, canonical_token=fixture.cohort.publication_token
        )
        == frozen
    )
    with pytest.raises(StateError, match="retained native bytes"):
        with module._prepare(fixture):
            pytest.fail("completed native event was re-observed")


def test_in_scope_native_value_mutation_cannot_reseal_different_bytes() -> None:
    _, process, owner, _ = _setup()
    delivery = _prepare(owner, process)
    with owner.prepared_commit(delivery, process) as claimed:
        claimed.freeze_native_projection(_LINE)
        native = delivery._native_projection
        object.__setattr__(native, "ndjson", "replacement\n")
        with pytest.raises(StateError, match="counter observation"):
            claimed.freeze_native_projection("replacement\n")
        object.__setattr__(native, "ndjson", _LINE)
        assert claimed.freeze_native_projection(_LINE) == _LINE
    owner.collectors.cancel(delivery)
