# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Counter publication joins an outer commit without source-local half commits."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector_ownership import _prepare, _setup
from tests.unit.test_process_execution_state import _execute


def test_preclaimed_delivery_cancels_without_consuming_sequence() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with owner.prepared_commit(token, process) as prepared:
        assert prepared.observation == token.observation
        assert owner.collectors.connection(profile.source_instance) == profile
        with pytest.raises(StateError, match="unclaimed"):
            owner.collectors.cancel(token)
        with pytest.raises(StateError, match="active commit scope"):
            owner.collectors.commit(token)
        with pytest.raises(StateError, match="completed or cancelled"):
            owner.collectors.snapshot()
    with pytest.raises(StateError, match="active preparation"):
        prepared.commit_no_fail()
    owner.collectors.cancel(token)
    assert owner.collectors.snapshot() == (profile,)


def test_precommit_exception_rolls_back_state_and_keeps_counter_reservation() -> None:
    state, process, owner, profile = _setup()
    token = _prepare(owner, process)
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(process, token.observation.observed_at)
    plan = builder.seal()
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="injected"):
        with owner.prepared_commit(token, process):
            with state.prepared_action_cohort_materialization(plan) as prepared:
                prepared.certify_composite_commit(prepared.expected_result)
                prepared.apply_provisional()
                raise RuntimeError("injected precommit source preparation failure")
    assert state.materialization_digest() == before
    assert owner.collectors.connection(profile.source_instance) == profile
    assert owner.collectors.completed_observation(token) is None
    owner.collectors.cancel(token)


def test_commit_has_no_validation_callback_and_completed_retry_survives_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, process, owner, profile = _setup()
    token = _prepare(owner, process)
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(process, token.observation.observed_at)
    plan = builder.seal()
    with owner.prepared_commit(token, process) as collector:
        with state.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            with monkeypatch.context() as patch:

                def forbidden(*args: object, **kwargs: object) -> None:
                    raise AssertionError("commit tried to compute a completion proof")

                patch.setattr(ESCollectorRegistry, "_proof", forbidden)
                prepared.finalize_no_fail()
                collector.commit_no_fail()
                collector.commit_no_fail()
    observed = owner.collectors.completed_observation(token)
    assert observed == token.observation
    assert owner.collectors.connection(profile.source_instance).next_delivery == 1
    _execute(state, process, seconds=6)
    with owner.prepared_commit(token, process) as completed:
        completed.commit_no_fail()
        assert completed.observation == observed
    assert owner.collectors.connection(profile.source_instance).next_delivery == 1


def test_failed_return_after_commit_retains_exact_proof_and_does_not_duplicate() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with pytest.raises(RuntimeError, match="lost return"):
        with owner.prepared_commit(token, process) as prepared:
            prepared.commit_no_fail()
            raise RuntimeError("injected lost return")
    assert owner.commit(token, process) == token.observation
    assert owner.collectors.connection(profile.source_instance).next_delivery == 1


def test_preclaimed_handle_cannot_commit_from_another_thread() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with owner.prepared_commit(token, process) as prepared:
        with ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(prepared.commit_no_fail)
            with pytest.raises(StateError, match="active preparation"):
                result.result(timeout=2)
        assert owner.collectors.connection(profile.source_instance) == profile
        prepared.commit_no_fail()


def test_copied_handle_and_capability_cannot_commit_a_reserved_delivery() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with pytest.raises(StateError, match="stale"):
        with owner.prepared_commit(replace(token), process):
            pytest.fail("copied capability admitted")
    with owner.prepared_commit(token, process) as prepared:
        copied = replace(prepared)
        with pytest.raises(StateError, match="active preparation"):
            copied.commit_no_fail()
        assert owner.collectors.connection(profile.source_instance) == profile
    owner.collectors.cancel(token)


def test_owner_exec_before_claim_rejects_without_consuming_counters() -> None:
    state, process, owner, profile = _setup()
    token = _prepare(owner, process)
    _execute(state, process)
    with pytest.raises(StateError, match="live Mac"):
        with owner.prepared_commit(token, process):
            pytest.fail("stale collector execution admitted")
    assert owner.collectors.connection(profile.source_instance) == profile
    owner.collectors.cancel(token)
