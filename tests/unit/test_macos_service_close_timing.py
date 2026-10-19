# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authored service closures stage timing with their canonical owners."""

import pytest

from tests.unit.test_macos_persistence_workflow import _request, _workflow


@pytest.mark.parametrize("operation", ["exit", "unload"])
def test_rejected_service_close_does_not_publish_source_timing(operation: str) -> None:
    bundle, caller, host, definition, path, _ = _workflow()
    for index, stage in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, stage, index))
    timing = bundle.dispatcher.source_timing_planner
    before = timing.state_digest()
    before_audit = timing.timing_runtime.audit.snapshot()

    def fail() -> None:
        raise RuntimeError("injected service precommit failure")

    bundle.authority._materialization_precommit_hook = fail
    with pytest.raises(RuntimeError, match="injected service"):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, 10))
    assert timing.state_digest() == before
    assert timing.timing_runtime.audit.snapshot() == before_audit
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is not None
    assert bundle.services.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("stage", ["source_prepare", "source_validate", "service_prepare"])
def test_service_close_preparation_failure_releases_timing_lane(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    bundle, caller, host, definition, path, _ = _workflow()
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    timing = bundle.dispatcher.source_timing_planner
    before = timing.state_digest()
    if stage == "source_prepare":
        target, method = bundle.dispatcher, "prepare_builder"
    elif stage == "source_validate":
        target, method = bundle.dispatcher, "validate_prepared"
    else:
        target, method = type(bundle.services), "prepare_service_process_closure"
    original = getattr(target, method)

    def fail(*args: object, **kwargs: object) -> None:
        if stage == "source_prepare":
            original(*args, **kwargs)
        raise RuntimeError("injected preparation failure")

    with monkeypatch.context() as patch:
        patch.setattr(target, method, fail)
        with pytest.raises(RuntimeError, match="injected preparation"):
            bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    assert timing.state_digest() == before
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is not None
    assert timing.preparation_authority_census().active_claims == 0
    # An exact retry proves the failed overlay released its exclusive planning lane.
    bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is None


@pytest.mark.parametrize("after_commit", [False, True])
def test_timing_lost_acknowledgement_does_not_duplicate_service_close(
    monkeypatch: pytest.MonkeyPatch, after_commit: bool
) -> None:
    from evidenceforge.generation.source_timing import SourceTimingPreparation

    bundle, caller, host, definition, path, emitter = _workflow()
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    emitter.reset_mock()
    original = SourceTimingPreparation.commit_no_fail
    failed = False

    def fail(prepared: SourceTimingPreparation) -> object:
        nonlocal failed
        if not failed:
            failed = True
            if after_commit:
                original(prepared)
            raise RuntimeError("injected timing lost acknowledgement")
        return original(prepared)

    monkeypatch.setattr(SourceTimingPreparation, "commit_no_fail", fail)
    bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    assert failed
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is None
    assert emitter.emit.call_count == 1
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert bundle.dispatcher.source_timing_planner.preparation_authority_census().active_claims == 0


def test_lost_service_acknowledgement_retains_committed_timing_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    bundle, caller, host, definition, path, _ = _workflow()
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    original = bundle.lifecycle._service_closure_receipt_locked

    def fail(plan: object) -> None:
        original(plan)
        raise RuntimeError("injected service lost acknowledgement")

    retained = []
    publish = bundle.dispatcher.publish_prepared

    def capture(prepared: object, *, materialization_receipt: object) -> object:
        retained.append(materialization_receipt)
        return publish(prepared, materialization_receipt=materialization_receipt)

    monkeypatch.setattr(bundle.lifecycle, "_service_closure_receipt_locked", fail)
    monkeypatch.setattr(bundle.dispatcher, "publish_prepared", capture)
    bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    proof = retained[0]
    assert proof.source_timing_receipt is not None
    assert bundle.dispatcher.source_timing_planner.authenticates_preparation_receipt(
        proof.source_timing_receipt
    )
    assert proof.authenticates(bundle.authority._receipt_secret)
    assert not replace(proof, source_timing_receipt=None).authenticates(
        bundle.authority._receipt_secret
    )
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is None


def test_group_dispatch_cannot_substitute_another_committed_timing_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.posix_group_closure import PosixGroupServiceClosureReceipt
    from evidenceforge.models.exceptions import EventContractError

    bundle, caller, host, definition, path, emitter = _workflow()
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    retained = []
    original = bundle.dispatcher.publish_prepared

    def retain(prepared: object, *, materialization_receipt: object) -> None:
        retained.append((prepared, materialization_receipt))

    with monkeypatch.context() as patch:
        patch.setattr(bundle.dispatcher, "publish_prepared", retain)
        bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    prepared, receipt = retained[0]
    timing = bundle.dispatcher.source_timing_planner
    with timing.prepared_planning() as unrelated:
        pass
    with unrelated.claimed_commit():
        other = unrelated.commit_no_fail()
    mismatched = PosixGroupServiceClosureReceipt.issue(
        secret=bundle.authority._receipt_secret,
        group=receipt.group,
        plans=(prepared._lifecycle_ticket,),
        service_receipt=receipt.service_receipt,
        prior_version=receipt.prior_version,
        committed_version=receipt.committed_version,
        collector_publication_token=receipt.collector_publication_token,
        source_timing_receipt=other,
    )
    assert bundle.authority.authenticates_process_service_closure_composite_receipt(
        prepared._lifecycle_ticket, mismatched
    )
    emitter.reset_mock()
    with pytest.raises(EventContractError, match="does not own this source timing"):
        original(prepared, materialization_receipt=mismatched)
    assert not emitter.emit.called
    original(prepared, materialization_receipt=receipt)
    assert emitter.emit.call_count == 1


def test_foreign_timing_owner_is_rejected_without_cancelling_its_preparation() -> None:
    from evidenceforge.generation.source_timing import SourceTimingPlanner
    from evidenceforge.models.exceptions import StateError
    from tests.unit.test_service_group_closure import _owned_group

    state, _, authority, adapter, group, plan, request = _owned_group()
    owner = SourceTimingPlanner()
    foreign = SourceTimingPlanner()
    authority.bind_source_timing_planner(owner)
    before = state.materialization_digest()
    with foreign.prepared_planning() as preparation:
        pass
    try:
        with pytest.raises(StateError, match="exact uncommitted source timing owner"):
            authority.materialize_process_group_service_closure_composite(
                plan,
                group,
                adapter.prepare_service_process_closure(request),
                source_timing_preparation=preparation,
            )
        assert state.materialization_digest() == before
        assert foreign.authenticates_preparation(preparation)
        assert adapter.service_preparation_census().reserved_keys == 0
    finally:
        preparation.cancel()
