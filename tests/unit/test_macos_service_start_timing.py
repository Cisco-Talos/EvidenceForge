# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""System-job activation owns source timing with canonical allocation."""

import pytest

from tests.unit.test_macos_persistence_workflow import _request, _workflow


def test_rejected_activation_leaves_timing_state_unchanged() -> None:
    bundle, caller, host, definition, path, _ = _workflow()
    for index, stage in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, stage, index))
    timing = bundle.dispatcher.source_timing_planner
    before = timing.state_digest()
    before_state = bundle.state.materialization_digest()

    def fail() -> None:
        raise RuntimeError("injected activation precommit failure")

    bundle.authority._materialization_precommit_hook = fail
    with pytest.raises(RuntimeError, match="injected activation"):
        bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert timing.state_digest() == before
    assert bundle.state.materialization_digest() == before_state
    assert bundle.services.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("stage", ["source_prepare", "source_validate", "service_prepare"])
def test_activation_preparation_failure_releases_timing_and_remains_retryable(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    bundle, caller, host, definition, path, _ = _workflow()
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    timing = bundle.dispatcher.source_timing_planner
    before = timing.state_digest()
    before_state = bundle.state.materialization_digest()
    if stage == "service_prepare":
        target, method = type(bundle.services), "prepare_service_publication"
    else:
        target = bundle.dispatcher
        method = "prepare_builder" if stage == "source_prepare" else "validate_prepared"
    original = getattr(target, method)

    def fail(*args: object, **kwargs: object) -> None:
        if stage == "source_prepare":
            original(*args, **kwargs)
        raise RuntimeError("injected activation preparation failure")

    with monkeypatch.context() as patch:
        patch.setattr(target, method, fail)
        with pytest.raises(RuntimeError, match="injected activation"):
            bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert timing.state_digest() == before
    assert bundle.state.materialization_digest() == before_state
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert timing.preparation_authority_census().active_claims == 0
    result = bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert bundle.state.get_process(result.process.hostname, result.process.pid) is not None


@pytest.mark.parametrize(
    "stage", ["lifecycle", "state_before", "state_after", "timing_before", "timing_after"]
)
def test_activation_adopts_exact_commits_after_lost_acknowledgements(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    from evidenceforge.generation.lifecycle_registry import PreparedLifecycleStartBatch
    from evidenceforge.generation.source_timing import SourceTimingPreparation
    from evidenceforge.generation.state_manager import StateManager

    bundle, caller, host, definition, path, emitter = _workflow()
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    emitter.reset_mock()
    if stage == "lifecycle":
        target, method = PreparedLifecycleStartBatch, "commit"
    elif stage.startswith("state"):
        target, method = StateManager, "_commit_prevalidated_process_materialization"
    else:
        target, method = SourceTimingPreparation, "commit_no_fail"
    original = getattr(target, method)
    calls = 0

    def fail(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            if stage in {"lifecycle", "state_after", "timing_after"}:
                original(*args, **kwargs)
            raise RuntimeError("injected activation lost acknowledgement")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method, fail)
    before = bundle.state.materialization_version
    result = bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert calls == (2 if stage in {"state_before", "timing_before"} else 1)
    assert bundle.state.materialization_version == before + 1
    assert (
        bundle.state.get_process_identity(result.process.hostname, result.process.pid)
        == result.process
    )
    assert bundle.lifecycle.get_process(result.process.object_id) is not None
    assert emitter.emit.call_count == 1
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert bundle.dispatcher.source_timing_planner.preparation_authority_census().active_claims == 0


def test_activation_source_rejects_a_different_committed_timing_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from evidenceforge.models.exceptions import EventContractError

    bundle, caller, host, definition, path, emitter = _workflow()
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    retained = []
    original = bundle.dispatcher.publish_prepared

    def retain(prepared: object, *, materialization_receipt: object) -> None:
        retained.append((prepared, materialization_receipt))

    with monkeypatch.context() as patch:
        patch.setattr(bundle.dispatcher, "publish_prepared", retain)
        bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    prepared, proof = retained[0]
    timing = bundle.dispatcher.source_timing_planner
    with timing.prepared_planning() as unrelated:
        pass
    with unrelated.claimed_commit():
        other = unrelated.commit_no_fail()
    emitter.reset_mock()
    with pytest.raises(EventContractError, match="does not own this source timing"):
        original(prepared, materialization_receipt=replace(proof, source_timing_receipt=other))
    assert not emitter.emit.called
    original(prepared, materialization_receipt=proof)
    assert emitter.emit.call_count == 1
