# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production service workflows adopt exact completed closure proofs once."""

from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.state_manager import PreparedActionCohortMaterialization
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_persistence_workflow import _request, _workflow


def _active_group(collect: bool = True) -> tuple:
    bundle, caller, host, definition, path, emitter = _workflow(collect)
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    identities = [result.process]
    for index in (4, 5):
        plan = bundle.state.plan_process_materialization(
            system=host.hostname,
            parent_pid=identities[-1].pid,
            image=f"/usr/local/libexec/invented-child-{index}",
            command_line="invented-child",
            username="root",
            integrity_level="Medium",
            os_category="macos",
            credentials=PosixProcessCredentials(0, 0, 0, 0),
            start_time=_START + timedelta(seconds=index),
        )
        bundle.authority.materialize_process(plan)
        identities.append(plan.identity)
    collector = ESCollectionActionOwner(bundle.state, bundle.dispatcher.es_collectors)
    profile = collector.open(
        _profile(
            hostname=host.hostname,
            opened_at=identities[0].started_at,
            last_delivery_at=identities[0].started_at,
        ),
        identities[0],
    )
    emitter.reset_mock()
    return bundle, caller, host, definition, path, emitter, tuple(identities), collector, profile


@pytest.mark.parametrize("stage", ["service", "state", "collector"])
@pytest.mark.parametrize("collect", [False, True])
@pytest.mark.parametrize("operation", ["exit", "unload"])
def test_group_unload_finishes_source_publication_after_exact_owner_lost_return(
    monkeypatch: pytest.MonkeyPatch, stage: str, collect: bool, operation: str
) -> None:
    bundle, caller, host, definition, path, emitter, identities, collector, profile = _active_group(
        collect
    )
    if stage == "service":
        target, method = bundle.lifecycle, "_service_closure_receipt_locked"
    elif stage == "state":
        target, method = PreparedActionCohortMaterialization, "finalize_no_fail"
    else:
        target, method = ESCollectorRegistry, "_finalize_closures"
    original = getattr(target, method)
    calls = 0

    def fail(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        original(*args, **kwargs)
        raise RuntimeError("injected completed closure lost return")

    monkeypatch.setattr(target, method, fail)
    before = bundle.state.materialization_version
    request = _request(bundle, caller, host, definition, path, operation, 10)
    result = bundle.execute(request)
    assert calls == 1
    assert bundle.state.materialization_version == before + 1
    terminated = identities if operation == "unload" else identities[:1]
    assert set(result.terminated) == set(terminated)
    assert all(bundle.state.get_process(item.hostname, item.pid) is None for item in terminated)
    if operation == "exit":
        assert all(
            bundle.state.get_process(item.hostname, item.pid) is not None for item in identities[1:]
        )
        assert (
            bundle.state.get_process_identity(identities[1].hostname, identities[1].pid).parent_pid
            == 1
        )
    assert collector.collectors.connection(profile.source_instance).closed_at == request.timestamp
    assert emitter.emit.call_count == (len(terminated) if collect else 0)
    if collect:
        assert {call.args[0].process.pid for call in emitter.emit.call_args_list} == {
            item.pid for item in terminated
        }
    assert bundle.services.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("damage", ["absent", "integrity", "members", "timing"])
def test_workflow_rejects_damaged_preallocated_owner_proof(
    monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from evidenceforge.models.exceptions import EventContractError, StateError

    bundle, caller, host, definition, path, _, identities, _, _ = _active_group()
    original = bundle.dispatcher._prepare_action_cohort_publication_objects

    def damage_result(record: object) -> None:
        original(record)
        if damage == "absent":
            record.expected_lifecycle_receipt = None
        elif damage == "integrity":
            object.__setattr__(record.expected_lifecycle_receipt, "_integrity", "0" * 64)
        elif damage == "members":
            object.__setattr__(record.expected_lifecycle_receipt, "processes", ())
        else:
            record.expected_timing_receipt = None

    monkeypatch.setattr(
        bundle.dispatcher, "_prepare_action_cohort_publication_objects", damage_result
    )
    before = bundle.state.materialization_digest()
    with pytest.raises(
        (EventContractError, StateError), match="authentication|before certification"
    ):
        bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    assert bundle.state.materialization_digest() == before
    assert all(bundle.state.get_process(item.hostname, item.pid) is not None for item in identities)
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert bundle.dispatcher.action_cohort_publication_census().retained_bytes == 0


def test_completed_close_does_not_swallow_a_user_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, caller, host, definition, path, emitter, identities, _, _ = _active_group()
    original = bundle.lifecycle._service_closure_receipt_locked

    def interrupt(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)
        raise KeyboardInterrupt("injected user interruption")

    monkeypatch.setattr(bundle.lifecycle, "_service_closure_receipt_locked", interrupt)
    with pytest.raises(KeyboardInterrupt, match="user interruption") as caught:
        bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    receipt = caught.value.action_cohort_receipt
    result = bundle.dispatcher.resume_action_cohort_projection(receipt)
    assert bundle.dispatcher.authenticates_action_cohort_publication_receipt(receipt)
    assert all(bundle.state.get_process(item.hostname, item.pid) is None for item in identities)
    assert all(item.status == "succeeded" for item in result.projections)
    bundle.dispatcher.assert_exact_projection_recoveries_drained()


@pytest.mark.parametrize("ordinal", [1, 2, 3])
@pytest.mark.parametrize("after_write", [False, True])
def test_authored_group_cleanup_recovers_exact_rows_after_partial_write(
    monkeypatch: pytest.MonkeyPatch, ordinal: int, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
    from tests.unit.test_macos_exact_exit_group import _rows

    bundle, caller, host, definition, path, emitter, identities, _, _ = _active_group()
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == ordinal:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected authored partial row")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    with pytest.raises(RuntimeError, match="authored partial row") as caught:
        bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    version = bundle.state.materialization_version
    result = bundle.dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert bundle.state.materialization_version == version
    assert all(item.status == "succeeded" for item in result.projections)
    bundle.dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [row for row in _rows(emitter.output_path) if row["action"] == "TERMINATE"]
    assert len(rows) == len(identities)
    assert {row["objectID"] for row in rows} == {item.object_id for item in identities}


@pytest.mark.parametrize("stage", ["state", "timing", "collector"])
@pytest.mark.parametrize("after_commit", [False, True])
@pytest.mark.parametrize("interrupt", [False, True])
def test_authored_close_recovers_one_owner_fault_and_preserves_user_interrupt(
    monkeypatch: pytest.MonkeyPatch, stage: str, after_commit: bool, interrupt: bool
) -> None:
    from evidenceforge.generation.source_timing import SourceTimingPreparation

    bundle, caller, host, definition, path, _, identities, _, profile = _active_group()
    if stage == "state":
        target, method = PreparedActionCohortMaterialization, "finalize_no_fail"
    elif stage == "timing":
        target, method = SourceTimingPreparation, "commit_no_fail"
    else:
        target, method = ESCollectorRegistry, "_finalize_closures"
    original = getattr(target, method)
    attempts = 0

    def fail(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_commit:
                original(*args, **kwargs)
            if interrupt:
                raise KeyboardInterrupt("injected canonical interruption")
            raise RuntimeError("injected canonical return failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method, fail)
    before = bundle.state.materialization_version
    request = _request(bundle, caller, host, definition, path, "unload", 10)
    if interrupt:
        with pytest.raises(KeyboardInterrupt, match="canonical interruption") as caught:
            bundle.execute(request)
        bundle.dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    else:
        bundle.execute(request)
    assert attempts == (1 if after_commit else 2)
    assert bundle.state.materialization_version == before + 1
    assert all(bundle.state.get_process(item.hostname, item.pid) is None for item in identities)
    assert (
        bundle.dispatcher.es_collectors.connection(profile.source_instance).closed_at
        == request.timestamp
    )
    bundle.dispatcher.assert_exact_projection_recoveries_drained()
