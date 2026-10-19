# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Service-owned Mac terminal cohorts use the existing exact source transaction."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import ActionCohortServiceClosure
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_leader_exit_completion_plan,
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.utils.rng import stable_uuid
from tests.unit.test_macos_exact_exit_group import _rows
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_service_close_adoption import _active_group


def _prepare(
    tmp_path: Path, *, collected: bool = True, leader_only: bool = False, threaded: bool = False
) -> tuple:
    bundle, caller, host, definition, _, _, identities, collector, profile = _active_group(False)
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    bundle.dispatcher.emitters = {"ecar": emitter} if collected else {}
    at = _START + timedelta(seconds=10)
    job = bundle.lifecycle.service_for_logical_at(
        host.hostname,
        stable_uuid(
            "macos-launchd-system-job",
            bundle.deployments.host_deployment(host.hostname).hostname,
            definition.label,
        ),
        at,
    )
    factory = (
        macos_system_job_leader_exit_completion_plan
        if leader_only
        else macos_system_job_unload_completion_plan
    )
    close = factory(
        lifecycle_registry=bundle.lifecycle,
        state_manager=bundle.state,
        service_object_id=job.identity.object_id,
        completed_at=at,
        action_id="exact-service-close",
    )
    root = (
        f"process-exit:{identities[0].object_id}"
        if leader_only
        else "process-exit-group:exact-service"
    )
    with bundle.dispatcher.source_timing_planner.prepared_planning() as timing:
        carriers = []
        for item in close.cohort.process_terminations:
            live = bundle.state.get_process(item.identity.hostname, item.identity.pid)
            event = process_exit_occurrence(
                host=host,
                process=item.identity,
                timestamp=item.end_time,
                integrity_level=live.integrity_level,
            )
            event.process.exit_outcome = item.exit_outcome
            carriers.append(
                bundle.dispatcher.prepare_action_cohort_projection(
                    event, source_timing_preparation=timing
                )
            )
    dispatches = tuple(
        bundle.dispatcher.bind_action_cohort_projection(item, state_plan=close.cohort)
        for item in carriers
    )
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    batch = bundle.dispatcher.prepare_action_cohort_batch(
        root,
        close.cohort,
        dispatches,
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=True,
        service_closure=ActionCohortServiceClosure(close.group, close.closure, not leader_only),
    )
    return bundle, emitter, identities, profile, close, batch


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("leader_only", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_exact_service_terminal_batch_commits_all_owners_once(
    tmp_path: Path, collected: bool, leader_only: bool, threaded: bool
) -> None:
    bundle, emitter, identities, profile, close, batch = _prepare(
        tmp_path, collected=collected, leader_only=leader_only, threaded=threaded
    )
    before = bundle.state.materialization_version
    result = bundle.dispatcher.publish_prepared_action_cohort_batch(batch)
    assert bundle.state.materialization_version == before + 1
    assert bundle.lifecycle.authenticates_service_process_closure_receipt(
        result.lifecycle, request=close.closure
    )
    assert bundle.dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert bundle.dispatcher.es_collectors.connection(
        profile.source_instance
    ).closed_at == _START + timedelta(seconds=10)
    assert len(result.projections) == (1 if leader_only else 3)
    for identity in identities[:1] if leader_only else identities:
        assert bundle.state.get_process(identity.hostname, identity.pid) is None
    if leader_only:
        child = bundle.state.get_process_identity_by_object_id(identities[1].object_id)
        assert child.parent_pid == 1
        assert len(bundle.state.get_posix_group_members(close.group)) == 2
    bundle.dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == (len(result.projections) if collected else 0)


@pytest.mark.parametrize("after_write", [False, True])
@pytest.mark.parametrize("ordinal", [1, 2, 3])
def test_exact_service_group_recovers_partial_sink_without_reclosing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool, ordinal: int
) -> None:
    original = ExternalSortedLineWriter._commit_exact_row
    calls = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal calls
        calls += 1
        if calls == ordinal:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected exact service row failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    bundle, emitter, identities, profile, close, batch = _prepare(tmp_path)
    with pytest.raises(RuntimeError, match="service row failure") as caught:
        bundle.dispatcher.publish_prepared_action_cohort_batch(batch)
    before = bundle.state.materialization_digest()
    result = bundle.dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert bundle.state.materialization_digest() == before
    assert all(row.status == "succeeded" for row in result.projections)
    assert all(bundle.state.get_process(item.hostname, item.pid) is None for item in identities)
    bundle.dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


def test_cancel_exact_service_batch_preserves_every_owner(tmp_path: Path) -> None:
    bundle, emitter, _, profile, _, batch = _prepare(tmp_path)
    before = bundle.state.materialization_digest()
    assert bundle.dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert bundle.state.materialization_digest() == before
    assert bundle.dispatcher.es_collectors.connection(profile.source_instance).closed_at is None
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert bundle.dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


@pytest.mark.parametrize("stage", ["service", "state", "collector", "timing"])
@pytest.mark.parametrize("leader_only", [False, True])
def test_exact_service_closure_adopts_completed_owner_acknowledgements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, leader_only: bool
) -> None:
    from evidenceforge.events.es_collector import ESCollectorRegistry
    from evidenceforge.generation.source_timing import SourceTimingPreparation
    from evidenceforge.generation.state_manager import PreparedActionCohortMaterialization

    bundle, emitter, identities, _, _, batch = _prepare(tmp_path, leader_only=leader_only)
    if stage == "service":
        target, method = bundle.lifecycle, "_service_closure_receipt_locked"
    elif stage == "state":
        target, method = PreparedActionCohortMaterialization, "finalize_no_fail"
    elif stage == "collector":
        target, method = ESCollectorRegistry, "_finalize_closures"
    else:
        target, method = SourceTimingPreparation, "commit_no_fail"
    original = getattr(target, method)
    calls = 0

    def lose_return(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        original(*args, **kwargs)
        raise RuntimeError("injected exact owner lost acknowledgement")

    monkeypatch.setattr(target, method, lose_return)
    before = bundle.state.materialization_version
    result = bundle.dispatcher.publish_prepared_action_cohort_batch(batch)
    assert calls == 1
    assert bundle.state.materialization_version == before + 1
    assert all(item.status == "succeeded" for item in result.projections)
    emitter.close()
    assert len(_rows(tmp_path)) == (1 if leader_only else len(identities))


@pytest.mark.parametrize("stage", ["certification", "state", "collector"])
def test_exact_service_precommit_fault_rolls_back_all_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    from evidenceforge.events.es_collector import PreparedESCollectorClosures
    from evidenceforge.generation.state_manager import PreparedActionCohortMaterialization

    bundle, emitter, identities, profile, _, batch = _prepare(tmp_path)
    before = bundle.state.materialization_digest()
    if stage == "certification":
        target, method = bundle.lifecycle, "_certify_service_closure"
    elif stage == "state":
        target, method = PreparedActionCohortMaterialization, "apply_provisional"
    else:
        target, method = PreparedESCollectorClosures, "apply_provisional"
    original = getattr(target, method)

    def reject(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)
        raise RuntimeError("injected reversible closure fault")

    monkeypatch.setattr(target, method, reject)
    with pytest.raises(RuntimeError, match="reversible closure fault"):
        bundle.dispatcher.publish_prepared_action_cohort_batch(batch)
    assert bundle.state.materialization_digest() == before
    assert all(
        bundle.lifecycle.get_process(item.object_id).closed_at is None for item in identities
    )
    assert bundle.dispatcher.es_collectors.connection(profile.source_instance).closed_at is None
    assert bundle.services.service_preparation_census().reserved_keys == 0
    assert bundle.dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []
