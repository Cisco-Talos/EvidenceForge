# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused exact projection recovery tests for dispatcher-owned Type-5 publication."""

from __future__ import annotations

from copy import copy
from datetime import UTC, datetime
from multiprocessing import get_context
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from unittest.mock import MagicMock, Mock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedActionCohortProjection,
)
from evidenceforge.events.identity import EntityIdentity, EventIdentityPlan
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
    PreparedExecutionEffectAuditCommit,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.intent_ledger import (
    AuthoredIntentLedger,
    IntentExecutionLedger,
    PreparedIntentExecutionBatch,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    PreparedLifecycleActionCohort,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.generation.state_manager import (
    PreparedActionCohortMaterialization,
    StateManager,
)
from evidenceforge.models.exceptions import EventContractError
from evidenceforge.utils.rng import stable_uuid

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _windows_host() -> HostContext:
    return HostContext(
        hostname="HOST-01",
        ip="10.0.0.10",
        os="Windows Server 2022",
        os_category="windows",
        system_type="server",
        domain="corp.local",
        fqdn="host-01.corp.local",
        netbios_domain="CORP",
    )


def _builtin_type_five_event(*, cluster_id: str | None = None) -> OccurrenceBuilder:
    host = _windows_host()
    semantic_key = "service-logon:unit-test"
    entity = EntityIdentity(
        object_id=stable_uuid("authentication-occurrence", semantic_key),
        kind="authentication_occurrence",
        hostname=host.hostname,
        semantic_key=semantic_key,
    )
    return OccurrenceBuilder(
        timestamp=_START,
        event_type="logon",
        dst_host=host,
        auth=AuthContext(
            username="SYSTEM",
            user_sid="S-1-5-18",
            logon_id="0x3e7",
            logon_type=5,
            auth_package="Negotiate",
            source_ip="-",
            elevated=True,
            logon_process="Advapi",
            lm_package="-",
            logon_guid="{00000000-0000-0000-0000-000000000000}",
            subject_sid="S-1-5-18",
            subject_username="SYSTEM",
            subject_domain="NT AUTHORITY",
            subject_logon_id="0x3e7",
        ),
        storyline_cluster_id=cluster_id,
        lifecycle=ActionLifecycleContext(
            group_id=semantic_key,
            canonical_start=_START,
            phase="start",
        ),
        identity_plan=EventIdentityPlan(subject=entity),
    )


def _ecar_emitter(output_path: Path, *, threaded: bool = False) -> EcarEmitter:
    format_def = Mock()
    format_def.name = "ecar"
    format_def.output.template = "{}"
    format_def.output.header_template = None
    format_def.output.footer_template = None
    format_def.output.encoding = "utf-8"
    return EcarEmitter(format_def, output_path, threaded=threaded)


def _fifo_probe_row(label: str, second: int) -> dict[str, object]:
    return {
        "timestamp": _START.replace(second=second),
        "hostname": "HOST-01",
        "object": "FLOW",
        "action": "CONNECT",
        "_host_fqdn": "host-01.corp.local",
        "_fifo_probe_label": label,
    }


def _run_threaded_type_five_fifo_probe(output_root: str) -> None:
    """Publish real Type-5 evidence behind a blocked ordinary FIFO prefix."""

    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(Path(output_root), threaded=True)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    blocker_entered = Event()
    release_blocker = Event()
    dispatch_order: list[str] = []
    failures: list[BaseException] = []
    results: list[object] = []

    original_dispatch = emitter._dispatch

    def dispatch(event_data: dict[str, object]) -> None:
        label = str(event_data.pop("_fifo_probe_label", "exact"))
        dispatch_order.append(label)
        if label == "blocker":
            blocker_entered.set()
            if not release_blocker.wait(timeout=5):
                raise AssertionError("FIFO blocker was not released")
        original_dispatch(event_data)

    emitter._dispatch = dispatch

    emitter.emit_event(_fifo_probe_row("blocker", 1))
    if not blocker_entered.wait(timeout=5):
        raise AssertionError("threaded eCAR worker did not enter the FIFO blocker")
    emitter.emit_event(_fifo_probe_row("ordinary", 2))

    def publish() -> None:
        try:
            carrier = _prepare_state_neutral_projection(dispatcher, cluster_id="type-five-fifo")
            results.append(dispatcher.publish_state_neutral_exact_projection(carrier))
        except BaseException as error:
            failures.append(error)

    publisher = Thread(target=publish, daemon=True)
    publisher.start()
    deadline = monotonic() + 5
    while monotonic() < deadline:
        if failures:
            raise failures[0]
        with emitter._exact_publication_condition:
            active = bool(emitter._active_exact_publication_keys)
            pending = getattr(emitter, "_pending_exact_publication_key", None) is not None
        if active or pending:
            break
        sleep(0.01)
    else:
        raise AssertionError("Type-5 publication did not install its FIFO fence")

    release_blocker.set()
    publisher.join(timeout=5)
    if publisher.is_alive():
        raise AssertionError("Type-5 publication deadlocked behind its ordinary FIFO predecessor")
    if failures:
        raise failures[0]
    if len(results) != 1:
        raise AssertionError("Type-5 publication did not return one result")
    result = results[0]
    if not dispatcher.authenticates_state_neutral_projection_publication_receipt(result.receipt):
        raise AssertionError("Type-5 publication did not return an authentic receipt")
    if dispatch_order != ["blocker", "ordinary", "exact"]:
        raise AssertionError(f"unexpected FIFO dispatch order: {dispatch_order!r}")
    emitter.close()
    dispatcher.assert_exact_projection_recoveries_drained()


def test_threaded_type_five_drains_ordinary_fifo_prefix_before_exact(
    tmp_path: Path,
) -> None:
    """A proactively reserved Type-5 participant cannot strand its FIFO predecessor."""

    context = get_context("spawn")
    child = context.Process(
        target=_run_threaded_type_five_fifo_probe,
        args=(str(tmp_path / "threaded-type-five-child"),),
    )
    child.start()
    child.join(timeout=12)
    if child.is_alive():
        child.terminate()
        child.join(timeout=2)
        pytest.fail("threaded Type-5 FIFO probe did not exit within its bounded child lifetime")
    assert child.exitcode == 0


def _prepare_state_neutral_projection(
    dispatcher: EventDispatcher,
    *,
    cluster_id: str | None = None,
) -> PreparedActionCohortProjection:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        return dispatcher.prepare_action_cohort_projection(
            _builtin_type_five_event(cluster_id=cluster_id),
            source_timing_preparation=timing,
        )


def _zero_node_entry(root_action_id: str) -> ExecutionEffectAuditCohortEntry:
    anchor = ActionAnchor("process_execution", root_action_id, source="unit_test")
    plan = ExecutionEffectPlan(anchor, ())
    return ExecutionEffectAuditCohortEntry(plan, plan.reconcile(()))


def _prepare_named_exact_projection(
    output_path: Path,
    *,
    with_intent: bool = False,
) -> tuple[
    StateManager,
    LifecycleRegistry,
    EventDispatcher,
    EcarEmitter,
    PreparedActionCohortBatch,
    str,
]:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    session_plan = builder.plan_session(
        username="svc-backup",
        system="HOST-01",
        logon_type=5,
        source_ip="-",
        session_kind="service",
        start_time=_START,
        logon_guid_required=False,
        lifecycle_group_id="named-service-session",
    )
    state_plan = builder.seal()
    identity = session_plan.identity
    host = _windows_host()
    event = OccurrenceBuilder(
        timestamp=_START,
        event_type="logon",
        dst_host=host,
        auth=AuthContext(
            username="svc-backup",
            user_sid="S-1-5-21-1000",
            logon_id=identity.logon_id,
            logon_type=5,
            auth_package="Negotiate",
            source_ip="-",
            source_port=0,
            elevated=True,
            logon_process="Advapi",
            lm_package="-",
            logon_guid=identity.logon_guid,
            subject_sid="S-1-5-18",
            subject_username="SYSTEM",
            subject_domain="NT AUTHORITY",
            subject_logon_id="0x3e7",
        ),
        lifecycle=ActionLifecycleContext(
            group_id=identity.lifecycle_group_id,
            canonical_start=_START,
            phase="start",
        ),
        identity_plan=EventIdentityPlan(subject=identity, session=identity),
    )
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    emitter = _ecar_emitter(output_path)
    intent_ledger = (
        IntentExecutionLedger(AuthoredIntentLedger("named-exact-owner-test", ()))
        if with_intent
        else None
    )
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
        intent_execution_ledger=intent_ledger,
    )
    if with_intent:
        dispatcher.authored_intent_id = "named-type-five-intent"
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event,
            source_timing_preparation=timing,
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=state_plan)
    root_action_id = "named-type-five"
    batch = dispatcher.prepare_action_cohort_batch(
        root_action_id,
        state_plan,
        (dispatch,),
        (_zero_node_entry(root_action_id),),
        (),
        (),
        exact_projection=True,
    )
    return state, registry, dispatcher, emitter, batch, identity.logon_id


def test_state_neutral_exact_projection_rejects_custom_target_before_render(
    tmp_path: Path,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    prior_census = dispatcher.action_cohort_publication_census()
    carrier = _prepare_state_neutral_projection(dispatcher)
    prior_state_version = state.materialization_version
    prior_timing_digest = dispatcher.source_timing_planner.state_digest()

    with pytest.raises(EventContractError, match="exact.*target|unsupported"):
        dispatcher.publish_state_neutral_exact_projection(carrier)

    emitter.emit.assert_not_called()
    assert state.materialization_version == prior_state_version
    assert dispatcher.source_timing_planner.state_digest() == prior_timing_digest
    assert dispatcher.action_cohort_publication_census() == prior_census
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0


def test_state_neutral_exact_projection_prepares_before_sink_and_publishes_once(
    tmp_path: Path,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter}, lifecycle_shadow=shadow)
    carrier = _prepare_state_neutral_projection(dispatcher, cluster_id="cluster-1")
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    prior_state_version = state.materialization_version
    prior_state_digest = state.materialization_digest()
    prior_lifecycle_census = registry.census()

    result = dispatcher.publish_state_neutral_exact_projection(carrier)

    assert result.projection.status == "succeeded"
    assert dispatcher.authenticates_state_neutral_projection_publication_receipt(result.receipt)
    assert state.materialization_version == prior_state_version
    assert state.materialization_digest() == prior_state_digest
    assert registry.census() == prior_lifecycle_census
    emitter.close()
    assert output_path.exists()
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1
    assert dispatcher.source_evidence_status["cluster-1"]["ecar"]["visible"] == 1
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0


@pytest.mark.parametrize("owner", ["intent", "timing", "observations"])
def test_state_neutral_adopts_canonical_owner_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner: str,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    intent_ledger = IntentExecutionLedger(AuthoredIntentLedger("exact-owner-test", ()))
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        intent_execution_ledger=intent_ledger,
    )
    if owner == "intent":
        dispatcher.authored_intent_id = "state-neutral-intent"
    carrier = _prepare_state_neutral_projection(
        dispatcher,
        cluster_id="state-neutral-owner-lost-return",
    )
    attempts = 0
    if owner == "intent":
        original = PreparedIntentExecutionBatch.commit_no_fail

        def lose_intent_return(
            preparation: PreparedIntentExecutionBatch,
        ) -> object:
            nonlocal attempts
            attempts += 1
            original(preparation)
            raise RuntimeError("injected intent commit lost return")

        monkeypatch.setattr(
            PreparedIntentExecutionBatch,
            "commit_no_fail",
            lose_intent_return,
        )
    elif owner == "timing":
        original_timing = SourceTimingPreparation.commit_no_fail

        def lose_timing_return(preparation: SourceTimingPreparation) -> object:
            nonlocal attempts
            attempts += 1
            original_timing(preparation)
            raise RuntimeError("injected timing commit lost return")

        monkeypatch.setattr(
            SourceTimingPreparation,
            "commit_no_fail",
            lose_timing_return,
        )
    else:
        original_observations = EventDispatcher._commit_action_cohort_observations_no_fail

        def lose_observation_return(
            owner_dispatcher: EventDispatcher,
            publication: object,
        ) -> None:
            nonlocal attempts
            attempts += 1
            original_observations(owner_dispatcher, publication)
            raise RuntimeError("injected observation commit lost return")

        monkeypatch.setattr(
            EventDispatcher,
            "_commit_action_cohort_observations_no_fail",
            lose_observation_return,
        )

    result = dispatcher.publish_state_neutral_exact_projection(carrier)

    assert result.projection.status == "succeeded"
    assert attempts == 1
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    if owner == "intent":
        assert result.intent is not None
        snapshot = intent_ledger.snapshot()[0]
        assert snapshot.intent_id == "state-neutral-intent"
        assert snapshot.occurrence_reference_count == 1
    else:
        assert result.intent is None
    assert (
        dispatcher.source_evidence_status["state-neutral-owner-lost-return"]["ecar"]["visible"] == 1
    )
    emitter.close()
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


def test_named_type_five_exact_batch_stages_before_canonical_commit(tmp_path: Path) -> None:
    state, registry, dispatcher, emitter, batch, logon_id = _prepare_named_exact_projection(
        tmp_path
    )
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    prior_state_version = state.materialization_version
    prior_state_digest = state.materialization_digest()
    prior_lifecycle_census = registry.census()

    assert not output_path.exists()
    assert state.get_session(logon_id) is None
    assert dispatcher.action_cohort_publication_census().prepared_batches == 1
    assert dispatcher.exact_projection_recovery_census().authority.prepared_batches == 1
    assert state.materialization_version == prior_state_version
    assert state.materialization_digest() == prior_state_digest
    assert registry.census() == prior_lifecycle_census

    result = dispatcher.publish_prepared_action_cohort_batch(batch)

    assert result.projections[0].status == "succeeded"
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert state.get_session(logon_id) is not None
    assert state.materialization_version == prior_state_version + 1
    assert dispatcher.action_cohort_publication_census().prepared_batches == 0
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    assert registry.action_cohort_preparation_census().committed_receipt_authorities == 1
    del result
    assert registry.prune_action_cohort_receipt_authorities() == 1
    assert registry.action_cohort_preparation_census().committed_receipt_authorities == 0
    emitter.close()
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


def test_named_type_five_commit_lost_return_resumes_existing_action_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_first_return(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        attempts += 1
        original(writer, key, digest, frozen)
        if attempts == 1:
            raise RuntimeError("injected named commit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_first_return)
    state, _registry, dispatcher, emitter, batch, logon_id = _prepare_named_exact_projection(
        tmp_path
    )

    with pytest.raises(RuntimeError, match="named commit lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)

    receipt = caught.value.action_cohort_receipt
    pending = caught.value.action_cohort_result
    assert caught.value.exact_projection_receipt is receipt
    assert state.get_session(logon_id) is not None
    assert pending.projections[0].status == "recoverable"
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1

    result = dispatcher.resume_action_cohort_projection(receipt)

    assert result is pending
    assert result.projections[0].status == "succeeded"
    assert attempts == 2
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize(
    "owner",
    ["lifecycle", "audit", "intent", "timing", "dispatcher_ledgers", "state"],
)
def test_named_type_five_adopts_owner_lost_return_and_retains_sink_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner: str,
) -> None:
    original_sink = ExternalSortedLineWriter._commit_exact_row
    sink_attempts = 0

    def fail_first_sink(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal sink_attempts
        sink_attempts += 1
        if sink_attempts == 1:
            raise RuntimeError("injected sink retry boundary")
        original_sink(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_first_sink)
    state, registry, dispatcher, emitter, batch, logon_id = _prepare_named_exact_projection(
        tmp_path,
        with_intent=owner == "intent",
    )
    owner_attempts = 0
    if owner == "lifecycle":
        original_owner = PreparedLifecycleActionCohort.commit_no_fail

        def lose_owner_return(preparation: PreparedLifecycleActionCohort) -> object:
            nonlocal owner_attempts
            owner_attempts += 1
            original_owner(preparation)
            raise RuntimeError("injected lifecycle commit lost return")

        monkeypatch.setattr(
            PreparedLifecycleActionCohort,
            "commit_no_fail",
            lose_owner_return,
        )
    elif owner == "audit":
        original_audit = PreparedExecutionEffectAuditCommit.commit_no_fail

        def lose_audit_return(preparation: PreparedExecutionEffectAuditCommit) -> object:
            nonlocal owner_attempts
            owner_attempts += 1
            original_audit(preparation)
            raise RuntimeError("injected audit commit lost return")

        monkeypatch.setattr(
            PreparedExecutionEffectAuditCommit,
            "commit_no_fail",
            lose_audit_return,
        )
    elif owner == "intent":
        original_intent = PreparedIntentExecutionBatch.commit_no_fail

        def lose_intent_return(preparation: PreparedIntentExecutionBatch) -> object:
            nonlocal owner_attempts
            owner_attempts += 1
            original_intent(preparation)
            raise RuntimeError("injected named intent commit lost return")

        monkeypatch.setattr(
            PreparedIntentExecutionBatch,
            "commit_no_fail",
            lose_intent_return,
        )
    elif owner == "timing":
        original_timing = SourceTimingPreparation.commit_no_fail

        def lose_timing_return(preparation: SourceTimingPreparation) -> object:
            nonlocal owner_attempts
            owner_attempts += 1
            original_timing(preparation)
            raise RuntimeError("injected named timing commit lost return")

        monkeypatch.setattr(
            SourceTimingPreparation,
            "commit_no_fail",
            lose_timing_return,
        )
    elif owner == "dispatcher_ledgers":
        original_ledgers = EventDispatcher._commit_action_cohort_dispatcher_ledgers_no_fail

        def lose_dispatcher_ledgers_return(
            owner_dispatcher: EventDispatcher,
            record: object,
        ) -> None:
            nonlocal owner_attempts
            owner_attempts += 1
            original_ledgers(owner_dispatcher, record)
            raise RuntimeError("injected dispatcher-ledger commit lost return")

        monkeypatch.setattr(
            EventDispatcher,
            "_commit_action_cohort_dispatcher_ledgers_no_fail",
            lose_dispatcher_ledgers_return,
        )
    else:
        original_state = PreparedActionCohortMaterialization.finalize_no_fail

        def lose_state_return(preparation: PreparedActionCohortMaterialization) -> object:
            nonlocal owner_attempts
            owner_attempts += 1
            original_state(preparation)
            raise RuntimeError("injected State finalize lost return")

        monkeypatch.setattr(
            PreparedActionCohortMaterialization,
            "finalize_no_fail",
            lose_state_return,
        )

    with pytest.raises(RuntimeError, match="sink retry boundary") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)

    receipt = caught.value.action_cohort_receipt
    assert owner_attempts == 1
    assert state.materialization_version == 1
    assert state.get_session(logon_id) is not None
    assert registry.census().live_sessions == 1
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1

    result = dispatcher.resume_action_cohort_projection(receipt)

    assert result.projections[0].status == "succeeded"
    assert sink_attempts == 2
    assert state.materialization_version == 1
    assert registry.census().live_sessions == 1
    if owner == "intent":
        assert result.intent is not None
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


def test_named_exact_post_issue_failure_cancels_provisional_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = EventDispatcher._action_cohort_batch_integrity
    dispatchers: list[EventDispatcher] = []

    def fail_after_issue(
        dispatcher: EventDispatcher,
        carrier: object,
        record: object,
    ) -> str:
        dispatchers.append(dispatcher)
        integrity = original(dispatcher, carrier, record)
        if record.exact_publication_batch is not None:
            raise RuntimeError("injected post-issue integrity failure")
        return integrity

    monkeypatch.setattr(EventDispatcher, "_action_cohort_batch_integrity", fail_after_issue)

    with pytest.raises(RuntimeError, match="post-issue integrity failure"):
        _prepare_named_exact_projection(tmp_path)

    dispatcher = dispatchers[-1]
    census = dispatcher.action_cohort_publication_census()
    exact = dispatcher.exact_projection_recovery_census()
    assert census.prepared_batches == 0
    assert census.retained_members == 0
    assert census.retained_bytes == 0
    assert census.capability_locators == 0
    assert census.prepared_projections == 0
    assert census.projection_groups == 0
    assert exact.unresolved_recoveries == 0
    assert exact.authority.active_batches == 0
    assert exact.authority.prepared_batches == 0
    assert dispatcher.state_manager.materialization_version == 0


def test_state_neutral_commit_lost_return_resumes_same_batch_and_rejects_receipt_abuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    carrier = _prepare_state_neutral_projection(dispatcher, cluster_id="cluster-retry")
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_first_return(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        attempts += 1
        original(writer, key, digest, frozen)
        if attempts == 1:
            raise RuntimeError("injected exact commit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_first_return)
    prior_state_version = state.materialization_version

    with pytest.raises(RuntimeError, match="commit lost return") as caught:
        dispatcher.publish_state_neutral_exact_projection(carrier)

    receipt = caught.value.state_neutral_projection_receipt
    pending_result = caught.value.state_neutral_projection_result
    timing_digest = dispatcher.source_timing_planner.state_digest()
    census = dispatcher.exact_projection_recovery_census()
    assert pending_result.projection.status == "recoverable"
    assert state.materialization_version == prior_state_version
    assert dispatcher.source_evidence_status["cluster-retry"]["ecar"]["visible"] == 1
    assert census.unresolved_recoveries == 1
    assert census.authority.active_batches == 1
    assert census.authority.prepared_batches == 1
    assert census.high_water_recoveries == 1
    assert dispatcher.authenticates_state_neutral_projection_publication_receipt(receipt)

    copied = copy(receipt)
    tampered = copy(receipt)
    object.__setattr__(tampered, "publication_token", "tampered")
    foreign = EventDispatcher(StateManager(), {})
    for owner, candidate in (
        (dispatcher, copied),
        (dispatcher, tampered),
        (foreign, receipt),
    ):
        with pytest.raises(EventContractError, match="copied|foreign|stale|authentication"):
            owner.resume_state_neutral_exact_projection(candidate)

    result = dispatcher.resume_state_neutral_exact_projection(receipt)

    assert result is pending_result
    assert result.projection.status == "succeeded"
    assert result.projection.error is None
    assert attempts == 2
    assert dispatcher.source_timing_planner.state_digest() == timing_digest
    assert dispatcher.source_evidence_status["cluster-retry"]["ecar"]["visible"] == 1
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    dispatcher.assert_exact_projection_recoveries_drained()
    with pytest.raises(EventContractError, match="stale|released"):
        dispatcher.resume_state_neutral_exact_projection(receipt)
    emitter.close()
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


def test_state_neutral_release_lost_return_is_reconciled_without_republication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    carrier = _prepare_state_neutral_projection(dispatcher)
    original = ExternalSortedLineWriter._release_exact_row
    attempts = 0

    def lose_first_release(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
    ) -> None:
        nonlocal attempts
        attempts += 1
        original(writer, key)
        if attempts == 1:
            raise RuntimeError("injected exact release lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_release_exact_row", lose_first_release)

    with pytest.raises(RuntimeError, match="release lost return") as caught:
        dispatcher.publish_state_neutral_exact_projection(carrier)

    receipt = caught.value.state_neutral_projection_receipt
    pending = caught.value.state_neutral_projection_result
    assert pending.projection.status == "release_pending"
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1

    result = dispatcher.resume_state_neutral_exact_projection(receipt)

    assert result is pending
    assert result.projection.status == "succeeded"
    assert attempts == 2
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0
    emitter.close()
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


def test_state_neutral_resume_adopts_release_completed_before_recovery_pop(
    tmp_path: Path,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    carrier = _prepare_state_neutral_projection(dispatcher)

    class LoseFirstReleasedPop(dict[int, object]):
        failed = False

        def pop(self, key: int, *default: object) -> object:
            retained = self.get(key)
            batch = getattr(retained, "batch", None)
            if not self.failed and batch is not None and batch.released:
                self.failed = True
                raise RuntimeError("injected post-release recovery-pop lost return")
            return super().pop(key, *default)

    retained_recoveries = LoseFirstReleasedPop()
    dispatcher._exact_projection_recoveries = retained_recoveries

    with pytest.raises(RuntimeError, match="post-release recovery-pop lost return"):
        dispatcher.publish_state_neutral_exact_projection(carrier)

    recovery = next(iter(retained_recoveries.values()))
    receipt = recovery.receipt
    assert recovery.batch.released
    assert recovery.outcome.status == "succeeded"
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0

    result = dispatcher.resume_state_neutral_exact_projection(receipt)

    assert result is recovery.result
    assert result.projection.status == "succeeded"
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    output_path = tmp_path / "host-01.corp.local" / "ecar.json"
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1


def test_state_neutral_recovery_rejects_concurrent_and_reentrant_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    carrier = _prepare_state_neutral_projection(dispatcher)
    original = ExternalSortedLineWriter._commit_exact_row
    second_started = Event()
    allow_second = Event()
    receipt_holder: list[object] = []
    reentrant_errors: list[BaseException] = []
    attempts = 0

    def controlled_commit(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected recoverable sink failure")
        try:
            dispatcher.resume_state_neutral_exact_projection(receipt_holder[0])
        except BaseException as error:
            reentrant_errors.append(error)
        second_started.set()
        assert allow_second.wait(timeout=2)
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", controlled_commit)
    with pytest.raises(RuntimeError, match="recoverable sink failure") as caught:
        dispatcher.publish_state_neutral_exact_projection(carrier)
    receipt_holder.append(caught.value.state_neutral_projection_receipt)
    worker_result: list[object] = []
    worker_errors: list[BaseException] = []

    def resume_in_worker() -> None:
        try:
            worker_result.append(
                dispatcher.resume_state_neutral_exact_projection(receipt_holder[0])
            )
        except BaseException as error:
            worker_errors.append(error)

    worker = Thread(target=resume_in_worker)
    worker.start()
    assert second_started.wait(timeout=2)
    with pytest.raises(EventContractError, match="concurrent"):
        dispatcher.resume_state_neutral_exact_projection(receipt_holder[0])
    allow_second.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert not worker_errors
    assert len(worker_result) == 1
    assert len(reentrant_errors) == 1
    assert isinstance(reentrant_errors[0], EventContractError)
    assert "reentrant" in str(reentrant_errors[0])
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


def test_exact_sink_callbacks_run_outside_dispatcher_and_timing_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    carrier = _prepare_state_neutral_projection(dispatcher)
    original = ExternalSortedLineWriter._commit_exact_row
    callback_checked = Event()

    def assert_lock_available(lock: object) -> None:
        acquired = Event()

        def probe() -> None:
            if lock.acquire(timeout=1):
                acquired.set()
                lock.release()

        worker = Thread(target=probe)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert acquired.is_set()

    def checked_commit(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        for lock in (
            dispatcher._action_cohort_lock,
            dispatcher._source_evidence_lock,
            dispatcher._publication_ledger_lock,
            dispatcher.source_timing_planner._preparation_lock,
        ):
            assert_lock_available(lock)
        callback_checked.set()
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", checked_commit)

    dispatcher.publish_state_neutral_exact_projection(carrier)

    assert callback_checked.is_set()
    emitter.close()


def test_unresolved_recovery_is_bounded_and_not_receipt_evictable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    emitter = _ecar_emitter(tmp_path)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        action_cohort_receipt_capacity=1,
    )
    first = _prepare_state_neutral_projection(dispatcher)
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail_once(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected retained recovery")
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_once)
    with pytest.raises(RuntimeError, match="retained recovery") as caught:
        dispatcher.publish_state_neutral_exact_projection(first)
    receipt = caught.value.state_neutral_projection_receipt
    first_committed_timing = dispatcher.source_timing_planner.state_digest()
    census = dispatcher.exact_projection_recovery_census()
    assert census.unresolved_recoveries == 1
    assert census.recovery_capacity == 1_024
    assert census.high_water_recoveries == 1

    dispatcher.output_start_time = _START.replace(second=1)
    second = _prepare_state_neutral_projection(dispatcher)
    with pytest.raises(EventContractError, match="receipt capacity.*no resolved"):
        dispatcher.publish_state_neutral_exact_projection(second)

    assert dispatcher.source_timing_planner.state_digest() == first_committed_timing
    assert dispatcher.authenticates_state_neutral_projection_publication_receipt(receipt)
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1

    drained = dispatcher.drain_exact_projection_recoveries()

    assert drained == (caught.value.state_neutral_projection_result,)
    dispatcher.assert_exact_projection_recoveries_drained()
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0
    emitter.close()
