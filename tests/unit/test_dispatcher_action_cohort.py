# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused generic action-cohort dispatcher publication tests."""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import copy
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event, Thread
from types import SimpleNamespace, TracebackType
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import (
    FileContentIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
)
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    OccurrenceRole,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.events.dispatcher import (
    ActionCohortExternalEffectLink,
    ActionCohortPublicationResult,
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedActionCohortProjection,
    PreparedDispatch,
    PreparedDispatchStateIntent,
    _ActionCohortObservationDelta,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.observation import ObservationSummary
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ChildProcessEffectIntent,
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    FileEffectAction,
    FileEffectIntent,
    NetworkEffectIntent,
    SessionEffectAction,
    SessionEffectIntent,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPreparedGroupCommit,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    PreparedLifecycleActionCohort,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ProcessMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import EventContractError, StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)
_ROOT_ACTION_ID = "action-cohort-root"


class _ExitFailureContext:
    """Delegate one owner context, then inject an exit failure for unwind tests."""

    def __init__(
        self,
        inner: AbstractContextManager[object],
        failure: BaseException,
    ) -> None:
        self._inner = inner
        self._failure = failure

    def __enter__(self) -> object:
        return self._inner.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._inner.__exit__(exc_type, exc, traceback)
        raise self._failure


class _EnterFailureContext:
    """Fail one later owner claim before it can yield a capability."""

    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def __enter__(self) -> object:
        raise self._failure

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        raise AssertionError("unentered context must not close")


@dataclass(slots=True)
class _PreparedCohort:
    state: StateManager
    registry: LifecycleRegistry
    authority: GeneratorLifecycleAuthority
    audit: ExecutionEffectAuditCounter
    dispatcher: EventDispatcher
    emitter: MagicMock
    state_plan: ActionCohortMaterializationPlan
    process_plans: tuple[ProcessMaterializationPlan, ...]
    timing: SourceTimingPreparation
    dispatches: tuple[PreparedDispatch, ...]
    batch: PreparedActionCohortBatch


def _host() -> HostContext:
    return HostContext(
        hostname="HOST-01",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        os_category="linux",
        system_type="server",
    )


def _process_start(plan: ProcessMaterializationPlan) -> OccurrenceBuilder:
    identity = plan.identity
    return OccurrenceBuilder(
        timestamp=identity.started_at,
        event_type="process_create",
        src_host=_host(),
        process=ProcessContext(
            pid=identity.pid,
            parent_pid=identity.parent_pid,
            image=identity.image,
            command_line=identity.command_line,
            username=identity.principal,
            integrity_level=plan.integrity_level,
            logon_id=identity.logon_id,
            start_time=identity.started_at,
        ),
        identity_plan=EventIdentityPlan(subject=identity),
        lifecycle=ActionLifecycleContext(
            group_id=identity.lifecycle_group_id,
            canonical_start=identity.started_at,
            phase="start",
            parent_group_id=identity.parent_lifecycle_group_id or None,
        ),
    )


def _zero_node_entry() -> ExecutionEffectAuditCohortEntry:
    anchor = ActionAnchor("process_execution", _ROOT_ACTION_ID, source="unit_test")
    plan = ExecutionEffectPlan(anchor, ())
    return ExecutionEffectAuditCohortEntry(plan, plan.reconcile(()))


def _linked_entry(
    intent: ChildProcessEffectIntent | SessionEffectIntent | FileEffectIntent,
    owner: ProcessIdentity | SessionIdentity,
) -> ExecutionEffectAuditCohortEntry:
    anchor = ActionAnchor("process_execution", _ROOT_ACTION_ID, source="unit_test")
    node = ExecutionEffectNode.create(
        anchor,
        intent,
        role=OccurrenceRole.DEPENDENT,
        requirement=EffectRequirement.EXTERNALLY_OWNED,
    )
    plan = ExecutionEffectPlan(anchor, (node,))
    outcome = EffectExecutionOutcome(
        node.node_id,
        EffectOutcomeStatus.LINKED,
        child_action_id=owner.lifecycle_group_id,
    )
    return ExecutionEffectAuditCohortEntry(plan, plan.reconcile((outcome,)))


def _external_process_identity() -> ProcessIdentity:
    return ProcessIdentity(
        hostname="HOST-01",
        object_id="external-process",
        pid=400,
        parent_pid=1,
        image="/usr/bin/external",
        command_line="external",
        principal="root",
        logon_id="0x3e7",
        started_at=_START,
        lifecycle_group_id="external-process-lifecycle",
    )


def _external_session_identity() -> SessionIdentity:
    return SessionIdentity(
        hostname="HOST-01",
        object_id="external-session",
        logon_id="0x401",
        session_id=4,
        principal="alice",
        session_kind="interactive",
        started_at=_START,
        lifecycle_group_id="external-session-lifecycle",
    )


def _dispatcher_environment(*, member_count: int = 1) -> _PreparedCohort:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process_plans = tuple(
        builder.plan_process(
            system="HOST-01",
            parent_pid=0,
            image=f"/usr/bin/cohort-{ordinal}",
            command_line=f"cohort-{ordinal}",
            username="root",
            integrity_level="Medium",
            os_category="linux",
            lifecycle_group_id=f"cohort-process-{ordinal}",
            start_time=_START,
        )
        for ordinal in range(member_count)
    )
    state_plan = builder.seal()

    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    audit = ExecutionEffectAuditCounter()
    dispatcher.bind_execution_effect_audit(audit)

    carriers: list[PreparedActionCohortProjection] = []
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        for process_plan in process_plans:
            carriers.append(
                dispatcher.prepare_action_cohort_projection(
                    _process_start(process_plan),
                    source_timing_preparation=timing,
                )
            )
    dispatches = tuple(
        dispatcher.bind_action_cohort_projection(carrier, state_plan=state_plan)
        for carrier in carriers
    )
    batch = dispatcher.prepare_action_cohort_batch(
        _ROOT_ACTION_ID,
        state_plan,
        dispatches,
        (_zero_node_entry(),),
        (),
        (),
    )
    return _PreparedCohort(
        state=state,
        registry=registry,
        authority=authority,
        audit=audit,
        dispatcher=dispatcher,
        emitter=emitter,
        state_plan=state_plan,
        process_plans=process_plans,
        timing=timing,
        dispatches=dispatches,
        batch=batch,
    )


def _artifact_record(plan: ProcessMaterializationPlan) -> LocalArtifactVersionRecord:
    """Return exact runtime binary truth for the cohort's staged Linux process."""

    identity = plan.identity
    content = FileContentIdentity(
        file_object_id="cohort-runtime-binary",
        version=1,
        size_bytes=8_192,
        mime_type="application/x-elf",
        seed_ref="cohort-runtime-binary-seed",
    )
    artifact = LocalArtifactIdentity(
        hostname=identity.hostname,
        principal=identity.principal,
        platform="linux",
        user_profile_id="profile-root",
        application_profile_id="cohort-runtime-profile",
        application_id="cohort-runtime",
        family="runtime",
        source_object_id=identity.lifecycle_group_id,
        native_path=identity.image,
        content_id=content.content_id,
    )
    binary = LocalArtifactBinaryIdentity(
        artifact_version_id=artifact.artifact_version_id,
        content_id=content.content_id,
        digests=content.digests,
        platform="linux",
        architecture="x64",
        artifact_name=identity.image.rsplit("/", 1)[-1],
    )
    return LocalArtifactVersionRecord(artifact=artifact, content=content, binary=binary)


def _artifact_dispatcher_environment() -> tuple[
    _PreparedCohort,
    LocalArtifactVersionRegistry,
    LocalArtifactVersionRecord,
]:
    """Prepare one full action cohort whose root owns a runtime artifact token."""

    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process_plan = builder.plan_process(
        system="HOST-01",
        parent_pid=0,
        image="/usr/bin/cohort-runtime",
        command_line="cohort-runtime",
        username="root",
        integrity_level="Medium",
        os_category="linux",
        lifecycle_group_id="cohort-runtime-process",
        start_time=_START,
    )
    state_plan = builder.seal()
    lifecycle_registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, lifecycle_registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    artifact_registry = LocalArtifactVersionRegistry(capacity=4)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
        local_artifact_registry=artifact_registry,
    )
    dispatcher.bind_lifecycle_authority(authority)
    audit = ExecutionEffectAuditCounter()
    dispatcher.bind_execution_effect_audit(audit)
    record = _artifact_record(process_plan)
    token = artifact_registry.prepare_publish_version(record, _START)
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        prepared = dispatcher.prepare_builder(
            _process_start(process_plan),
            state_intent=PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT,
            lifecycle_ticket=state_plan,
            artifact_publications=(token,),
            source_timing_preparation=timing,
        )
    dispatches = (prepared,)
    batch = dispatcher.prepare_action_cohort_batch(
        _ROOT_ACTION_ID,
        state_plan,
        dispatches,
        (_zero_node_entry(),),
        (),
        (),
    )
    return (
        _PreparedCohort(
            state=state,
            registry=lifecycle_registry,
            authority=authority,
            audit=audit,
            dispatcher=dispatcher,
            emitter=emitter,
            state_plan=state_plan,
            process_plans=(process_plan,),
            timing=timing,
            dispatches=dispatches,
            batch=batch,
        ),
        artifact_registry,
        record,
    )


def test_action_cohort_preparation_is_authentic_bounded_and_trusted_cancelled() -> None:
    cohort = _dispatcher_environment()
    census = cohort.dispatcher.action_cohort_publication_census()

    assert cohort.dispatcher.authenticates_prepared_action_cohort_batch(cohort.batch)
    assert census.prepared_batches == 1
    assert census.retained_members == 1
    assert census.capability_locators == 1
    assert (
        cohort.state.get_process(
            cohort.process_plans[0].identity.hostname,
            cohort.process_plans[0].identity.pid,
        )
        is None
    )

    object.__setattr__(cohort.batch, "_integrity_token", object())
    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)
    assert not cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)
    terminal = cohort.dispatcher.action_cohort_publication_census()
    assert terminal.prepared_batches == 0
    assert terminal.retained_members == 0
    assert terminal.capability_locators == 0
    assert cohort.audit.action_cohort_preparation_census().active == 0
    assert not cohort.dispatcher.source_timing_planner.authenticates_preparation(cohort.timing)


def test_action_cohort_commits_runtime_artifacts_with_every_canonical_owner() -> None:
    cohort, artifacts, record = _artifact_dispatcher_environment()

    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None
    result = cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)

    assert result.artifacts is not None
    assert artifacts.authenticates_publication_group_receipt(result.artifacts)
    assert artifacts.resolve_version(record.artifact.artifact_version_id) == record
    assert cohort.state.get_process("HOST-01", cohort.process_plans[0].identity.pid) is not None
    assert cohort.audit.snapshot().plan_count == 1
    assert cohort.emitter.emit.call_count == 1
    census = artifacts.census()
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0


def test_action_cohort_cancellation_releases_runtime_artifacts_without_owner_residue() -> None:
    cohort, artifacts, record = _artifact_dispatcher_environment()
    before_state = cohort.state.materialization_digest()
    before_audit = cohort.audit.snapshot()

    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)

    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None
    assert artifacts.census().prepared_publications == 0
    assert cohort.state.materialization_digest() == before_state
    assert cohort.audit.snapshot() == before_audit
    assert cohort.emitter.emit.call_count == 0
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 0


def test_action_cohort_artifact_commit_failure_rolls_back_every_uncommitted_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort, artifacts, record = _artifact_dispatcher_environment()
    before_state = cohort.state.materialization_digest()
    before_audit = cohort.audit.snapshot()
    before_lifecycle = cohort.registry.census()

    def reject_artifact_commit(
        _claim: LocalArtifactPreparedGroupCommit,
    ) -> object:
        raise StateError("injected ordinary artifact publication failure")

    monkeypatch.setattr(
        LocalArtifactPreparedGroupCommit,
        "commit_no_fail",
        reject_artifact_commit,
    )
    with pytest.raises(StateError, match="artifact publication failure"):
        cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)

    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None
    artifact_census = artifacts.census()
    assert artifact_census.prepared_publications == 0
    assert artifact_census.claimed_publications == 0
    assert cohort.state.materialization_digest() == before_state
    assert cohort.audit.snapshot() == before_audit
    assert cohort.registry.census() == before_lifecycle
    assert cohort.emitter.emit.call_count == 0
    assert not cohort.dispatcher.source_timing_planner.authenticates_preparation(cohort.timing)
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 0


def test_action_cohort_rejects_foreign_copy_order_tamper_and_artifacts() -> None:
    cohort = _dispatcher_environment(member_count=2)
    copied = copy(cohort.batch)

    assert not cohort.dispatcher.authenticates_prepared_action_cohort_batch(copied)
    assert not cohort.dispatcher.cancel_prepared_action_cohort_batch(copied)

    object.__setattr__(cohort.batch, "_dispatches", tuple(reversed(cohort.dispatches)))
    assert not cohort.dispatcher.authenticates_prepared_action_cohort_batch(cohort.batch)
    object.__setattr__(cohort.batch, "_dispatches", cohort.dispatches)
    object.__setattr__(cohort.dispatches[0], "_artifact_publications", (object(),))
    with pytest.raises(EventContractError, match="artifact publication"):
        cohort.dispatcher.prepare_action_cohort_batch(
            _ROOT_ACTION_ID,
            cohort.state_plan,
            cohort.dispatches,
            (_zero_node_entry(),),
            (),
            (),
        )

    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)


def test_action_cohort_batch_cleanup_failure_retains_locator_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()
    original = SourceTimingPreparation.cancel
    attempts = 0

    def fail_once(preparation: SourceTimingPreparation) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise StateError("injected timing cancellation failure")
        original(preparation)

    monkeypatch.setattr(SourceTimingPreparation, "cancel", fail_once)
    with pytest.raises(EventContractError, match="cancellation cleanup failed"):
        cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)

    retained = cohort.dispatcher.action_cohort_publication_census()
    assert retained.prepared_batches == 1
    assert retained.capability_locators == 1
    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)
    assert attempts == 2
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 0


def test_projection_cleanup_failure_retains_group_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process_plan = builder.plan_process(
        system="HOST-01",
        parent_pid=0,
        image="/usr/bin/projection",
        command_line="projection",
        username="root",
        integrity_level="Medium",
        os_category="linux",
        lifecycle_group_id="projection-process",
        start_time=_START,
    )
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            _process_start(process_plan),
            source_timing_preparation=timing,
        )

    original = SourceTimingPreparation.cancel
    attempts = 0

    def fail_once(preparation: SourceTimingPreparation) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise StateError("injected projection timing cancellation failure")
        original(preparation)

    monkeypatch.setattr(SourceTimingPreparation, "cancel", fail_once)
    with pytest.raises(StateError, match="injected projection"):
        dispatcher.cancel_prepared_action_cohort_projection(carrier)
    retained = dispatcher.action_cohort_publication_census()
    assert retained.prepared_projections == 1
    assert retained.projection_groups == 1
    assert retained.capability_locators == 1
    assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
    assert attempts == 2
    assert dispatcher.action_cohort_publication_census().prepared_projections == 0


def test_failed_preparation_cleanup_retries_members_and_nested_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("injected batch construction failure")
    member_cleanup_failure = StateError("injected member cleanup failure")
    timing_cleanup_failure = StateError("injected timing cleanup failure")
    captured_dispatchers: list[EventDispatcher] = []
    captured_dispatches: list[tuple[PreparedDispatch, ...]] = []
    armed = False
    member_failed = False
    timing_failed = False
    original_batch_integrity = EventDispatcher._action_cohort_batch_integrity
    original_member_integrity = EventDispatcher._prepared_dispatch_integrity
    original_timing_cancel = SourceTimingPreparation.cancel

    def fail_batch_integrity(
        dispatcher: EventDispatcher,
        carrier: PreparedActionCohortBatch,
        _record: object,
    ) -> str:
        nonlocal armed
        captured_dispatchers.append(dispatcher)
        captured_dispatches.append(carrier._dispatches)
        object.__setattr__(carrier._dispatches[0], "_action_cohort_batch_id", "tampered")
        armed = True
        raise primary

    def fail_first_member_cleanup(
        dispatcher: EventDispatcher,
        prepared: PreparedDispatch,
    ) -> str:
        nonlocal member_failed
        if (
            armed
            and captured_dispatches
            and prepared is captured_dispatches[0][0]
            and prepared._action_cohort_batch_id is None
            and not member_failed
        ):
            member_failed = True
            raise member_cleanup_failure
        return original_member_integrity(dispatcher, prepared)

    def fail_first_timing_cleanup(preparation: SourceTimingPreparation) -> None:
        nonlocal timing_failed
        if armed and not timing_failed:
            timing_failed = True
            raise timing_cleanup_failure
        original_timing_cancel(preparation)

    monkeypatch.setattr(
        EventDispatcher,
        "_action_cohort_batch_integrity",
        fail_batch_integrity,
    )
    monkeypatch.setattr(
        EventDispatcher,
        "_prepared_dispatch_integrity",
        fail_first_member_cleanup,
    )
    monkeypatch.setattr(SourceTimingPreparation, "cancel", fail_first_timing_cleanup)

    with pytest.raises(RuntimeError) as caught:
        _dispatcher_environment(member_count=2)
    assert caught.value is primary
    assert len(getattr(primary, "__notes__", ())) == 2

    dispatcher = captured_dispatchers[0]
    dispatches = captured_dispatches[0]
    retained = dispatcher.action_cohort_publication_census()
    assert retained.prepared_batches == 1
    assert retained.retained_members == 2
    assert retained.capability_locators == 1
    assert type(dispatches[0]._action_cohort_batch_id) is int
    assert dispatches[1]._action_cohort_batch_id is None

    monkeypatch.setattr(
        EventDispatcher,
        "_action_cohort_batch_integrity",
        original_batch_integrity,
    )
    monkeypatch.setattr(
        EventDispatcher,
        "_prepared_dispatch_integrity",
        original_member_integrity,
    )
    monkeypatch.setattr(SourceTimingPreparation, "cancel", original_timing_cancel)
    assert dispatcher.prune_prepared_action_cohort_batches() == 1
    assert dispatches[0]._action_cohort_batch_id is None
    assert dispatches[1]._action_cohort_batch_id is None
    terminal = dispatcher.action_cohort_publication_census()
    assert terminal.prepared_batches == 0
    assert terminal.retained_members == 0
    assert terminal.capability_locators == 0


def test_action_cohort_rejects_oversized_public_tuples_before_traversal() -> None:
    cohort = _dispatcher_environment()
    audit_before = cohort.audit.action_cohort_preparation_census()
    oversized_objects = (object(),) * 257
    oversized_entries = (_zero_node_entry(),) * 257

    oversized_calls = (
        (oversized_entries, (), (), ()),
        ((_zero_node_entry(),), oversized_objects, (), ()),
        ((_zero_node_entry(),), (), oversized_objects, ()),
        ((_zero_node_entry(),), (), (), oversized_objects),
    )
    for entries, bindings, links, plans in oversized_calls:
        with pytest.raises(EventContractError, match="capacity exceeded"):
            cohort.dispatcher.prepare_action_cohort_batch(
                _ROOT_ACTION_ID,
                cohort.state_plan,
                cohort.dispatches,
                entries,
                bindings,
                links,
                owned_effect_plans=plans,
            )

    assert cohort.audit.action_cohort_preparation_census() == audit_before
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 1
    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)


def test_action_cohort_rejects_unbounded_nested_effect_work_before_owner_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()
    audit_before = cohort.audit.action_cohort_preparation_census()
    owner_called = False

    def forbidden_state_authentication(
        _state: StateManager,
        _plan: object,
    ) -> bool:
        nonlocal owner_called
        owner_called = True
        raise AssertionError("nested-work rejection reached a State owner")

    monkeypatch.setattr(
        StateManager,
        "authenticates_action_cohort_plan",
        forbidden_state_authentication,
    )

    huge_plan = OwnedEffectOccurrencePlan(
        EffectOccurrenceOwner.BASELINE_AMBIENT_FILE_ROOT,
        EffectOccurrenceKind.FILE,
        _ROOT_ACTION_ID,
        "huge-owned-root",
        1,
    )
    object.__setattr__(huge_plan, "occurrence_count", 10**12)
    with pytest.raises(EventContractError, match="occurrence capacity exceeded"):
        cohort.dispatcher.prepare_action_cohort_batch(
            _ROOT_ACTION_ID,
            cohort.state_plan,
            cohort.dispatches,
            (_zero_node_entry(),),
            (),
            (),
            owned_effect_plans=(huge_plan,),
        )

    huge_entry = _zero_node_entry()
    object.__setattr__(huge_entry.plan, "nodes", (object(),) * 2_049)
    with pytest.raises(EventContractError, match="nested effect-member capacity exceeded"):
        cohort.dispatcher.prepare_action_cohort_batch(
            _ROOT_ACTION_ID,
            cohort.state_plan,
            cohort.dispatches,
            (huge_entry,),
            (),
            (),
        )

    huge_reconciliation_entry = _zero_node_entry()
    object.__setattr__(
        huge_reconciliation_entry.reconciliation,
        "missing_node_ids",
        ("missing",) * 2_049,
    )
    with pytest.raises(EventContractError, match="nested effect-member capacity exceeded"):
        cohort.dispatcher.prepare_action_cohort_batch(
            _ROOT_ACTION_ID,
            cohort.state_plan,
            cohort.dispatches,
            (huge_reconciliation_entry,),
            (),
            (),
        )

    assert not owner_called
    assert cohort.audit.action_cohort_preparation_census() == audit_before
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 1
    assert cohort.dispatcher.cancel_prepared_action_cohort_batch(cohort.batch)


def test_action_cohort_linked_effects_require_exact_supported_owner_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _external_process_identity()
    session = _external_session_identity()
    state = StateManager()
    dispatcher = EventDispatcher(state, {})

    monkeypatch.setattr(
        StateManager,
        "get_process_identity_by_object_id",
        lambda _state, object_id: process if object_id == process.object_id else None,
    )
    monkeypatch.setattr(
        StateManager,
        "get_session",
        lambda _state, logon_id: object() if logon_id == session.logon_id else None,
    )
    monkeypatch.setattr(
        StateManager,
        "get_session_identity",
        lambda _state, logon_id: session if logon_id == session.logon_id else None,
    )

    def state_plan(owner: ProcessIdentity | SessionIdentity) -> SimpleNamespace:
        empty: tuple[object, ...] = ()
        return SimpleNamespace(
            sessions=empty,
            processes=empty,
            live_session_process_role_patches=empty,
            session_metadata_patches=empty,
            process_activity_patches=(SimpleNamespace(target=owner),),
            session_activity_patches=empty,
            process_terminations=empty,
            session_terminalizations=empty,
        )

    valid_pairs = (
        (ChildProcessEffectIntent("/usr/bin/child", "child"), process),
        (SessionEffectIntent(SessionEffectAction.START, "interactive", "alice"), session),
    )
    for intent, owner in valid_pairs:
        entry = _linked_entry(intent, owner)
        dispatcher._validate_action_cohort_effect_member_bindings(
            root_action_id=_ROOT_ACTION_ID,
            state_plan=state_plan(owner),
            dispatches=(),
            audit_entries=(entry,),
            bindings=(),
            external_links=(ActionCohortExternalEffectLink(0, entry.plan.nodes[0].node_id, owner),),
            owned_effect_plans=(),
        )

    invalid_pairs = (
        (ChildProcessEffectIntent("/usr/bin/child", "child"), session),
        (SessionEffectIntent(SessionEffectAction.START, "interactive", "alice"), process),
        (FileEffectIntent(FileEffectAction.READ, "/tmp/input"), process),
    )
    for intent, owner in invalid_pairs:
        entry = _linked_entry(intent, owner)
        with pytest.raises(EventContractError, match="State-owned external identity"):
            dispatcher._validate_action_cohort_effect_member_bindings(
                root_action_id=_ROOT_ACTION_ID,
                state_plan=state_plan(owner),
                dispatches=(),
                audit_entries=(entry,),
                bindings=(),
                external_links=(
                    ActionCohortExternalEffectLink(0, entry.plan.nodes[0].node_id, owner),
                ),
                owned_effect_plans=(),
            )


def test_multi_occurrence_action_cohort_guard_remains_closed_to_network_effects() -> None:
    """Only typed process-local endpoint rows may use the per-ordinal relaxation."""

    dispatcher = EventDispatcher(StateManager(), {})
    anchor = ActionAnchor("process_execution", _ROOT_ACTION_ID, source="unit_test")
    node = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("db.internal", 5432, occurrence_cardinality=2),
        role=OccurrenceRole.DEPENDENT,
    )
    plan = ExecutionEffectPlan(anchor, (node,))
    outcome = EffectExecutionOutcome(
        node.node_id,
        EffectOutcomeStatus.REALIZED,
        completed_at=_START,
        child_action_id="network-owner",
        canonical_occurrence_count=2,
    )
    entry = ExecutionEffectAuditCohortEntry(plan, plan.reconcile((outcome,)))

    with pytest.raises(EventContractError, match="typed per-ordinal State/lifecycle authority"):
        dispatcher._validate_action_cohort_effect_member_bindings(
            root_action_id=_ROOT_ACTION_ID,
            state_plan=SimpleNamespace(),
            dispatches=(),
            audit_entries=(entry,),
            bindings=(),
            external_links=(),
            owned_effect_plans=(),
        )


def test_later_owner_claim_failure_preserves_primary_and_closes_prior_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()
    primary = RuntimeError("injected State claim failure")
    close_failure = StateError("injected timing close failure")
    original_timing_claim = SourceTimingPreparation.claimed_commit

    def timing_claim(
        preparation: SourceTimingPreparation,
    ) -> AbstractContextManager[object]:
        return _ExitFailureContext(original_timing_claim(preparation), close_failure)

    def state_claim(
        _state: StateManager,
        _plan: ActionCohortMaterializationPlan,
    ) -> AbstractContextManager[object]:
        return _EnterFailureContext(primary)

    monkeypatch.setattr(SourceTimingPreparation, "claimed_commit", timing_claim)
    monkeypatch.setattr(StateManager, "prepared_action_cohort_materialization", state_claim)

    with pytest.raises(RuntimeError) as caught:
        with cohort.dispatcher.claimed_action_cohort(cohort.batch):
            raise AssertionError("later owner claim unexpectedly succeeded")
    assert caught.value is primary
    assert len(getattr(primary, "__notes__", ())) == 1
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 0
    assert cohort.registry.action_cohort_preparation_census().reservations == 0
    assert cohort.audit.action_cohort_preparation_census().active == 0


def test_final_auth_failure_preserves_primary_and_attempts_every_owner_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()
    primary = RuntimeError("injected final authentication failure")
    close_failure = StateError("injected audit close failure")
    original_audit_claim = ExecutionEffectAuditCounter.claimed_action_cohort

    def audit_claim(
        counter: ExecutionEffectAuditCounter,
        preparation: object,
    ) -> AbstractContextManager[object]:
        return _ExitFailureContext(
            original_audit_claim(counter, preparation),
            close_failure,
        )

    def fail_final_auth(
        _dispatcher: EventDispatcher,
        _record: object,
    ) -> bool:
        raise primary

    monkeypatch.setattr(ExecutionEffectAuditCounter, "claimed_action_cohort", audit_claim)
    monkeypatch.setattr(
        EventDispatcher,
        "_action_cohort_expected_publications_authenticate",
        fail_final_auth,
    )

    with pytest.raises(RuntimeError) as caught:
        with cohort.dispatcher.claimed_action_cohort(cohort.batch):
            raise AssertionError("final authentication unexpectedly succeeded")
    assert caught.value is primary
    assert len(getattr(primary, "__notes__", ())) == 1
    assert cohort.dispatcher.action_cohort_publication_census().prepared_batches == 0
    assert cohort.registry.action_cohort_preparation_census().reservations == 0
    assert cohort.audit.action_cohort_preparation_census().active == 0
    assert not cohort.dispatcher.source_timing_planner.authenticates_preparation(cohort.timing)


def test_action_cohort_publishes_exact_precomputed_receipt_and_result() -> None:
    cohort = _dispatcher_environment()
    prior_version = cohort.state.materialization_version

    result = cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)

    assert type(result) is ActionCohortPublicationResult
    assert cohort.dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert result.state.semantic_id == cohort.state_plan.semantic_id
    assert result.state.committed_version == prior_version + 1
    assert result.receipt.committed_state_version == prior_version + 1
    assert result.projections[0].status == "succeeded"
    assert result.projections[0].error is None
    assert cohort.emitter.emit.call_count == 1
    assert cohort.timing.receipt is result.timing
    assert cohort.audit.action_cohort_preparation_census().active == 0
    assert cohort.dispatcher.action_cohort_publication_census().committed_receipts == 1
    assert not cohort.dispatcher.authenticates_prepared_action_cohort_batch(cohort.batch)
    with pytest.raises(EventContractError, match="stale|consumed"):
        cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)


def test_action_cohort_publishes_exact_admitted_process_create_frontier() -> None:
    """Prepared timing exposes a process frontier only after its projection publishes."""

    cohort = _dispatcher_environment()
    identity = cohort.process_plans[0].identity
    planner = cohort.dispatcher.source_timing_planner
    lookup = {
        "hostname": identity.hostname,
        "pid": identity.pid,
        "started_at": identity.started_at,
    }

    assert planner.admitted_process_create_frontier(**lookup) is None

    cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)

    emitted = cohort.emitter.emit.call_args.args[0]
    assert planner.admitted_process_create_frontier(**lookup) == planner.admission_time(
        emitted,
        "ecar",
    )


def test_emitter_failure_is_terminal_but_attempts_later_members() -> None:
    cohort = _dispatcher_environment(member_count=2)
    failure = RuntimeError("injected first sink failure")
    cohort.emitter.emit.side_effect = (failure, None)

    with cohort.dispatcher.claimed_action_cohort(cohort.batch) as capability:
        with pytest.raises(RuntimeError, match="injected first sink failure") as caught:
            capability.commit_no_fail()
        assert capability.committed
        assert capability.receipt is not None
        assert capability.result is not None
        assert cohort.dispatcher.authenticates_action_cohort_publication_receipt(capability.receipt)
        assert capability.result.projections[0].status == "failed"
        assert capability.result.projections[0].error is failure
        assert capability.result.projections[1].status == "succeeded"
        assert cohort.emitter.emit.call_count == 2
        assert caught.value.action_cohort_receipt is capability.receipt
        assert caught.value.action_cohort_result is capability.result
        with pytest.raises(EventContractError, match="stale|consumed"):
            capability.commit_no_fail()


def test_projection_tail_performs_no_timing_or_observation_planning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("postcommit projection attempted canonical planning")

    monkeypatch.setattr(
        cohort.dispatcher.source_timing_planner,
        "record_admitted_source_event",
        forbidden,
    )
    monkeypatch.setattr(cohort.dispatcher, "_record_observation", forbidden)

    result = cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)
    assert result.projections[0].status == "succeeded"


def test_action_cohort_observation_commit_copies_only_affected_summaries() -> None:
    cohort = _dispatcher_environment()
    dispatcher = cohort.dispatcher
    dispatcher._source_evidence_status = {
        f"cluster-{ordinal}": {"endpoint": ObservationSummary(visible=ordinal)}
        for ordinal in range(1_000)
    }
    retained_root = dispatcher._source_evidence_status
    retained_unrelated = retained_root["cluster-999"]
    record = SimpleNamespace(
        observation_deltas=(
            _ActionCohortObservationDelta(
                cluster_id="cluster-1",
                source="endpoint",
                status="delayed",
                timestamp=_START,
            ),
            _ActionCohortObservationDelta(
                cluster_id="new-cluster",
                source="network",
                status="visible",
                timestamp=_START,
            ),
        ),
        prepared_observation_updates=None,
        observation_committed=False,
    )
    waiter_started = Event()
    waiter_acquired = Event()

    def wait_for_summary_fence() -> None:
        waiter_started.set()
        with dispatcher._source_evidence_lock:
            waiter_acquired.set()

    with dispatcher._claimed_action_cohort_observations(record):
        assert len(record.prepared_observation_updates) == 2
        assert dispatcher._source_evidence_status is retained_root
        assert dispatcher._source_evidence_status["cluster-999"] is retained_unrelated
        waiter = Thread(target=wait_for_summary_fence)
        waiter.start()
        assert waiter_started.wait(timeout=1)
        assert not waiter_acquired.wait(timeout=0.05)
        dispatcher._commit_action_cohort_observations_no_fail(record)
    waiter.join(timeout=1)

    assert not waiter.is_alive()
    assert waiter_acquired.is_set()
    assert dispatcher._source_evidence_status is retained_root
    assert dispatcher._source_evidence_status["cluster-999"] is retained_unrelated
    assert dispatcher._source_evidence_status["cluster-1"]["endpoint"].visible == 1
    assert dispatcher._source_evidence_status["cluster-1"]["endpoint"].delayed == 1
    assert dispatcher._source_evidence_status["new-cluster"]["network"].visible == 1


def test_lifecycle_failure_rolls_back_hidden_state_and_leaves_other_owners_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cohort = _dispatcher_environment()
    prior_version = cohort.state.materialization_version
    prior_timing_digest = cohort.dispatcher.source_timing_planner.state_digest()

    def fail_lifecycle(_prepared: PreparedLifecycleActionCohort) -> object:
        raise StateError("injected lifecycle primitive failure")

    monkeypatch.setattr(PreparedLifecycleActionCohort, "commit_no_fail", fail_lifecycle)
    with pytest.raises(StateError, match="lifecycle primitive failure"):
        cohort.dispatcher.publish_prepared_action_cohort_batch(cohort.batch)

    assert cohort.state.materialization_version == prior_version
    assert (
        cohort.state.get_process(
            cohort.process_plans[0].identity.hostname,
            cohort.process_plans[0].identity.pid,
        )
        is None
    )
    assert cohort.dispatcher.source_timing_planner.state_digest() == prior_timing_digest
    assert cohort.audit.action_cohort_preparation_census().active == 0
    assert cohort.emitter.emit.call_count == 0
    census = cohort.dispatcher.action_cohort_publication_census()
    assert census.prepared_batches == 0
    assert census.committed_receipts == 0
