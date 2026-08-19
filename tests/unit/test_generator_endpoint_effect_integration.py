# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production integration tests for process-owned endpoint effect plans."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import UserProfileIdentity
from evidenceforge.events.contracts import OccurrenceRole
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedDispatch,
    PreparedDispatchStateIntent,
)
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    EffectRequirement,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    FileEffectAction,
    FileEffectIntent,
    RegistryEffectAction,
    RegistryEffectIntent,
)
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectSpec,
    EndpointStateDisposition,
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
    PreparedProcessEffectActor,
    PreparedRegistryEffectPayload,
)
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionPreparedEffects,
    ProcessExecutionRequest,
)
from evidenceforge.generation.actions.scanner_probe import NmapCommandProbeRequest
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactPreparedGroupCommit,
    LocalArtifactPublicationGroupReceipt,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System, User


class _NoAmbientEffectsRandom:
    """Suppress ambient file, module, and registry lotteries deterministically."""

    def random(self) -> float:
        return 0.99

    def choice(self, values):
        return values[0]

    def choices(self, population, weights=None, k=1):
        _ = (weights, k)
        return [population[0]]

    def randint(self, lower: int, _upper: int) -> int:
        return lower

    def uniform(self, lower: float, _upper: float) -> float:
        return lower

    def getrandbits(self, bits: int) -> int:
        return (1 << min(bits, 8)) - 1


class _RegistryOnlyRandom(_NoAmbientEffectsRandom):
    """Admit only the process registry lottery on its third probability draw."""

    def __init__(self) -> None:
        self.random_calls = 0

    def random(self) -> float:
        self.random_calls += 1
        return 0.1 if self.random_calls == 3 else 0.99


def _fixture() -> tuple[ActivityGenerator, StateManager, Mock, User, System, datetime]:
    state = StateManager()
    emitter = Mock()
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"windows_event_security": emitter},
    )
    generator = ActivityGenerator(state, {"windows_event_security": emitter}, dispatcher=dispatcher)
    user = User(username="alice", full_name="Alice Example", email="alice@example.test")
    system = System(
        hostname="WS-001",
        ip="10.10.1.20",
        os="Windows 11 Enterprise",
        type="workstation",
    )
    timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    state.set_current_time(timestamp)
    return generator, state, emitter, user, system, timestamp


def _artifact_fixture(
    *,
    enforce_binary_identity: bool = False,
) -> tuple[
    ActivityGenerator,
    StateManager,
    Mock,
    User,
    System,
    datetime,
    LocalArtifactVersionRegistry,
]:
    """Build one production-shaped generator with a shared runtime artifact owner."""

    state = StateManager()
    emitter = Mock()
    artifact_registry = LocalArtifactVersionRegistry(capacity=16)
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"windows_event_security": emitter},
        local_artifact_registry=artifact_registry,
        enforce_binary_identity=enforce_binary_identity,
    )
    runtime_content_manager = RuntimeContentIdentityManager(artifact_registry)
    generator = ActivityGenerator(
        state,
        {"windows_event_security": emitter},
        dispatcher=dispatcher,
        runtime_content_manager=runtime_content_manager,
    )
    user = User(username="alice", full_name="Alice Example", email="alice@example.test")
    system = System(
        hostname="WS-001",
        ip="10.10.1.20",
        os="Windows 11 Enterprise",
        architecture="x64",
        type="workstation",
    )
    timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    state.set_current_time(timestamp)
    return generator, state, emitter, user, system, timestamp, artifact_registry


def test_activity_generator_preserves_legacy_positional_generation_window_order() -> None:
    """The existing 15-positional constructor contract keeps both window arguments exact."""

    state = StateManager()
    emitter = Mock()
    window_start = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)
    window_end = window_start + timedelta(hours=2)

    generator = ActivityGenerator(
        state,
        {"windows_event_security": emitter},
        None,
        None,
        None,
        "complete",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        window_start,
        window_end,
    )

    assert generator._proxy_channel_window_start == window_start
    assert generator._scenario_end_time == window_end
    assert generator._has_explicit_generation_window_end
    assert generator._runtime_content_manager is None


def test_foreign_runtime_registry_rejects_before_dispatcher_binding_and_exact_retry() -> None:
    """A foreign owner cannot partially bind the dispatcher or poison an exact retry."""

    state = StateManager()
    emitter = Mock()
    dispatcher_registry = LocalArtifactVersionRegistry(capacity=16)
    foreign_registry = LocalArtifactVersionRegistry(capacity=16)
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"windows_event_security": emitter},
        local_artifact_registry=dispatcher_registry,
    )
    neutral_bindings = (
        dispatcher.lifecycle_shadow,
        dispatcher._lifecycle_authority,
        dispatcher._lifecycle_strict_predicate,
        dispatcher._execution_effect_audit,
        dispatcher.local_artifact_registry,
    )

    with pytest.raises(ValueError, match="share one local artifact registry"):
        ActivityGenerator(
            state,
            {"windows_event_security": emitter},
            dispatcher=dispatcher,
            runtime_content_manager=RuntimeContentIdentityManager(foreign_registry),
        )

    assert (
        dispatcher.lifecycle_shadow,
        dispatcher._lifecycle_authority,
        dispatcher._lifecycle_strict_predicate,
        dispatcher._execution_effect_audit,
        dispatcher.local_artifact_registry,
    ) == neutral_bindings

    exact_manager = RuntimeContentIdentityManager(dispatcher_registry)
    generator = ActivityGenerator(
        state,
        {"windows_event_security": emitter},
        dispatcher=dispatcher,
        runtime_content_manager=exact_manager,
    )

    assert generator._runtime_content_manager is exact_manager
    assert dispatcher.local_artifact_registry is dispatcher_registry
    assert dispatcher.lifecycle_shadow is not None
    assert dispatcher.lifecycle_shadow.registry is generator._lifecycle_authority.registry
    assert dispatcher._execution_effect_audit is generator._execution_effect_audit


def test_foreign_lifecycle_registry_rejects_before_dispatcher_binding_and_exact_retry() -> None:
    """A foreign lifecycle owner cannot partially bind or poison the exact retry."""

    state = StateManager()
    emitter = Mock()
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"windows_event_security": emitter},
    )
    exact_registry = LifecycleRegistry()
    exact_shadow = LifecycleShadow(state, exact_registry)
    foreign_registry = LifecycleRegistry()
    foreign_authority = GeneratorLifecycleAuthority(
        state,
        LifecycleShadow(state, foreign_registry),
    )
    neutral_bindings = (
        dispatcher.lifecycle_shadow,
        dispatcher._lifecycle_authority,
        dispatcher._lifecycle_strict_predicate,
        dispatcher._execution_effect_audit,
        dispatcher.local_artifact_registry,
    )

    with pytest.raises(ValueError, match="share one registry"):
        ActivityGenerator(
            state,
            {"windows_event_security": emitter},
            dispatcher=dispatcher,
            lifecycle_shadow=exact_shadow,
            lifecycle_authority=foreign_authority,
        )

    assert (
        dispatcher.lifecycle_shadow,
        dispatcher._lifecycle_authority,
        dispatcher._lifecycle_strict_predicate,
        dispatcher._execution_effect_audit,
        dispatcher.local_artifact_registry,
    ) == neutral_bindings

    exact_authority = GeneratorLifecycleAuthority(state, exact_shadow)
    generator = ActivityGenerator(
        state,
        {"windows_event_security": emitter},
        dispatcher=dispatcher,
        lifecycle_shadow=exact_shadow,
        lifecycle_authority=exact_authority,
    )

    assert dispatcher.lifecycle_shadow is exact_shadow
    assert dispatcher._lifecycle_authority is exact_authority
    assert dispatcher._execution_effect_audit is generator._execution_effect_audit


def test_missing_dispatcher_artifact_registry_binds_exact_runtime_owner() -> None:
    """A manager supplied to a neutral dispatcher becomes its exact artifact owner."""

    state = StateManager()
    emitter = Mock()
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"windows_event_security": emitter},
    )
    artifact_registry = LocalArtifactVersionRegistry(capacity=16)
    runtime_content_manager = RuntimeContentIdentityManager(artifact_registry)

    generator = ActivityGenerator(
        state,
        {"windows_event_security": emitter},
        dispatcher=dispatcher,
        runtime_content_manager=runtime_content_manager,
    )

    assert dispatcher.local_artifact_registry is artifact_registry
    assert generator._runtime_content_manager is runtime_content_manager

    user = User(username="alice", full_name="Alice Example", email="alice@example.test")
    system = System(
        hostname="WS-001",
        ip="10.10.1.20",
        os="Windows 11 Enterprise",
        architecture="x64",
        type="workstation",
    )
    timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    state.set_current_time(timestamp)
    image = r"C:\Users\Public\missing-registry-retry.exe"

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            image,
            image,
            ensure_file_event=True,
        )

    assert artifact_registry.census().live_versions == 1


def _retained_process_runtime_shape(generator: ActivityGenerator) -> tuple[object, ...]:
    """Return retained runtime-cache structure while ignoring read-only probe counters."""

    census_reader = getattr(generator, "process_runtime_cache_census", None)
    if not callable(census_reader):
        # The process/effect bridge lands before the separate packed-retention owner.
        # Preserve this all-or-none assertion against the exact legacy structures that
        # the bridge can mutate without importing that independently owned migration.
        names = (
            "_user_process_history",
            "_terminated_process_keys",
            "_terminated_process_times",
            "_last_one_shot_cli_launch_by_exe",
            "_last_one_shot_cli_launch_by_command",
            "_preferred_browser_by_session",
            "_last_browser_launch_by_session",
            "_process_source_create_times",
            "_process_source_terminate_times",
            "_process_source_create_latest",
            "_process_source_terminate_latest",
            "_session_process_source_terminate_times",
            "_process_connection_hold_until",
            "_foreground_shell_next_time",
            "_foreground_shell_release_groups",
        )
        return tuple(
            (
                name,
                tuple(
                    sorted(
                        (repr(key), repr(value))
                        for key, value in (
                            container.items()
                            if isinstance(container, dict)
                            else ((item, item) for item in container)
                        )
                    )
                ),
            )
            for name in names
            if isinstance((container := getattr(generator, name, None)), (dict, set))
        )

    census = census_reader()
    return (
        census.physical_records,
        census.live_entries,
        census.backing_entries,
        census.stale_entries,
        census.high_water_entries,
        census.reverse_subjects,
        census.reverse_bindings,
        census.reverse_high_water,
        census.reverse_backing_entries,
        census.reverse_stale_entries,
        census.watermark,
        tuple(
            (
                family.name,
                family.live_entries,
                family.backing_entries,
                family.stale_entries,
                family.high_water_mark,
            )
            for family in census.families
        ),
    )


def _events(emitter: Mock) -> list[OccurrenceBuilder]:
    return [call.args[0] for call in emitter.emit.call_args_list]


def test_guaranteed_file_create_uses_exact_process_plan_and_preserves_fields() -> None:
    generator, state, emitter, user, system, timestamp = _fixture()
    image = r"C:\Users\Public\dropper.exe"

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            image,
            image,
            ensure_file_event=True,
        )

    process_identity = state.get_process_identity(system.hostname, pid)
    assert process_identity is not None
    file_event = next(
        event
        for event in _events(emitter)
        if event.event_type == "file_create" and event.file is not None
    )
    assert file_event.file.path == image
    assert file_event.file.action == "create"
    assert file_event.process is not None
    assert file_event.process.pid == pid
    assert file_event.identity_plan is not None
    assert file_event.identity_plan.actor_id == process_identity.object_id
    assert file_event.identity_plan.subject is not None
    assert file_event.identity_plan.subject.kind == "file"
    audit = generator.execution_effect_audit_snapshot()
    assert audit.plan_count == 2
    assert audit.no_effect_plan_count == 1
    assert audit.planned_node_count == 1
    assert audit.realized_effect_occurrence_count == 1


def test_required_storyline_redirect_is_one_planned_realized_process_linked_file() -> None:
    generator, state, emitter, user, system, timestamp = _fixture()
    path = r"C:\Windows\Temp\filelist.txt"
    file_time = timestamp + timedelta(seconds=5)
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(FileEffectAction.CREATE, path),
            occurrence_times=(file_time,),
            instance_key="storyline-command-output-file",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=file_time + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp,
        logon_id="0x12345",
        process_name=r"C:\Windows\System32\cmd.exe",
        command_line=rf"cmd.exe /c dir C:\ > {path}",
        from_storyline=True,
        suppress_command_file_effect=True,
        requested_endpoint_effects=(requested_effect,),
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, request).execute()

    file_events = [
        event
        for event in _events(emitter)
        if event.event_type == "file_create" and event.file is not None
    ]
    assert len(file_events) == 1
    file_event = file_events[0]
    assert file_event.file.path == path
    assert file_event.process is not None and file_event.process.pid == pid
    assert file_event.effect_provenance is not None
    assert (
        file_event.effect_provenance.root_action_id
        == ProcessExecutionActionBundle(
            generator,
            request,
        ).anchor.action_id
    )
    assert file_event.effect_provenance.plan_action_id != ""
    audit = generator.execution_effect_audit_snapshot()
    assert audit.complete
    assert audit.planned_node_count == 1
    assert audit.realized_node_count == 1
    assert audit.reconciled_effect_occurrence_count == 1
    assert audit.published_effect_occurrence_count == 1
    assert audit.effect_publication_mismatch_count == 0


def test_second_required_redirect_prepare_rejection_leaves_every_authority_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An Nth required occurrence fails before root, artifact, or owner publication."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    ledger = IntentExecutionLedger(AuthoredIntentLedger("redirect-rejection", ()))
    generator.dispatcher.intent_execution_ledger = ledger
    generator.dispatcher.authored_intent_id = "redirect-rejection"
    path = r"C:\Windows\Temp\filelist.txt"
    file_times = (
        timestamp + timedelta(seconds=5),
        timestamp + timedelta(seconds=7),
    )
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(
                FileEffectAction.CREATE,
                path,
                occurrence_cardinality=len(file_times),
            ),
            occurrence_times=file_times,
            instance_key="storyline-command-output-file",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=file_times[-1] + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp,
        logon_id="0x12345",
        process_name=r"C:\Windows\System32\cmd.exe",
        command_line=rf"cmd.exe /c dir C:\ > {path}",
        from_storyline=True,
        suppress_command_file_effect=True,
        requested_endpoint_effects=(requested_effect,),
    )
    state_digest = state.materialization_digest()
    lifecycle_census = generator._lifecycle_authority.census()
    registry_census = generator._lifecycle_authority.registry.stats()
    runtime_shape = _retained_process_runtime_shape(generator)
    artifact_census = artifact_registry.census()
    audit_snapshot = generator.execution_effect_audit_snapshot()
    timing_planner = generator.dispatcher.source_timing_planner
    timing_digest = timing_planner.state_digest()
    timing_census = timing_planner.census(estimate_bytes=True)
    timing_audit = timing_planner.timing_runtime.audit.snapshot()
    source_status = generator.dispatcher.source_evidence_status
    original_prepare = generator.dispatcher.prepare_builder
    dependent_prepare_attempts = 0

    def reject_required_file(
        builder: OccurrenceBuilder,
        **kwargs: object,
    ) -> PreparedDispatch:
        nonlocal dependent_prepare_attempts
        if builder.file is not None:
            dependent_prepare_attempts += 1
            if dependent_prepare_attempts == 2:
                raise EventContractError("injected required redirect consequence rejection")
        return original_prepare(builder, **kwargs)

    monkeypatch.setattr(generator.dispatcher, "prepare_builder", reject_required_file)

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(
            EventContractError,
            match="injected required redirect consequence rejection",
        ),
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    assert dependent_prepare_attempts == 2
    assert state.materialization_digest() == state_digest
    assert generator._lifecycle_authority.census() == lifecycle_census
    assert generator._lifecycle_authority.registry.stats() == registry_census
    assert _retained_process_runtime_shape(generator) == runtime_shape
    assert artifact_registry.census() == artifact_census
    assert generator.execution_effect_audit_snapshot() == audit_snapshot
    assert timing_planner.state_digest() == timing_digest
    assert timing_planner.census(estimate_bytes=True) == timing_census
    assert timing_planner.timing_runtime.audit.snapshot() == timing_audit
    assert ledger.snapshot() == ()
    assert generator.dispatcher.source_evidence_status == source_status
    emitter.emit.assert_not_called()


def test_process_artifacts_commit_before_timing_and_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compound process commit preserves artifact, timing, then output order."""

    (
        generator,
        _state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    order: list[str] = []
    prepared_timing_capabilities: list[SourceTimingPreparation] = []
    original_artifact_commit = LocalArtifactPreparedGroupCommit.commit_no_fail
    original_timing_commit = SourceTimingPreparation.commit_no_fail
    original_prepare_builder = generator.dispatcher.prepare_builder

    def commit_artifact(
        commit: LocalArtifactPreparedGroupCommit,
    ) -> LocalArtifactPublicationGroupReceipt:
        order.append("artifact")
        return original_artifact_commit(commit)

    def commit_timing(preparation: SourceTimingPreparation) -> None:
        order.append("timing")
        original_timing_commit(preparation)

    def record_publication(*_args: object, **_kwargs: object) -> None:
        order.append("publish")

    def capture_preparation(
        builder: OccurrenceBuilder,
        **kwargs: object,
    ) -> PreparedDispatch:
        preparation = kwargs.get("source_timing_preparation")
        if preparation is not None:
            assert isinstance(preparation, SourceTimingPreparation)
            prepared_timing_capabilities.append(preparation)
        return original_prepare_builder(builder, **kwargs)

    monkeypatch.setattr(LocalArtifactPreparedGroupCommit, "commit_no_fail", commit_artifact)
    monkeypatch.setattr(SourceTimingPreparation, "commit_no_fail", commit_timing)
    monkeypatch.setattr(generator.dispatcher, "prepare_builder", capture_preparation)
    emitter.emit.side_effect = record_publication

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\dropper.exe",
            r"C:\Users\Public\dropper.exe",
            ensure_file_event=True,
        )

    assert order.count("artifact") == 1
    assert order.count("timing") == 1
    assert order.count("publish") >= 2
    assert order[:2] == ["artifact", "timing"]
    assert set(order[2:]) == {"publish"}
    assert len(prepared_timing_capabilities) == 2
    timing_preparation = prepared_timing_capabilities[0]
    assert all(preparation is timing_preparation for preparation in prepared_timing_capabilities)
    assert timing_preparation.committed
    assert timing_preparation.receipt is not None
    assert generator.dispatcher.source_timing_planner.authenticates_preparation_receipt(
        timing_preparation.receipt
    )
    assert list(dict.fromkeys(event.event_type for event in _events(emitter)))[:2] == [
        "process_create",
        "file_create",
    ]
    census = artifact_registry.census()
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0
    assert census.reserved_slots == 0


def test_required_artifact_failure_rolls_back_production_action_cohort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ordinary artifact-owner failure leaves every canonical owner unchanged."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    ledger = IntentExecutionLedger(AuthoredIntentLedger("artifact-failure", ()))
    generator.dispatcher.intent_execution_ledger = ledger
    generator.dispatcher.authored_intent_id = "artifact-failure"
    state_digest = state.materialization_digest()
    lifecycle_census = generator._lifecycle_authority.census()
    registry_census = generator._lifecycle_authority.registry.stats()
    runtime_shape = _retained_process_runtime_shape(generator)
    artifact_census = artifact_registry.census()
    audit_snapshot = generator.execution_effect_audit_snapshot()
    timing_planner = generator.dispatcher.source_timing_planner
    timing_digest = timing_planner.state_digest()
    timing_census = timing_planner.census(estimate_bytes=True)
    timing_audit = timing_planner.timing_runtime.audit.snapshot()
    source_status = generator.dispatcher.source_evidence_status
    cohort_census = generator.dispatcher.action_cohort_publication_census()
    commit_attempts = 0

    def reject_artifacts(
        _commit: LocalArtifactPreparedGroupCommit,
    ) -> LocalArtifactPublicationGroupReceipt:
        nonlocal commit_attempts
        commit_attempts += 1
        raise StateError("injected runtime artifact group failure")

    monkeypatch.setattr(
        LocalArtifactPreparedGroupCommit,
        "commit_no_fail",
        reject_artifacts,
    )

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(StateError, match="injected runtime artifact group failure"),
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\dropper.exe",
            r"C:\Users\Public\dropper.exe",
            ensure_file_event=True,
        )

    assert commit_attempts == 1
    assert state.materialization_digest() == state_digest
    assert generator._lifecycle_authority.census() == lifecycle_census
    assert generator._lifecycle_authority.registry.stats() == registry_census
    assert _retained_process_runtime_shape(generator) == runtime_shape
    assert artifact_registry.census() == artifact_census
    assert generator.execution_effect_audit_snapshot() == audit_snapshot
    assert timing_planner.state_digest() == timing_digest
    assert timing_planner.census(estimate_bytes=True) == timing_census
    assert timing_planner.timing_runtime.audit.snapshot() == timing_audit
    assert ledger.snapshot() == ()
    assert generator.dispatcher.source_evidence_status == source_status
    assert generator.dispatcher.action_cohort_publication_census() == cohort_census
    emitter.emit.assert_not_called()


def test_filtered_multi_occurrence_effect_cohort_commits_rows_and_latest_frontiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filtered multi-occurrence rows still commit exact State and audit frontiers."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    logon_id = generator.generate_logon(user, system, timestamp)
    emitter.reset_mock()
    generator.dispatcher.output_start_time = timestamp + timedelta(hours=1)
    process_time = timestamp + timedelta(seconds=1)
    occurrence_times = (
        process_time + timedelta(seconds=5),
        process_time + timedelta(seconds=7),
    )
    path = r"C:\Users\Public\warmup.exe"
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(
                FileEffectAction.CREATE,
                path,
                occurrence_cardinality=len(occurrence_times),
            ),
            occurrence_times=occurrence_times,
            instance_key="filtered-warmup-file",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=occurrence_times[-1] + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=process_time,
        logon_id=logon_id,
        process_name=r"C:\Users\Public\warmup.exe",
        command_line=r"C:\Users\Public\warmup.exe",
        requested_endpoint_effects=(requested_effect,),
    )
    prepared_file_builders: list[OccurrenceBuilder] = []
    original_prepare = generator.dispatcher.prepare_builder

    def capture_prepare(
        builder: OccurrenceBuilder,
        **kwargs: object,
    ) -> PreparedDispatch:
        if builder.event_type == "file_create":
            prepared_file_builders.append(builder)
        return original_prepare(builder, **kwargs)

    monkeypatch.setattr(generator.dispatcher, "prepare_builder", capture_prepare)

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, request).execute()

    process = state.get_process(system.hostname, pid)
    assert process is not None
    assert process.last_activity_time == occurrence_times[-1]
    session = state.get_session(logon_id)
    assert session is not None
    assert session.last_activity_time == occurrence_times[-1]
    assert tuple(builder.timestamp for builder in prepared_file_builders) == occurrence_times
    assert tuple(
        builder.effect_provenance.occurrence_ordinal
        for builder in prepared_file_builders
        if builder.effect_provenance is not None
    ) == (0, 1)
    audit = generator.execution_effect_audit_snapshot()
    assert audit.complete
    assert audit.planned_effect_occurrence_count == 2
    assert audit.realized_effect_occurrence_count == 2
    assert audit.reconciled_effect_occurrence_count == 2
    assert audit.published_effect_occurrence_count == 2
    artifact_census = artifact_registry.census()
    assert artifact_census.live_versions == 1
    assert artifact_census.prepared_publications == 0
    assert artifact_census.claimed_publications == 0
    assert artifact_census.reserved_slots == 0
    emitter.emit.assert_not_called()


def test_process_endpoint_action_cohort_rejects_over_member_cap_before_mutation() -> None:
    """Root plus endpoint occurrences cannot overflow the bounded dispatcher cohort."""

    generator, state, emitter, user, system, timestamp = _fixture()
    logon_id = generator.generate_logon(user, system, timestamp)
    emitter.reset_mock()
    timing_planner = generator.dispatcher.source_timing_planner
    occurrence_times = tuple(timestamp + timedelta(seconds=5 + ordinal) for ordinal in range(256))
    path = r"C:\Windows\Temp\bounded.txt"
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(
                FileEffectAction.CREATE,
                path,
                occurrence_cardinality=len(occurrence_times),
            ),
            occurrence_times=occurrence_times,
            instance_key="over-cap-file",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=occurrence_times[-1] + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp + timedelta(seconds=1),
        logon_id=logon_id,
        process_name=r"C:\Users\Public\bounded.exe",
        command_line=r"C:\Users\Public\bounded.exe",
        requested_endpoint_effects=(requested_effect,),
    )
    before_state = state.materialization_digest()
    before_lifecycle = generator._lifecycle_authority.census()
    before_registry = generator._lifecycle_authority.registry.stats()
    before_runtime_shape = _retained_process_runtime_shape(generator)
    before_audit = generator.execution_effect_audit_snapshot()
    before_timing = timing_planner.state_digest()
    before_timing_census = timing_planner.census(estimate_bytes=True)
    before_timing_audit = timing_planner.timing_runtime.audit.snapshot()
    before_source_status = generator.dispatcher.source_evidence_status
    before_cohort = generator.dispatcher.action_cohort_publication_census()

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(ExecutionEffectPlanError, match="root/occurrence member limit") as exc_info,
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_PLAN
    assert state.materialization_digest() == before_state
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert generator._lifecycle_authority.registry.stats() == before_registry
    assert _retained_process_runtime_shape(generator) == before_runtime_shape
    assert generator.execution_effect_audit_snapshot() == before_audit
    assert timing_planner.state_digest() == before_timing
    assert timing_planner.census(estimate_bytes=True) == before_timing_census
    assert timing_planner.timing_runtime.audit.snapshot() == before_timing_audit
    assert generator.dispatcher.source_evidence_status == before_source_status
    assert generator.dispatcher.action_cohort_publication_census() == before_cohort
    emitter.emit.assert_not_called()


def test_equal_time_multi_occurrence_closure_uses_distinct_plan_owned_keys() -> None:
    """Valid equal-time closure ordinals retain distinct canonical identities."""

    generator, state, emitter, user, system, timestamp = _fixture()
    logon_id = generator.generate_logon(user, system, timestamp)
    emitter.reset_mock()
    process_time = timestamp + timedelta(seconds=1)
    effect_time = process_time + timedelta(seconds=5)
    path = r"C:\Windows\Temp\gone.txt"
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(
                FileEffectAction.DELETE,
                path,
                occurrence_cardinality=2,
            ),
            occurrence_times=(effect_time, effect_time),
            instance_key="equal-time-closure-delete",
            role=OccurrenceRole.CLOSURE,
        ),
        event_type="file_delete",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.DELETE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=process_time,
        logon_id=logon_id,
        process_name=r"C:\Users\Public\cleanup.exe",
        command_line=r"C:\Users\Public\cleanup.exe",
        requested_endpoint_effects=(requested_effect,),
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, request).execute()

    file_events = [event for event in _events(emitter) if event.event_type == "file_delete"]
    assert len(file_events) == 2
    assert all(event.timestamp == effect_time for event in file_events)
    assert all(
        event.occurrence_key is not None and event.occurrence_key.role is OccurrenceRole.CLOSURE
        for event in file_events
    )
    assert len({event.occurrence_id for event in file_events}) == 2
    assert tuple(
        event.effect_provenance.occurrence_ordinal
        for event in file_events
        if event.effect_provenance is not None
    ) == (0, 1)
    process = state.get_process(system.hostname, pid)
    assert process is not None and process.last_activity_time == effect_time
    session = state.get_session(logon_id)
    assert session is not None and session.last_activity_time == effect_time
    audit = generator.execution_effect_audit_snapshot()
    assert audit.complete
    assert audit.published_effect_occurrence_count == 2


def test_scanner_effect_intent_bypasses_process_endpoint_action_cohort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanner commands stay on the legacy process/dependent path until grouped transport."""

    generator, state, emitter, user, system, timestamp = _fixture()
    prepared_state_intents: list[tuple[str, PreparedDispatchStateIntent]] = []
    scanner_process_visibility: list[bool] = []
    cohort_census = generator.dispatcher.action_cohort_publication_census()
    original_prepare = generator.dispatcher.prepare_builder

    def capture_prepare(
        builder: OccurrenceBuilder,
        **kwargs: object,
    ) -> PreparedDispatch:
        if builder.event_type in {"process_create", "file_create"}:
            state_intent = kwargs.get("state_intent")
            assert isinstance(state_intent, PreparedDispatchStateIntent)
            prepared_state_intents.append((builder.event_type, state_intent))
        return original_prepare(builder, **kwargs)

    def reject_partial_scanner_cohort(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scanner process must not enter the endpoint action cohort")

    def execute_scanner_probe(request: NmapCommandProbeRequest) -> int:
        scanner_process_visibility.append(
            state.get_process(system.hostname, request.pid) is not None
        )
        return 1

    monkeypatch.setattr(generator.dispatcher, "prepare_builder", capture_prepare)
    monkeypatch.setattr(
        generator.dispatcher,
        "prepare_action_cohort_batch",
        reject_partial_scanner_cohort,
    )
    monkeypatch.setattr(
        generator,
        "_execute_nmap_command_probe_bundle",
        execute_scanner_probe,
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\scanner-dropper.exe",
            "nmap -sT -p 80 10.10.2.30",
            ensure_file_event=True,
        )

    assert scanner_process_visibility == [True]
    assert state.get_process(system.hostname, pid) is not None
    assert prepared_state_intents[:2] == [
        ("process_create", PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_START),
        ("file_create", PreparedDispatchStateIntent.EXTERNAL_DEPENDENT),
    ]
    assert generator.dispatcher.action_cohort_publication_census() == cohort_census
    assert generator.execution_effect_audit_snapshot().complete
    emitted = _events(emitter)
    assert [event.event_type for event in emitted][:2] == [
        "process_create",
        "file_create",
    ]
    process_event, file_event = emitted[:2]
    assert process_event.identity_plan is not None
    assert process_event.identity_plan.session is None
    assert file_event.lifecycle is None


def test_no_session_linux_nmap_preserves_process_probes_and_foreground_hold() -> None:
    """Legacy scanner publication samples its close after resolving the shell parent."""

    state = StateManager()
    process_emitter = Mock()
    connection_emitter = Mock()
    emitters = {
        "windows_event_security": process_emitter,
        "zeek_conn": connection_emitter,
    }
    dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    user = User(username="alice", full_name="Alice Example", email="alice@example.test")
    source = System(
        hostname="SCAN-01",
        ip="10.10.3.10",
        os="Ubuntu 22.04",
        type="server",
    )
    target = System(
        hostname="APP-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
        services=["ssh"],
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    state.set_current_time(timestamp)

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            user=user,
            system=source,
            time=timestamp,
            logon_id="0x123",
            process_name="/usr/bin/nmap",
            command_line="nmap -sT -p 22 10.10.2.30",
            parent_pid=0,
        )

    process = state.get_process(source.hostname, pid)
    assert process is not None
    parent = state.get_process(source.hostname, process.parent_pid)
    assert parent is not None and parent.image.rsplit("/", 1)[-1] in {"bash", "sh", "zsh"}
    probes = [
        event
        for event in _events(connection_emitter)
        if event.event_type == "connection"
        and event.network is not None
        and event.network.initiating_pid == pid
    ]
    assert len(probes) == 1
    probe_close = probes[0].network.closed_at
    assert probe_close is not None
    process_key = generator._process_instance_key(source.hostname, pid)
    assert process_key not in generator._process_connection_hold_until
    finalizer_time = generator.foreground_process_termination_time(source.hostname, pid)
    assert finalizer_time == process.start_time + timedelta(seconds=4.367418)


@pytest.mark.parametrize("effect_kind", ["file", "registry"])
def test_scanner_multi_occurrence_endpoint_rejects_without_owner_residue(
    effect_kind: str,
) -> None:
    """The scanner legacy path rejects unsupported cardinality before publication."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    ledger = IntentExecutionLedger(AuthoredIntentLedger("scanner-cardinality", ()))
    generator.dispatcher.intent_execution_ledger = ledger
    generator.dispatcher.authored_intent_id = "scanner-cardinality"
    occurrence_times = (
        timestamp + timedelta(seconds=5),
        timestamp + timedelta(seconds=7),
    )
    if effect_kind == "file":
        path = r"C:\Users\Public\scanner-results.txt"
        requested_effect = PreparedEndpointEffect(
            spec=EndpointEffectSpec(
                intent=FileEffectIntent(
                    FileEffectAction.CREATE,
                    path,
                    occurrence_cardinality=len(occurrence_times),
                ),
                occurrence_times=occurrence_times,
                instance_key="scanner-multi-output",
                state_disposition=EndpointStateDisposition.DURABLE_FINAL,
                retention_deadline=occurrence_times[-1] + timedelta(microseconds=1),
            ),
            event_type="file_create",
            payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
        )
    else:
        key = r"HKCU\Software\Scanner\LastTarget"
        requested_effect = PreparedEndpointEffect(
            spec=EndpointEffectSpec(
                intent=RegistryEffectIntent(
                    RegistryEffectAction.MODIFY,
                    key,
                    value_name="Target",
                    occurrence_cardinality=len(occurrence_times),
                ),
                occurrence_times=occurrence_times,
                instance_key="scanner-multi-registry",
                state_disposition=EndpointStateDisposition.DURABLE_FINAL,
                retention_deadline=occurrence_times[-1] + timedelta(microseconds=1),
            ),
            event_type="registry_modify",
            payload=PreparedRegistryEffectPayload(
                key=key,
                value_name="Target",
                value="10.10.2.30",
                value_type="REG_SZ",
                action=RegistryEffectAction.MODIFY,
            ),
        )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp,
        logon_id="0x12345",
        process_name=r"C:\Users\Public\nmap.exe",
        command_line="nmap -sT -p 80 10.10.2.30",
        requested_endpoint_effects=(requested_effect,),
    )
    timing_planner = generator.dispatcher.source_timing_planner
    before_state = state.materialization_digest()
    before_lifecycle = generator._lifecycle_authority.census()
    before_registry = generator._lifecycle_authority.registry.stats()
    before_runtime_shape = _retained_process_runtime_shape(generator)
    before_artifacts = artifact_registry.census()
    before_audit = generator.execution_effect_audit_snapshot()
    before_timing = timing_planner.state_digest()
    before_timing_census = timing_planner.census(estimate_bytes=True)
    before_timing_audit = timing_planner.timing_runtime.audit.snapshot()
    before_source_status = generator.dispatcher.source_evidence_status
    before_cohort = generator.dispatcher.action_cohort_publication_census()
    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        patch.object(
            RuntimeContentIdentityManager,
            "prepare_effect_publication",
            side_effect=AssertionError("artifact preparation preceded scanner validation"),
        ) as prepare_artifact,
        pytest.raises(
            ExecutionEffectPlanError,
            match="scanner process endpoint effects require exactly one occurrence",
        ) as exc_info,
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_PLAN
    assert state.materialization_digest() == before_state
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert generator._lifecycle_authority.registry.stats() == before_registry
    assert _retained_process_runtime_shape(generator) == before_runtime_shape
    assert artifact_registry.census() == before_artifacts
    assert generator.execution_effect_audit_snapshot() == before_audit
    assert timing_planner.state_digest() == before_timing
    assert timing_planner.census(estimate_bytes=True) == before_timing_census
    assert timing_planner.timing_runtime.audit.snapshot() == before_timing_audit
    assert generator.dispatcher.source_evidence_status == before_source_status
    assert generator.dispatcher.action_cohort_publication_census() == before_cohort
    assert ledger.snapshot() == ()
    prepare_artifact.assert_not_called()
    emitter.emit.assert_not_called()


def test_unregistered_state_session_multi_occurrence_rejects_without_owner_residue() -> None:
    """A compatibility-only State session cannot silently truncate endpoint cardinality."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=3,
        source_ip="10.10.1.10",
        start_time=timestamp,
    )
    occurrence_times = (
        timestamp + timedelta(seconds=5),
        timestamp + timedelta(seconds=7),
    )
    path = r"C:\Users\Public\compatibility-output.txt"
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(
                FileEffectAction.CREATE,
                path,
                occurrence_cardinality=len(occurrence_times),
            ),
            occurrence_times=occurrence_times,
            instance_key="compatibility-session-multi-output",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=occurrence_times[-1] + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp + timedelta(seconds=1),
        logon_id=logon_id,
        process_name=r"C:\Users\Public\compatibility-tool.exe",
        command_line=r"C:\Users\Public\compatibility-tool.exe",
        requested_endpoint_effects=(requested_effect,),
    )
    timing_planner = generator.dispatcher.source_timing_planner
    before_state = state.materialization_digest()
    before_lifecycle = generator._lifecycle_authority.census()
    before_registry = generator._lifecycle_authority.registry.stats()
    before_runtime_shape = _retained_process_runtime_shape(generator)
    before_artifacts = artifact_registry.census()
    before_audit = generator.execution_effect_audit_snapshot()
    before_timing = timing_planner.state_digest()
    before_timing_census = timing_planner.census(estimate_bytes=True)
    before_timing_audit = timing_planner.timing_runtime.audit.snapshot()
    before_source_status = generator.dispatcher.source_evidence_status
    before_cohort = generator.dispatcher.action_cohort_publication_census()
    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        patch.object(
            RuntimeContentIdentityManager,
            "prepare_effect_publication",
            side_effect=AssertionError("artifact preparation preceded session validation"),
        ) as prepare_artifact,
        pytest.raises(
            ExecutionEffectPlanError,
            match="State session lacks exact lifecycle-registry identity",
        ) as exc_info,
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_PLAN
    assert state.materialization_digest() == before_state
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert generator._lifecycle_authority.registry.stats() == before_registry
    assert _retained_process_runtime_shape(generator) == before_runtime_shape
    assert artifact_registry.census() == before_artifacts
    assert generator.execution_effect_audit_snapshot() == before_audit
    assert timing_planner.state_digest() == before_timing
    assert timing_planner.census(estimate_bytes=True) == before_timing_census
    assert timing_planner.timing_runtime.audit.snapshot() == before_timing_audit
    assert generator.dispatcher.source_evidence_status == before_source_status
    assert generator.dispatcher.action_cohort_publication_census() == before_cohort
    prepare_artifact.assert_not_called()
    emitter.emit.assert_not_called()


def test_required_executable_file_commits_one_exact_artifact_before_publication() -> None:
    """The root and file row share one committed executable/content identity."""

    (
        generator,
        state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    image = r"C:\Users\Public\dropper.exe"

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            image,
            image,
            ensure_file_event=True,
        )

    process_event = next(
        event for event in _events(emitter) if event.event_type == "process_create"
    )
    file_event = next(event for event in _events(emitter) if event.event_type == "file_create")
    assert process_event.process is not None
    assert process_event.process.pid == pid
    assert process_event.process.binary_identity is not None
    assert file_event.file is not None
    assert file_event.file.artifact_identity is not None
    assert file_event.file.content_identity is not None
    record = artifact_registry.resolve_version(
        file_event.file.artifact_identity.artifact_version_id
    )
    assert record is not None
    assert record.artifact == file_event.file.artifact_identity
    assert record.content == file_event.file.content_identity
    assert record.binary == process_event.process.binary_identity
    census = artifact_registry.census()
    assert census.live_versions == 1
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0
    assert census.reserved_slots == 0


def test_unresolved_root_executable_commits_exact_binary_without_file_effect() -> None:
    """An unresolved process image is a required root publication, not a placeholder."""

    (
        generator,
        _state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    image = r"C:\Users\alice\AppData\Local\Temp\dotnet-sdk-installer.exe"

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            image,
            image,
        )

    process_event = next(
        event for event in _events(emitter) if event.event_type == "process_create"
    )
    assert process_event.process is not None
    assert process_event.process.binary_identity is not None
    record = artifact_registry.resolve_record_for_execution_path(
        system.hostname,
        user.username,
        image,
        "windows",
    )
    assert record is not None
    assert record.binary == process_event.process.binary_identity
    assert not any(event.file is not None for event in _events(emitter))
    census = artifact_registry.census()
    assert census.live_versions == 1
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0


def test_missing_compiled_runtime_owner_is_typed_and_leaves_every_authority_unchanged() -> None:
    """A missing exact host/principal profile is optional-admission truth, not raw ValueError."""

    generator, state, emitter, user, system, timestamp, artifact_registry = _artifact_fixture(
        enforce_binary_identity=True
    )
    generator.dispatcher.bind_deployment_registry(DeploymentContentRegistry())
    before_state = state.materialization_digest()
    before_lifecycle = generator._lifecycle_authority.census()
    before_cache = _retained_process_runtime_shape(generator)
    before_artifacts = artifact_registry.census()
    before_audit = generator.execution_effect_audit_snapshot()

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(ExecutionEffectPlanError) as exc_info,
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\alice\AppData\Local\Temp\unowned.exe",
            r"C:\Users\alice\AppData\Local\Temp\unowned.exe",
            ensure_file_event=True,
        )

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR
    assert "exact compiled host/principal profile" in str(exc_info.value)
    assert state.materialization_digest() == before_state
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert _retained_process_runtime_shape(generator) == before_cache
    assert artifact_registry.census() == before_artifacts
    assert generator.execution_effect_audit_snapshot() == before_audit
    assert _events(emitter) == []


def test_nested_parent_admission_rejection_cancels_outer_plan_without_mutation() -> None:
    """A late typed parent rejection cancels the frozen optional process admission."""

    (
        generator,
        state,
        emitter,
        user,
        _system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture()
    linux = System(
        hostname="LNX-001",
        ip="10.10.2.20",
        os="Ubuntu 24.04 LTS",
        architecture="x64",
        type="workstation",
    )
    effect_time = timestamp + timedelta(seconds=5)
    optional_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(FileEffectAction.CREATE, "/tmp/optional-result.bin"),
            occurrence_times=(effect_time,),
            instance_key="optional-parent-owned-file",
            requirement=EffectRequirement.OPTIONAL,
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=effect_time + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(
            path="/tmp/optional-result.bin",
            action=FileEffectAction.CREATE,
        ),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=linux,
        time=timestamp,
        logon_id="0xlinux-user",
        process_name="/opt/tools/collector",
        command_line="/opt/tools/collector --write /tmp/optional-result.bin",
        parent_pid=4,
        requested_endpoint_effects=(optional_effect,),
    )
    ledger = IntentExecutionLedger(AuthoredIntentLedger("parent-rejection", ()))
    generator.dispatcher.intent_execution_ledger = ledger
    generator.dispatcher.authored_intent_id = "parent-rejection"
    before_state = state.materialization_digest()
    before_lifecycle = generator._lifecycle_authority.census()
    before_cache = _retained_process_runtime_shape(generator)
    before_artifacts = artifact_registry.census()
    before_audit = generator.execution_effect_audit_snapshot()

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        patch.object(generator.dispatcher, "resolve_process_binary_identity", return_value=None),
        patch.object(
            generator,
            "_sanitize_user_parent_pid",
            side_effect=ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "nested Linux parent has no exact admissible runtime owner",
            ),
        ),
        pytest.raises(ExecutionEffectPlanError) as exc_info,
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR
    assert state.materialization_digest() == before_state
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert _retained_process_runtime_shape(generator) == before_cache
    assert artifact_registry.census() == before_artifacts
    assert generator.execution_effect_audit_snapshot() == before_audit
    assert ledger.snapshot() == ()
    assert _events(emitter) == []


def test_linux_root_runtime_binary_uses_system_profile_without_fabricated_user() -> None:
    """Linux root is a typed system artifact owner and never needs a fake user profile."""

    generator, state, emitter, _user, _system, timestamp, artifact_registry = _artifact_fixture(
        enforce_binary_identity=True
    )
    generator.dispatcher.bind_deployment_registry(DeploymentContentRegistry())
    root = User(username="root", full_name="root", email="root@linux.example.test")
    system = System(
        hostname="LINUX-01",
        ip="10.10.2.20",
        os="Ubuntu 24.04 LTS",
        architecture="x64",
        type="workstation",
    )
    image = "/usr/libexec/gnome-terminal-server"

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            root,
            system,
            timestamp,
            "0x3e7",
            image,
            image,
        )

    process_identity = state.get_process_identity(system.hostname, pid)
    assert process_identity is not None
    record = artifact_registry.resolve_record_for_execution_path(
        system.hostname,
        root.username,
        image,
        "linux",
    )
    assert record is not None
    assert record.binary is not None
    assert (
        record.artifact.user_profile_id
        == UserProfileIdentity(
            hostname=system.hostname,
            principal=root.username,
            platform="linux",
            profile_name="runtime-system",
        ).profile_id
    )
    assert not any(event.file is not None for event in _events(emitter))
    census = artifact_registry.census()
    assert census.live_versions == 1
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0
    assert census.reserved_slots == 0


def test_distinct_dependent_file_binds_same_required_root_binary_token() -> None:
    """A dependent file row proves its root binary and its own distinct content."""

    (
        generator,
        _state,
        emitter,
        user,
        system,
        timestamp,
        artifact_registry,
    ) = _artifact_fixture(enforce_binary_identity=True)
    image = r"C:\Users\alice\AppData\Local\Temp\msi_update.exe"
    path = r"C:\Windows\Temp\MSI26058.tmp"
    file_time = timestamp + timedelta(seconds=2)
    requested_effect = PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(FileEffectAction.CREATE, path),
            occurrence_times=(file_time,),
            instance_key="installer-output-file",
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=file_time + timedelta(microseconds=1),
        ),
        event_type="file_create",
        payload=PreparedFileEffectPayload(path=path, action=FileEffectAction.CREATE),
    )
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp,
        logon_id="0x12345",
        process_name=image,
        command_line="msi_update.exe /norestart",
        requested_endpoint_effects=(requested_effect,),
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        ProcessExecutionActionBundle(generator, request).execute()

    process_event = next(
        event for event in _events(emitter) if event.event_type == "process_create"
    )
    file_event = next(event for event in _events(emitter) if event.event_type == "file_create")
    assert process_event.process is not None
    assert process_event.process.binary_identity is not None
    assert file_event.process is not None
    assert file_event.process.binary_identity == process_event.process.binary_identity
    assert file_event.file is not None
    assert file_event.file.path == path
    assert file_event.file.artifact_identity is not None
    assert file_event.file.content_identity is not None
    census = artifact_registry.census()
    assert census.live_versions == 2
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0


def test_registry_lottery_reconciles_one_exact_process_owned_effect() -> None:
    generator, state, emitter, _user, system, timestamp = _fixture()
    system_user = User(
        username="SYSTEM",
        full_name="Local System",
        email="system@example.test",
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_RegistryOnlyRandom(),
    ):
        pid = generator.generate_process(
            system_user,
            system,
            timestamp,
            "0x3e7",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile",
        )

    process_identity = state.get_process_identity(system.hostname, pid)
    assert process_identity is not None
    registry_event = next(
        event for event in _events(emitter) if event.event_type == "registry_modify"
    )
    assert registry_event.registry is not None
    assert registry_event.registry.key.startswith("HKLM\\")
    assert registry_event.identity_plan is not None
    assert registry_event.identity_plan.actor_id == process_identity.object_id
    assert registry_event.identity_plan.subject is not None
    assert registry_event.identity_plan.subject.kind == "registry"
    audit = generator.execution_effect_audit_snapshot()
    assert audit.plan_count == 2
    assert audit.planned_node_count == 1
    assert audit.realized_effect_occurrence_count == 1


def test_required_near_window_contradiction_has_zero_root_mutation() -> None:
    generator, state, emitter, user, system, timestamp = _fixture()
    window_end = timestamp + timedelta(milliseconds=50)
    generator._scenario_end_time = window_end
    generator.dispatcher.output_end_time = window_end
    before_processes = tuple(state.list_running_processes())
    before_time = state.state.current_time
    before_audit = generator.execution_effect_audit_snapshot()

    with (
        patch.object(
            generator,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(ExecutionEffectPlanError, match="escapes its exact process/output"),
    ):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\near-end.exe",
            r"C:\Users\Public\near-end.exe",
            ensure_file_event=True,
        )

    assert tuple(state.list_running_processes()) == before_processes
    assert state.state.current_time == before_time
    assert _events(emitter) == []
    assert generator.execution_effect_audit_snapshot() == before_audit


def test_prepared_actor_drift_has_zero_root_mutation(monkeypatch) -> None:
    generator, state, emitter, user, system, timestamp = _fixture()
    before_processes = tuple(state.list_running_processes())
    before_time = state.state.current_time

    def drifted_plan(request, anchor: ActionAnchor) -> ProcessExecutionPreparedEffects:
        return ProcessExecutionPreparedEffects(
            root_anchor=anchor,
            actor=PreparedProcessEffectActor(
                hostname="OTHER-HOST",
                image=request.process_name,
                command_line=request.command_line,
                username=request.user.username,
                logon_id=request.logon_id,
                lifecycle_id=request.lifecycle_group_id or request.stable_id,
                started_at=request.time,
            ),
        )

    monkeypatch.setattr(generator, "_plan_process_execution_side_effects", drifted_plan)

    with pytest.raises(ExecutionEffectPlanError, match="drifted from the root execution intent"):
        generator.generate_process(
            user,
            system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\drift.exe",
            r"C:\Users\Public\drift.exe",
        )

    assert tuple(state.list_running_processes()) == before_processes
    assert state.state.current_time == before_time
    assert _events(emitter) == []


def test_session_deadline_contradiction_is_not_rewound_before_root_mutation() -> None:
    """Optional spacing beyond a session end rejects instead of inventing an earlier start."""

    generator, state, emitter, user, system, timestamp = _fixture()
    logon_id = "0xdeadline"
    state.register_session(
        logon_id=logon_id,
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip=system.ip,
        start_time=timestamp - timedelta(hours=1),
        session_kind="interactive",
    )
    state.plan_session_end(
        logon_id,
        SessionEndPlan(
            canonical_end=timestamp + timedelta(seconds=1),
            authority="explicit_storyline",
            storyline_event_id="deadline-event",
        ),
    )
    image = r"C:\Windows\System32\whoami.exe"
    command = "whoami.exe /groups"
    exe_key = (system.hostname, user.username, logon_id, "whoami.exe")
    generator._last_one_shot_cli_launch_by_exe[exe_key] = timestamp
    generator._last_one_shot_cli_launch_by_command[(*exe_key, command)] = timestamp
    before_processes = tuple(state.list_running_processes())
    before_time = state.state.current_time
    before_audit = generator.execution_effect_audit_snapshot()

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        generator.generate_process(
            user,
            system,
            timestamp,
            logon_id,
            image,
            command,
        )

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR
    assert tuple(state.list_running_processes()) == before_processes
    assert state.state.current_time == before_time
    assert _events(emitter) == []
    assert generator.execution_effect_audit_snapshot() == before_audit


def test_ssh_transport_close_precedes_session_end_and_rejects_without_root_mutation() -> None:
    """An SSH actor must honor the exact transport close before a later session end."""

    generator, state, emitter, user, system, timestamp = _fixture()
    logon_id = "0xtransport-deadline"
    state.register_session(
        logon_id=logon_id,
        username=user.username,
        system=system.hostname,
        logon_type=10,
        source_ip="10.10.1.10",
        start_time=timestamp - timedelta(hours=1),
        session_kind="ssh",
    )
    network_close_time = timestamp + timedelta(seconds=1)
    assert state.update_session_metadata(
        logon_id,
        network_close_time=network_close_time,
    )
    state.plan_session_end(
        logon_id,
        SessionEndPlan(
            canonical_end=timestamp + timedelta(minutes=10),
            authority="explicit_storyline",
            storyline_event_id="later-session-end",
        ),
    )
    image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    command = "powershell.exe -NoProfile -Command Get-Date"
    before_processes = tuple(state.list_running_processes())
    before_time = state.state.current_time
    before_lifecycle = generator._lifecycle_authority.census()
    before_audit = generator.execution_effect_audit_snapshot()

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        generator.generate_process(
            user,
            system,
            network_close_time + timedelta(seconds=1),
            logon_id,
            image,
            command,
        )

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR
    message = str(exc_info.value)
    assert f"host={system.hostname}" in message
    assert f"logon_id={logon_id}" in message
    assert f"image={image!r}" in message
    assert f"deadline={network_close_time.isoformat()}" in message
    assert tuple(state.list_running_processes()) == before_processes
    assert state.state.current_time == before_time
    assert generator._lifecycle_authority.census() == before_lifecycle
    assert _events(emitter) == []
    assert generator.execution_effect_audit_snapshot() == before_audit


def test_rdp_transport_close_does_not_end_reconnectable_logical_session() -> None:
    """RDP children may resume after disconnect while the logical session remains live."""

    generator, state, emitter, user, system, timestamp = _fixture()
    logon_id = "0xrdp-reconnectable"
    state.register_session(
        logon_id=logon_id,
        username=user.username,
        system=system.hostname,
        logon_type=10,
        source_ip="10.10.1.10",
        start_time=timestamp - timedelta(hours=1),
        session_kind="rdp",
    )
    network_close_time = timestamp + timedelta(seconds=1)
    assert state.update_session_metadata(
        logon_id,
        network_close_time=network_close_time,
    )
    logical_session_end = timestamp + timedelta(minutes=10)
    state.plan_session_end(
        logon_id,
        SessionEndPlan(
            canonical_end=logical_session_end,
            authority="explicit_storyline",
            storyline_event_id="rdp-reconnect-window",
        ),
    )
    process_time = network_close_time + timedelta(seconds=1)
    image = r"C:\Windows\System32\schtasks.exe"
    command = "schtasks.exe /Query"

    pid = generator.generate_process(
        user,
        system,
        process_time,
        logon_id,
        image,
        command,
    )

    running = state.get_process(system.hostname, pid)
    assert running is not None
    assert running.logon_id == logon_id
    assert running.start_time >= process_time
    process_event = next(
        event
        for event in _events(emitter)
        if event.event_type == "process_create"
        and event.process is not None
        and event.process.pid == pid
    )
    assert network_close_time < process_event.timestamp < logical_session_end


def test_sessionless_linux_process_effect_retains_exact_lifecycle_actor() -> None:
    generator, state, emitter, user, _system, timestamp = _fixture()
    linux = System(
        hostname="LNX-001",
        ip="10.10.1.30",
        os="Ubuntu 24.04",
        type="workstation",
    )

    with patch.object(
        generator,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = generator.generate_process(
            user,
            linux,
            timestamp,
            "",
            "/opt/tools/collector",
            "/opt/tools/collector --read /tmp/input",
            ensure_file_event=True,
        )

    process_identity = state.get_process_identity(linux.hostname, pid)
    assert process_identity is not None
    file_event = next(event for event in _events(emitter) if event.event_type == "file_create")
    assert file_event.identity_plan is not None
    assert file_event.identity_plan.actor_id == process_identity.object_id
