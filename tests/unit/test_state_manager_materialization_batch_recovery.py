# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Failure-atomic recovery for generic State materialization batches."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.state_manager import MaterializationBatchPlan, StateManager
from evidenceforge.models import Scenario
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)


def _minimal_boot_scenario(operating_system: str) -> Scenario:
    """Build the smallest real engine scenario that enters fleet boot materialization."""

    return Scenario.model_validate(
        {
            "version": "1.0",
            "name": "generic-batch-real-initialize",
            "description": "One-host production initialization regression",
            "environment": {
                "description": "One boot host",
                "users": [
                    {
                        "username": "analyst",
                        "full_name": "Analyst",
                        "email": "analyst@example.test",
                        "primary_system": "BOOT-HOST",
                        "enabled": True,
                    }
                ],
                "systems": [
                    {
                        "hostname": "BOOT-HOST",
                        "ip": "192.0.2.10",
                        "os": operating_system,
                        "type": "server",
                    }
                ],
            },
            "time_window": {"start": "2024-01-15T10:00:00Z", "duration": "1h"},
            "baseline_activity": {
                "description": "Minimal baseline",
                "intensity": "low",
                "variation": "low",
            },
            "output": {"logs": [], "destination": "./output", "compression": False},
        }
    )


@pytest.mark.parametrize(
    ("operating_system", "root_alias", "root_pid"),
    (
        ("Windows 11", "system", 4),
        ("Ubuntu 22.04", "systemd", 1),
    ),
)
def test_real_initialize_boot_batch_matches_detached_trial(
    tmp_path: Path,
    operating_system: str,
    root_alias: str,
    root_pid: int,
) -> None:
    """Production Windows and Linux boot batches must match their trial postimages."""

    engine = GenerationEngine(_minimal_boot_scenario(operating_system), tmp_path)

    engine._initialize()

    assert engine._system_pids["BOOT-HOST"][root_alias] == root_pid
    assert engine.state_manager.get_process("BOOT-HOST", root_pid) is not None
    transaction_census = engine.lifecycle_authority.census()
    assert transaction_census.materialization_batch_transactions_pending == 0
    assert transaction_census.materialization_batch_transactions_unacknowledged == 0
    assert transaction_census.materialization_batch_transactions_acknowledged == 1
    assert engine.state_manager._active_materialization_batch_preparations == {}
    assert engine.state_manager._active_materialization_batch_private_rollback is None
    assert engine.state_manager._active_prepared_state_claim is None
    if root_alias == "systemd":
        allocations = engine.state_manager._linux_pid_allocations["BOOT-HOST"]
        allocation_records = tuple(
            (event_time, logical_position)
            for block in allocations._blocks
            for event_time, _sequence, logical_position in block
        )
        assert len(allocation_records) == len(set(allocation_records))


def test_failed_real_initialize_clears_generic_batch_provisional_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost primitive return during real boot leaves no State batch authority active."""

    engine = GenerationEngine(_minimal_boot_scenario("Ubuntu 22.04"), tmp_path)
    manager = engine.state_manager
    original_commit = manager._commit_prevalidated_materialization_batch

    def commit_then_raise(*args: object, **kwargs: object) -> object:
        original_commit(*args, **kwargs)  # type: ignore[arg-type]
        raise StateError("injected real initialize batch failure")

    monkeypatch.setattr(
        manager,
        "_commit_prevalidated_materialization_batch",
        commit_then_raise,
    )

    with pytest.raises(StateError, match="injected real initialize batch failure"):
        engine._initialize()

    assert manager.materialization_version == 0
    assert manager.list_running_processes() == []
    assert manager.get_boot_time("BOOT-HOST") is None
    assert manager._active_materialization_batch_preparations == {}
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None
    assert engine.lifecycle_registry.stats().live_processes == 0


def _generic_batch(
    manager: StateManager,
    *,
    system: str = "WS-RECOVERY",
) -> tuple[MaterializationBatchPlan, str, int]:
    """Build one allocation-rich generic session/process/boot transaction."""

    builder = manager.begin_materialization_batch()
    session = builder.plan_session(
        username="analyst",
        system=system,
        logon_type=2,
        source_ip="127.0.0.1",
        start_time=_START + timedelta(seconds=1),
        session_kind="interactive",
    )
    process = builder.plan_process(
        system=system,
        parent_pid=4,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=2),
        require_session=True,
        session_plan=session,
    )
    builder.bind_session_processes(
        session,
        shell_plan=process,
        process_tree_root_plan=process,
    )
    builder.plan_boot_time(system, _START - timedelta(hours=2))
    return builder.seal(), session.identity.logon_id, process.identity.pid


def _assert_exact_preimage(
    manager: StateManager,
    *,
    digest: str,
    allocator_census: dict[str, int],
    state_summary: dict[str, object],
    logon_id: str,
    pid: int,
) -> None:
    """Require complete canonical, allocator, index, and claim cleanup."""

    assert manager.materialization_digest() == digest
    assert manager.pid_allocator_census() == allocator_census
    assert manager.get_state_summary() == state_summary
    assert manager.get_session(logon_id) is None
    assert manager.get_process("WS-RECOVERY", pid) is None
    assert manager.get_boot_time("WS-RECOVERY") is None
    assert manager._active_materialization_batch_preparations == {}
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


def _public_batch_callables(
    context: object,
    preparation: object,
) -> tuple[Callable[..., object], ...]:
    """Return every Python callable exposed by the generic-batch public objects."""

    context_type = type(context)
    preparation_type = type(preparation)
    return (
        StateManager.prepared_materialization_batch,
        context_type.__enter__,
        context_type.__exit__,
        context_type.__copy__,
        preparation_type._owner_manager,
        preparation_type._owner_context,
        preparation_type.__copy__,
        preparation_type.committed.fget,
        preparation_type.provisionally_applied.fget,
        preparation_type.apply_provisional,
        preparation_type.finalize_no_fail,
        preparation_type.commit_no_fail,
        preparation_type.commit,
    )


def _recursive_callable_surfaces(
    roots: tuple[Callable[..., object], ...],
) -> tuple[tuple[str, object], ...]:
    """Return closure/default/global values recursively reachable from callables."""

    pending: list[Callable[..., object]] = list(roots)
    seen: set[int] = set()
    surfaces: list[tuple[str, object]] = []
    while pending:
        candidate = pending.pop()
        function = getattr(candidate, "__func__", candidate)
        if id(function) in seen or not hasattr(function, "__code__"):
            continue
        seen.add(id(function))
        code = function.__code__
        for name, cell in zip(
            code.co_freevars,
            function.__closure__ or (),
            strict=True,
        ):
            value = cell.cell_contents
            surfaces.append((name, value))
            if callable(value) and hasattr(getattr(value, "__func__", value), "__code__"):
                pending.append(value)
        for index, value in enumerate(function.__defaults__ or ()):
            surfaces.append((f"<default:{index}>", value))
            if callable(value) and hasattr(getattr(value, "__func__", value), "__code__"):
                pending.append(value)
        for name, value in (function.__kwdefaults__ or {}).items():
            surfaces.append((f"<kwdefault:{name}>", value))
            if callable(value) and hasattr(getattr(value, "__func__", value), "__code__"):
                pending.append(value)
        for name in code.co_names:
            if name not in function.__globals__:
                continue
            value = function.__globals__[name]
            surfaces.append((f"<global:{name}>", value))
            if callable(value) and hasattr(getattr(value, "__func__", value), "__code__"):
                pending.append(value)
    return tuple(surfaces)


def _assert_private_batch_carrier_unreachable(
    context: object,
    preparation: object,
    *,
    forbidden_names: tuple[str, ...] = (),
) -> None:
    """Prove public objects expose no cleanup owner, graph, signer, or phase cell."""

    callables = _public_batch_callables(context, preparation)
    for candidate in callables:
        function = getattr(candidate, "__func__", candidate)
        assert function.__closure__ is None
        assert function.__defaults__ in (None, ())
        assert function.__kwdefaults__ in (None, {})

    surfaces = _recursive_callable_surfaces(callables)
    surface_names = {name for name, _value in surfaces}
    for forbidden_name in forbidden_names:
        assert forbidden_name not in surface_names

    forbidden_fragments = (
        "PrivateOwner",
        "PrivateRollbackAuthority",
        "RollbackJournal",
    )
    for _name, value in surfaces:
        assert not any(fragment in type(value).__name__ for fragment in forbidden_fragments)
        assert not isinstance(value, bytes)

    assert not hasattr(context, "gen")
    assert not hasattr(context, "__dict__")
    assert not hasattr(preparation, "__dict__")
    for legacy_capability in (
        "_apply_provisional_capability",
        "_finalize_no_fail_capability",
        "_committed_probe",
        "_provisional_probe",
    ):
        assert not hasattr(preparation, legacy_capability)

    for value in (*tuple(context), *tuple(preparation)):
        assert not any(fragment in type(value).__name__ for fragment in forbidden_fragments)
        assert not isinstance(value, bytes)


@pytest.mark.parametrize("observer_mode", ("fail-before", "call-original-then-raise"))
def test_generic_batch_postcommit_observation_failure_restores_exact_preimage(
    monkeypatch: pytest.MonkeyPatch,
    observer_mode: str,
) -> None:
    """No provisional State may escape when postimage certification itself fails."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def fail_postcommit_observation(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations == 2:
            if observer_mode == "call-original-then-raise":
                original_observation(journal)  # type: ignore[arg-type]
            raise RuntimeError(f"injected {observer_mode} postimage observation")
        return original_observation(journal)  # type: ignore[arg-type]

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        fail_postcommit_observation,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match="injected .* postimage observation"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations == 2
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("observer_mode", ("return", "call-original-then-raise"))
def test_generic_batch_first_replaceable_observer_runs_after_claim_fence(
    monkeypatch: pytest.MonkeyPatch,
    observer_mode: str,
) -> None:
    """A replaceable observer cannot publish unrelated State before batch exclusion."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0
    blocked_mutations = 0
    unrelated_logon_ids: list[str] = []

    def mutate_then_observe(journal: object) -> object:
        nonlocal blocked_mutations, observations
        observations += 1
        if observations != 1:
            return original_observation(journal)  # type: ignore[arg-type]
        try:
            unrelated_logon_ids.append(
                manager.create_session(
                    username="unrelated",
                    system="WS-UNRELATED",
                    logon_type=2,
                    source_ip="127.0.0.2",
                    start_time=_START,
                )
            )
        except StateError as error:
            assert "State mutation create_session is unavailable" in str(error)
            blocked_mutations += 1
        observation = original_observation(journal)  # type: ignore[arg-type]
        if observer_mode == "call-original-then-raise":
            raise RuntimeError("injected first-observer lost return")
        return observation

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        mutate_then_observe,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    if observer_mode == "call-original-then-raise":
        with pytest.raises(RuntimeError, match="first-observer lost return"):
            with manager.prepared_materialization_batch(plan) as preparation:
                preparation.apply_provisional()
    else:
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations >= 1
    assert blocked_mutations == 1
    assert unrelated_logon_ids == []
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_commit_lost_return_restores_exact_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A commit call-original-then-raise is rolled back without publishing its result."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    plan_b, logon_id_b, pid_b = _generic_batch(manager, system="WS-LOST-RETURN")
    original_commit = manager._commit_prevalidated_materialization_batch

    def commit_then_raise(*args: object, **kwargs: object) -> object:
        locator = manager._active_materialization_batch_private_rollback
        assert locator is not None
        record = next(iter(manager._active_materialization_batch_preparations.values()))
        assert record.provisional
        assert not hasattr(locator, "rollback_journal")
        record.plan = plan_b
        original_commit(*args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("injected generic batch commit lost return")

    monkeypatch.setattr(
        manager,
        "_commit_prevalidated_materialization_batch",
        commit_then_raise,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match="generic batch commit lost return"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )
    assert manager.get_session(logon_id_b) is None
    assert manager.get_process("WS-LOST-RETURN", pid_b) is None
    assert manager.get_boot_time("WS-LOST-RETURN") is None


def test_generic_batch_silent_postimage_failure_restores_exact_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing postimage value takes the same private-preimage recovery path."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def omit_postcommit_observation(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations == 2:
            return None
        return original_observation(journal)  # type: ignore[arg-type]

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        omit_postcommit_observation,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="has no rollback postimage"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations == 2
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("commit_mode", ("complete", "partial"))
def test_generic_batch_lost_return_survives_postimage_observer_failure(
    monkeypatch: pytest.MonkeyPatch,
    commit_mode: str,
) -> None:
    """A second internal fault cannot expose full or partial provisional writes."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def fail_postcommit_observation(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations == 2:
            original_observation(journal)  # type: ignore[arg-type]
            raise RuntimeError("injected observer failure after lost return")
        return original_observation(journal)  # type: ignore[arg-type]

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        fail_postcommit_observation,
    )
    if commit_mode == "complete":
        original_commit = manager._commit_prevalidated_materialization_batch

        def commit_then_raise(*args: object, **kwargs: object) -> object:
            original_commit(*args, **kwargs)  # type: ignore[arg-type]
            raise RuntimeError("injected complete generic batch lost return")

        monkeypatch.setattr(
            manager,
            "_commit_prevalidated_materialization_batch",
            commit_then_raise,
        )
    else:
        original_session_commit = manager._commit_prevalidated_session_materialization

        def commit_session_then_raise(
            callback_plan: MaterializationBatchPlan,
            **_kwargs: object,
        ) -> object:
            assert callback_plan.session is not None
            original_session_commit(
                callback_plan.session,
                advance_version=False,
                update_state_time=False,
                emit_log=False,
            )
            raise RuntimeError("injected partial generic batch lost return")

        monkeypatch.setattr(
            manager,
            "_commit_prevalidated_materialization_batch",
            commit_session_then_raise,
        )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match=f"injected {commit_mode} generic batch lost return"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations == 2
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )
