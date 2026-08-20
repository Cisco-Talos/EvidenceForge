# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Failure-atomic recovery for generic State materialization batches."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Thread

import pytest

import evidenceforge.generation.state_manager as state_manager_module
from evidenceforge.generation.state_manager import MaterializationBatchPlan, StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)


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


def test_generic_batch_rejects_callback_capable_plan_before_it_can_redirect_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public str subclass cannot swap the authenticated batch under the claim."""

    manager = StateManager()
    manager.set_current_time(_START)
    replacement_plan: MaterializationBatchPlan | None = None
    swaps_under_claim = 0

    class RedirectingHostname(str):
        def __repr__(self) -> str:
            nonlocal swaps_under_claim
            if (
                manager._active_prepared_state_claim is not None
                and manager._active_materialization_batch_preparations
            ):
                swaps_under_claim += 1
                record = next(iter(manager._active_materialization_batch_preparations.values()))
                assert replacement_plan is not None
                record.plan = replacement_plan
            return str.__repr__(self)

    hostile_hostname = RedirectingHostname("WS-PLAN-A")
    manager.register_hostname(hostile_hostname, "192.0.2.10")
    plan_a, logon_id_a, pid_a = _generic_batch(manager, system="WS-PLAN-A")
    plan_b, logon_id_b, pid_b = _generic_batch(manager, system="WS-PLAN-B")
    replacement_plan = plan_b
    original_validate = manager.validate_materialization_batch

    def validate_then_render_registered_hostname(candidate: MaterializationBatchPlan) -> None:
        original_validate(candidate)
        repr(hostile_hostname)

    monkeypatch.setattr(
        manager,
        "validate_materialization_batch",
        validate_then_render_registered_hostname,
    )
    version = manager.materialization_version
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="callback-capable"):
        with manager.prepared_materialization_batch(plan_a) as preparation:
            preparation.apply_provisional()

    disjoint_residue = (
        manager.get_session(logon_id_b),
        manager.get_process("WS-PLAN-B", pid_b),
        manager.get_boot_time("WS-PLAN-B"),
    )
    assert disjoint_residue == (None, None, None)
    assert manager.materialization_version == version
    assert manager.pid_allocator_census() == allocator_census
    assert manager.get_state_summary() == state_summary
    assert manager.get_session(logon_id_a) is None
    assert manager.get_process("WS-PLAN-A", pid_a) is None
    assert manager.get_boot_time("WS-PLAN-A") is None
    assert swaps_under_claim == 0
    assert manager._active_materialization_batch_preparations == {}
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


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


def test_generic_batch_commit_forged_return_cannot_certify_canonical_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A call-original-then-forge commit result is rejected before exposure."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_commit = manager._commit_prevalidated_materialization_batch
    commit_calls = 0

    def commit_then_forge(*args: object, **kwargs: object) -> object:
        nonlocal commit_calls
        commit_calls += 1
        original_commit(*args, **kwargs)  # type: ignore[arg-type]
        return None, ()

    monkeypatch.setattr(
        manager,
        "_commit_prevalidated_materialization_batch",
        commit_then_forge,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="canonical result"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()
            preparation.finalize_no_fail()

    assert commit_calls == 1
    assert not preparation.committed
    assert preparation._result is None
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("tamper", ("session", "boot-time"))
def test_generic_batch_commit_callback_cannot_forge_canonical_postimage(
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    """The dynamic commit seam must match the trusted plan-derived postimage."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_commit = manager._commit_prevalidated_materialization_batch

    def commit_then_tamper(*args: object, **kwargs: object) -> object:
        result = original_commit(*args, **kwargs)  # type: ignore[arg-type]
        if tamper == "session":
            assert result[0] is not None
            result[0].username = "forged-principal"
        else:
            manager._system_boot_times["WS-RECOVERY"] = _START - timedelta(days=30)
        return result

    monkeypatch.setattr(
        manager,
        "_commit_prevalidated_materialization_batch",
        commit_then_tamper,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="canonical postimage"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()
            preparation.finalize_no_fail()

    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("validation_mode", ("return", "original-then-raise"))
def test_generic_batch_validation_callback_runs_after_admission_fence(
    monkeypatch: pytest.MonkeyPatch,
    validation_mode: str,
) -> None:
    """Dynamic plan validation cannot publish unrelated State before the claim."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_validate = manager.validate_materialization_batch
    blocked_mutations = 0
    unrelated_logon_ids: list[str] = []

    def mutate_then_validate(candidate: MaterializationBatchPlan) -> None:
        nonlocal blocked_mutations
        try:
            unrelated_logon_ids.append(
                manager.create_session(
                    username="preclaim-unrelated",
                    system="WS-PRECLAIM",
                    logon_type=2,
                    source_ip="127.0.0.3",
                    start_time=_START,
                )
            )
        except StateError as error:
            assert "State mutation create_session is unavailable" in str(error)
            blocked_mutations += 1
        if validation_mode == "return":
            return
        original_validate(candidate)
        raise RuntimeError("injected validation callback lost return")

    monkeypatch.setattr(manager, "validate_materialization_batch", mutate_then_validate)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    if validation_mode == "original-then-raise":
        with pytest.raises(
            (RuntimeError, StateError),
            match="validation callback lost return|became stale|plan is stale",
        ):
            with manager.prepared_materialization_batch(plan):
                pass
    else:
        with manager.prepared_materialization_batch(plan):
            pass

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


@pytest.mark.parametrize(
    "method_name",
    (
        "_prepare_action_cohort_session_start",
        "_prepare_action_cohort_process_start",
        "_prepare_action_cohort_rollback_journal",
    ),
)
@pytest.mark.parametrize("preparation_mode", ("return", "original-then-raise"))
def test_generic_batch_dynamic_preparation_callbacks_run_after_admission_fence(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    preparation_mode: str,
) -> None:
    """Every replaceable preparation seam observes the early mutation fence."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original = getattr(manager, method_name)
    attempted_mutation = False
    blocked_mutations = 0
    unrelated_logon_ids: list[str] = []

    def mutate_then_prepare(*args: object, **kwargs: object) -> object:
        nonlocal attempted_mutation, blocked_mutations
        if not attempted_mutation:
            attempted_mutation = True
            try:
                unrelated_logon_ids.append(
                    manager.create_session(
                        username="prepare-unrelated",
                        system="WS-PREPARE",
                        logon_type=2,
                        source_ip="127.0.0.4",
                        start_time=_START,
                    )
                )
            except StateError as error:
                assert "State mutation create_session is unavailable" in str(error)
                blocked_mutations += 1
        if preparation_mode == "return":
            return None
        original(*args, **kwargs)
        raise RuntimeError("injected preparation callback lost return")

    monkeypatch.setattr(manager, method_name, mutate_then_prepare)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    if preparation_mode == "original-then-raise":
        with pytest.raises(RuntimeError, match="preparation callback lost return"):
            with manager.prepared_materialization_batch(plan):
                pass
    else:
        with manager.prepared_materialization_batch(plan):
            pass

    assert attempted_mutation
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


def test_generic_batch_commit_path_invokes_no_logger_callback_under_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reversible primitive tail does not call a user-configurable log handler."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, _logon_id, _pid = _generic_batch(manager)

    def unexpected_logger_callback(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("generic batch invoked logger callback under its State claim")

    monkeypatch.setattr(state_manager_module.logger, "debug", unexpected_logger_callback)

    with manager.prepared_materialization_batch(plan) as preparation:
        result = preparation.apply_provisional()
        assert result[0] is not None
        locator = manager._active_materialization_batch_private_rollback
        assert locator is not None
        assert preparation.provisionally_applied
        assert not preparation.committed
        preparation.finalize_no_fail()
        assert manager._active_materialization_batch_private_rollback is locator
        assert preparation.committed
        assert not preparation.provisionally_applied


@pytest.mark.parametrize("patch_target", ("instance", "class"))
def test_generic_batch_private_preimage_bypasses_persistently_failing_restore_seam(
    monkeypatch: pytest.MonkeyPatch,
    patch_target: str,
) -> None:
    """Prearmed recovery uses the captured primitive even if redispatch is poisoned."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0
    restore_calls = 0

    def fail_postcommit_observation(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations == 2:
            raise RuntimeError("injected postcommit observation failure")
        return original_observation(journal)  # type: ignore[arg-type]

    def persistently_fail_restore(_journal: object) -> None:
        nonlocal restore_calls
        restore_calls += 1
        raise RuntimeError("injected persistent private restore failure")

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        fail_postcommit_observation,
    )
    if patch_target == "instance":
        monkeypatch.setattr(
            manager,
            "_restore_action_cohort_rollback_journal",
            persistently_fail_restore,
        )
    else:
        monkeypatch.setattr(
            StateManager,
            "_restore_action_cohort_rollback_journal",
            persistently_fail_restore,
        )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match="injected postcommit observation failure"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations == 2
    assert restore_calls == 0
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize(
    "tamper",
    ("claim_epoch", "claim_thread", "certified", "result", "plan", "journal", "lane"),
)
def test_generic_batch_private_preimage_ignores_postcommit_record_tamper(
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    """Callback-visible record and observation metadata cannot revoke rollback."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def tamper_then_raise(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations != 2:
            return original_observation(journal)  # type: ignore[arg-type]
        original_observation(journal)  # type: ignore[arg-type]
        record = next(iter(manager._active_materialization_batch_preparations.values()))
        if tamper == "claim_epoch":
            record.claim_epoch += 1
        elif tamper == "claim_thread":
            record.claim_thread = Thread()
        elif tamper == "certified":
            record.certified = True
        elif tamper == "result":
            record.result = (None, ())
        elif tamper == "plan":
            record.plan = replace(record.plan, _integrity_token="tampered")
        elif tamper == "journal":
            object.__setattr__(journal, "materialization_version", -1)
        else:
            manager._active_materialization_batch_private_rollback = None
            manager._active_prepared_state_claim = None
            manager._active_materialization_batch_preparations.clear()
            manager._prepared_state_admission_epoch += 1
        raise RuntimeError(f"injected {tamper} postcommit tamper")

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        tamper_then_raise,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match=f"injected {tamper} postcommit tamper"):
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


def test_generic_batch_returning_observer_cannot_silently_tamper_control_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A returned postimage is not trusted until callback-visible controls authenticate."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def tamper_then_return(journal: object) -> object:
        nonlocal observations
        observations += 1
        postimage = original_observation(journal)  # type: ignore[arg-type]
        if observations == 2:
            record = next(iter(manager._active_materialization_batch_preparations.values()))
            record.claim_epoch += 1
        return postimage

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        tamper_then_return,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="control state drifted after apply"):
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


@pytest.mark.parametrize("commit_mode", ("normal", "lost-return"))
def test_generic_batch_precommit_observer_cannot_swap_the_committed_plan(
    monkeypatch: pytest.MonkeyPatch,
    commit_mode: str,
) -> None:
    """The private authority, not a callback-visible record, owns the commit input."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan_a, logon_id_a, pid_a = _generic_batch(manager, system="WS-A")
    plan_b, logon_id_b, pid_b = _generic_batch(manager, system="WS-B")
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    original_commit = manager._commit_prevalidated_materialization_batch
    observations = 0
    commit_calls = 0

    def swap_plan_then_return(journal: object) -> object:
        nonlocal observations
        observations += 1
        preimage = original_observation(journal)  # type: ignore[arg-type]
        if observations == 1:
            record = next(iter(manager._active_materialization_batch_preparations.values()))
            record.plan = plan_b
        return preimage

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        swap_plan_then_return,
    )
    if commit_mode == "lost-return":

        def commit_then_raise(*args: object, **kwargs: object) -> object:
            nonlocal commit_calls
            commit_calls += 1
            original_commit(*args, **kwargs)  # type: ignore[arg-type]
            raise RuntimeError("injected swapped-plan commit lost return")

        monkeypatch.setattr(
            manager,
            "_commit_prevalidated_materialization_batch",
            commit_then_raise,
        )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(StateError, match="control state drifted"):
        with manager.prepared_materialization_batch(plan_a) as preparation:
            preparation.apply_provisional()

    assert observations == 1
    assert commit_calls == 0
    assert manager.materialization_digest() == digest
    assert manager.pid_allocator_census() == allocator_census
    assert manager.get_state_summary() == state_summary
    assert manager.get_session(logon_id_a) is None
    assert manager.get_process("WS-A", pid_a) is None
    assert manager.get_boot_time("WS-A") is None
    assert manager.get_session(logon_id_b) is None
    assert manager.get_process("WS-B", pid_b) is None
    assert manager.get_boot_time("WS-B") is None
    assert manager._active_materialization_batch_preparations == {}
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


def test_generic_batch_private_restore_cannot_be_replaced_by_instance_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An instance rollback seam cannot replace registry-captured private restore."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0
    restore_attempts = 0

    def fail_postcommit_observation(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations == 2:
            raise RuntimeError("injected postcommit observation failure")
        return original_observation(journal)  # type: ignore[arg-type]

    def fail_trusted_restore(_manager: object, _journal: object) -> None:
        nonlocal restore_attempts
        restore_attempts += 1
        raise RuntimeError("injected catastrophic trusted restore failure")

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        fail_postcommit_observation,
    )
    monkeypatch.setattr(
        manager,
        "_materialization_batch_rollback_primitives",
        lambda: (StateManager._action_cohort_rollback_observation, fail_trusted_restore),
        raising=False,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match="postcommit observation failure"):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()

    assert observations == 2
    assert restore_attempts == 0
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_postcommit_callback_cannot_replace_private_rollback_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery primitives captured before callbacks cannot be rebound after commit."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    observations = 0

    def replace_primitives_then_raise(journal: object) -> object:
        nonlocal observations
        observations += 1
        if observations != 2:
            return original_observation(journal)  # type: ignore[arg-type]
        authority = manager._active_materialization_batch_private_rollback
        assert authority is not None
        monkeypatch.setattr(
            state_manager_module,
            "_TRUSTED_MATERIALIZATION_BATCH_ROLLBACK_RESTORE",
            lambda _manager, _journal: None,
            raising=False,
        )
        monkeypatch.setattr(
            state_manager_module,
            "_TRUSTED_MATERIALIZATION_BATCH_ROLLBACK_OBSERVATION",
            lambda _manager, _journal: (),
            raising=False,
        )
        raise RuntimeError("injected rollback primitive replacement")

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        replace_primitives_then_raise,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(RuntimeError, match="rollback primitive replacement"):
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


def test_generic_batch_postcommit_callback_cannot_forge_finalization_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only finalize_no_fail may create private finalization authority."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    original_observation: Callable[[object], object] = manager._action_cohort_rollback_observation
    original_replace = state_manager_module.replace
    observations = 0

    def forge_finalized_replace(instance: object, **changes: object) -> object:
        updated = original_replace(instance, **changes)
        if changes.get("result_exposed") is True:
            return original_replace(updated, finalized=True)
        return updated

    def replace_phase_constructor(journal: object) -> object:
        nonlocal observations
        observations += 1
        postimage = original_observation(journal)  # type: ignore[arg-type]
        if observations == 2:
            monkeypatch.setattr(state_manager_module, "replace", forge_finalized_replace)
        return postimage

    monkeypatch.setattr(
        manager,
        "_action_cohort_rollback_observation",
        replace_phase_constructor,
    )
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with manager.prepared_materialization_batch(plan) as preparation:
        preparation.apply_provisional()

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("mutation", ("object-setattr", "replace", "replace-identical"))
@pytest.mark.parametrize("forgery", ("finalized", "phase-cleared"))
def test_generic_batch_exposed_authority_phase_forgery_cannot_escape_state(
    mutation: str,
    forgery: str,
) -> None:
    """Caller-reachable authority flags are never trusted as terminal phase truth."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with manager.prepared_materialization_batch(plan) as preparation:
        preparation.apply_provisional()
        authority = manager._active_materialization_batch_private_rollback
        assert authority is not None
        changes = (
            {"claim_epoch": authority.claim_epoch + 1}
            if forgery == "finalized"
            else {"_integrity_token": "forged-cleared-phase"}
        )
        if mutation == "object-setattr":
            for name, value in changes.items():
                object.__setattr__(authority, name, value)
        elif mutation == "replace":
            manager._active_materialization_batch_private_rollback = replace(
                authority,
                **changes,
            )
        else:
            manager._active_materialization_batch_private_rollback = replace(authority)

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("mutation", ("object-setattr", "replace", "replace-identical"))
def test_generic_batch_finalized_phase_forgery_cannot_rollback_terminal_state(
    mutation: str,
) -> None:
    """Closure-held finalization truth survives later locator replacement."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()

    with manager.prepared_materialization_batch(plan) as preparation:
        result = preparation.apply_provisional()
        preparation.finalize_no_fail()
        authority = manager._active_materialization_batch_private_rollback
        assert authority is not None
        if mutation == "object-setattr":
            object.__setattr__(
                authority,
                "_integrity_token",
                "forged-cleared-finalized-phase",
            )
        elif mutation == "replace":
            manager._active_materialization_batch_private_rollback = replace(
                authority,
                _integrity_token="forged-cleared-finalized-phase",
            )
        else:
            manager._active_materialization_batch_private_rollback = replace(authority)

    assert preparation.committed
    assert preparation._result is result
    assert manager.get_session(logon_id) is result[0]
    assert manager.get_process("WS-RECOVERY", pid) is result[1][0]
    assert manager.get_boot_time("WS-RECOVERY") == _START - timedelta(hours=2)
    assert manager.materialization_digest() != digest
    assert manager.pid_allocator_census() != allocator_census
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


def test_generic_batch_exposed_rollback_graph_replacement_cannot_escape_state() -> None:
    """Cleanup owns its original journal even if a matching no-op graph is published."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with manager.prepared_materialization_batch(plan) as preparation:
        preparation.apply_provisional()
        authority = manager._active_materialization_batch_private_rollback
        assert authority is not None
        forged_noop_graph = object()
        assert not hasattr(authority, "rollback_journal")
        assert not hasattr(authority, "rollback_preimage")
        manager._active_materialization_batch_private_rollback = replace(
            authority,
            authority_identity=id(forged_noop_graph),
            _integrity_token="forged-noop-rollback-graph",
        )

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize(
    "tamper",
    (
        "clear_provisional",
        "forge_committed",
        "foreign_preparation_locator",
        "public_journal",
    ),
)
def test_generic_batch_result_phase_rollback_ignores_public_record_flags(
    tamper: str,
) -> None:
    """Only manager-private finalization authority may terminalize exposed State."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with manager.prepared_materialization_batch(plan) as preparation:
        preparation.apply_provisional()
        record = manager._active_materialization_batch_preparations[id(preparation)]
        locator = manager._active_materialization_batch_private_rollback
        assert locator is not None
        assert locator.preparation_locator == id(preparation)
        assert not hasattr(locator, "rollback_journal")
        if tamper == "clear_provisional":
            record.provisional = False
            assert preparation.provisionally_applied
        elif tamper == "forge_committed":
            record.committed = True
            preparation._committed = True
            assert not preparation.committed
        elif tamper == "foreign_preparation_locator":
            manager._active_materialization_batch_preparations[-1] = record
        else:
            object.__setattr__(record.rollback_journal, "materialization_version", -1)

    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_private_rollback_graph_remains_unreachable_after_result_exposure() -> None:
    """The exposed locator never carries the closure-owned rollback graph."""

    class LaterOwnerAbort(BaseException):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(LaterOwnerAbort):
        with manager.prepared_materialization_batch(plan) as preparation:
            preparation.apply_provisional()
            locator = manager._active_materialization_batch_private_rollback
            assert locator is not None
            assert not hasattr(locator, "rollback_journal")
            assert not hasattr(locator, "rollback_preimage")
            assert not hasattr(locator, "rollback_restore")
            raise LaterOwnerAbort()

    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize("tamper", ("phase", "phase-and-seal"))
def test_generic_batch_writable_closure_phase_cannot_forge_finalization(tamper: str) -> None:
    """No caller-writable capability cell can bypass later-owner rollback."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            preparation.apply_provisional()
            forbidden_names = ("phase",) if tamper == "phase" else ("phase", "phase_seal")
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=forbidden_names,
            )
            raise LaterOwnerError("later owner failed")

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_writable_closure_verifier_cannot_forge_finalization() -> None:
    """No public closure exposes finalization receipt truth or its verifier."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            preparation.apply_provisional()
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=(
                    "finalization_receipt",
                    "finalization_receipt_authenticates",
                ),
            )
            raise LaterOwnerError("later owner failed")

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_public_finalize_closure_cannot_mint_terminal_receipt() -> None:
    """No public capability surface may expose the private finalization signer."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    context = manager.prepared_materialization_batch(plan)
    with context as preparation:
        preparation.apply_provisional()
        _assert_private_batch_carrier_unreachable(
            context,
            preparation,
            forbidden_names=(
                "seal_finalization_receipt",
                "finalization_receipt",
                "trusted_authority",
                "rollback_preimage_digest",
                "certified_result_digest",
                "certified_postimage_digest",
            ),
        )

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_context_exposes_no_cleanup_generator_frame() -> None:
    """The returned context cannot expose or rewrite its exact cleanup authority."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()
    context = manager.prepared_materialization_batch(plan)

    with context as preparation:
        preparation.apply_provisional()
        _assert_private_batch_carrier_unreachable(context, preparation)
        assert not hasattr(context, "gi_frame")

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_writable_closure_journal_forgery_cannot_defeat_rollback() -> None:
    """No public callable exposes the closure-owned exact cleanup graph."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            preparation.apply_provisional()
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=(
                    "trusted_authority",
                    "cleanup_authority",
                    "rollback_journal",
                    "rollback_preimage",
                    "rollback_restore",
                ),
            )
            raise LaterOwnerError("later owner failed")

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


def test_generic_batch_cleanup_carrier_is_absent_from_public_callable_surfaces() -> None:
    """Public batch callables expose no cleanup closure, default, or global."""

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()
    context = manager.prepared_materialization_batch(plan)

    with context as preparation:
        preparation.apply_provisional()
        _assert_private_batch_carrier_unreachable(
            context,
            preparation,
            forbidden_names=(
                "cleanup_authority",
                "cleanup_authority_secret",
                "cleanup_hmac_new",
                "cleanup_manager",
                "cleanup_rollback_journal",
                "cleanup_rollback_preimage",
                "owners_by_context",
                "owners_by_preparation",
                "seal_finalization_receipt",
                "finalization_receipt",
            ),
        )

    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize(
    "cell_name",
    (
        "self",
        "record",
        "claim_epoch",
        "locator",
        "trusted_authority",
        "trusted_locator",
    ),
)
def test_generic_batch_recursive_public_closure_cell_forgery_cannot_defeat_cleanup(
    cell_name: str,
) -> None:
    """Former control cells are absent after provisional apply and cleanup is exact."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()
    state_summary = manager.get_state_summary()

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            preparation.apply_provisional()
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=(cell_name,),
            )
            raise LaterOwnerError("later owner failed")

    assert not preparation.committed
    _assert_exact_preimage(
        manager,
        digest=digest,
        allocator_census=allocator_census,
        state_summary=state_summary,
        logon_id=logon_id,
        pid=pid,
    )


@pytest.mark.parametrize(
    "cell_name",
    (
        "self",
        "record",
        "claim_epoch",
        "locator",
        "trusted_authority",
        "trusted_locator",
    ),
)
def test_generic_batch_recursive_closure_forgery_cannot_clear_finalized_receipt(
    cell_name: str,
) -> None:
    """Former control cells are absent and actual finalize remains terminal."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            result = preparation.apply_provisional()
            preparation.finalize_no_fail()
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=(cell_name,),
            )
            raise LaterOwnerError("later owner failed")

    assert preparation.committed
    assert preparation._result is result
    assert manager.get_session(logon_id) is result[0]
    assert manager.get_process("WS-RECOVERY", pid) is result[1][0]
    assert manager.get_boot_time("WS-RECOVERY") == _START - timedelta(hours=2)
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


@pytest.mark.parametrize("tamper", ("phase", "phase-and-seal"))
def test_generic_batch_writable_closure_phase_cannot_clear_actual_finalization(
    tamper: str,
) -> None:
    """A separate authenticated finalize receipt survives closure phase drift."""

    class LaterOwnerError(RuntimeError):
        pass

    manager = StateManager()
    manager.set_current_time(_START)
    plan, logon_id, pid = _generic_batch(manager)

    with pytest.raises(LaterOwnerError, match="later owner failed"):
        context = manager.prepared_materialization_batch(plan)
        with context as preparation:
            result = preparation.apply_provisional()
            preparation.finalize_no_fail()
            forbidden_names = ("phase",) if tamper == "phase" else ("phase", "phase_seal")
            _assert_private_batch_carrier_unreachable(
                context,
                preparation,
                forbidden_names=forbidden_names,
            )
            raise LaterOwnerError("later owner failed")

    assert preparation.committed
    assert preparation._result is result
    assert manager.get_session(logon_id) is result[0]
    assert manager.get_process("WS-RECOVERY", pid) is result[1][0]
    assert manager.get_boot_time("WS-RECOVERY") == _START - timedelta(hours=2)
    assert manager._active_materialization_batch_private_rollback is None
    assert manager._active_prepared_state_claim is None


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
