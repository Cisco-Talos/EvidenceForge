# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The denominator comes from canonical State, including source-bypassing births."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_es_ingress import MacosESIngress
from evidenceforge.generation.macos_process_census import MacosOccurrenceDigest, MacosProcessCensus
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_source_integration import _routed
from tests.unit.test_process_execution_state import _START, _execute, _process


def test_preexisting_lifetime_reexecs_count_independently_and_survive_checkpoint() -> None:
    state, before = _process()
    start = _START + timedelta(seconds=1)
    state.configure_macos_process_census(before.hostname, start, start + timedelta(minutes=1))
    first = _execute(state, before)
    second = _execute(state, first, seconds=2)
    census = dict(state.macos_process_census_snapshot())[before.hostname]
    assert census.forks.count == census.aggregate_births == 0
    assert census.execs == MacosOccurrenceDigest().add(
        before.hostname, f"process-exec:{first.execution_id}"
    ).add(before.hostname, f"process-exec:{second.execution_id}")
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.macos_process_census_snapshot() == state.macos_process_census_snapshot()
    assert _execute(restored, second, seconds=3) == _execute(state, second, seconds=3)
    assert restored.macos_process_census_snapshot() == state.macos_process_census_snapshot()


def test_aggregate_registration_without_source_publication_cannot_escape_census() -> None:
    state, before = _process()
    state.configure_macos_process_census(before.hostname, _START, _START + timedelta(minutes=1))
    for index in range(12):
        plan = state.plan_process_materialization(
            system=before.hostname,
            parent_pid=before.pid,
            image="/usr/bin/id",
            command_line="id",
            username="alex",
            integrity_level="Medium",
            os_category="macos",
            start_time=_START + timedelta(seconds=index + 1),
        )
        state.materialize_process(plan)
    census = dict(state.macos_process_census_snapshot())[before.hostname]
    assert census.execs.count == census.aggregate_births == 12
    assert len(census.aggregate_samples) == 8
    assert census.forks.count == 0


def test_provisional_exec_rollback_and_retry_do_not_double_count() -> None:
    state, before = _process()
    state.configure_macos_process_census(before.hostname, _START, _START + timedelta(minutes=1))
    prior = state.macos_process_census_snapshot()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        before, image="/usr/bin/id", command_line="id", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    assert state.macos_process_census_snapshot() == prior
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert dict(state.macos_process_census_snapshot())[before.hostname].execs.count == 1
    assert state.macos_process_census_snapshot() == prior
    state.materialize_action_cohort(plan)
    assert dict(state.macos_process_census_snapshot())[before.hostname].execs.count == 1


def test_census_is_half_open_and_pid_reuse_is_not_identity_reuse() -> None:
    _, identity = _process()
    census = MacosProcessCensus(_START, _START + timedelta(seconds=2))
    assert (
        census.birth(replace(identity, started_at=_START - timedelta(seconds=1)), forked=False)
        == census
    )
    assert census.birth(replace(identity, started_at=census.end), forked=True) == census
    first = census.birth(identity, forked=False)
    reused = replace(
        identity,
        object_id="new-lifetime-same-pid",
        primary_thread=None,
        started_at=_START + timedelta(seconds=1),
    )
    second = first.birth(reused, forked=False)
    assert second.execs.count == second.aggregate_births == 2
    assert second.execs != first.execs.add(
        identity.hostname, f"process-exec:{identity.execution_id}"
    )
    assert MacosOccurrenceDigest().add("a", "x").add("a", "y") == MacosOccurrenceDigest().add(
        "a", "y"
    ).add("a", "x")


def test_legacy_checkpoint_cannot_invent_a_complete_census_history() -> None:
    state, _ = _process()
    head = loads(_capture_head(state))
    head["schema_version"] = "10"
    head["simple"].pop("_macos_process_census")
    fresh = StateManager()
    _restore_head(fresh, dumps(head))
    assert fresh.macos_process_census_snapshot() == ()


@pytest.mark.parametrize("fault", ["none", "omit", "duplicate"])
def test_independent_fork_census_reconciles_actual_native_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _, dispatcher, output, cohort, event, _, _, child = _routed(tmp_path / "output")
    dispatcher.state_manager.configure_macos_process_census(
        child.hostname, event.timestamp, event.timestamp + timedelta(minutes=1)
    )
    ingress = MacosESIngress(tmp_path / "ingress")
    dispatcher.macos_es_ingress = ingress
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    census = dict(dispatcher.state_manager.macos_process_census_snapshot())[child.hostname]
    assert census.forks.count == 1 and census.execs.count == 0
    if fault != "none":
        sink = output.native_sink(event.src_host)
        write = sink.write

        def faulty_write(line: str) -> None:
            if fault == "duplicate":
                write(line)
                write(line)

        monkeypatch.setattr(sink, "write", faulty_write)
        with pytest.raises(StateError, match="omitted or duplicated"):
            ingress.finalize(dispatcher)
    else:
        ingress.finalize(dispatcher)
        summary = ingress.coverage.hosts[0].process_census
        assert summary.complete and summary.published_forks == summary.expected_forks == 1
    output.close()


@pytest.mark.parametrize("fault", ["none", "producer_bypass", "in_window_login"])
def test_complete_engine_accepts_commands_and_rejects_unresolved_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    import shlex

    from evidenceforge.generation.engine import GenerationEngine
    from tests.support.macos_ssh import MACOS_NATIVE_QUERY_COMMANDS
    from tests.unit.test_macos_installed_provisioning import _scenario

    scenario = _scenario()
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    scenario.macos_process_coverage = "complete"
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        system = scenario.environment.systems[0]
        user = scenario.environment.users[0]
        generator = engine.activity_generator
        # Explicitly model a pre-existing terminal; no born-in-window process is
        # backdated or excluded. The alternative case tests that boundary itself.
        at = (
            engine.start_time + timedelta(seconds=1)
            if fault == "in_window_login"
            else engine.start_time - timedelta(minutes=5)
        )
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(minutes=1))
        assert shell is not None
        if fault == "producer_bypass":
            monkeypatch.setattr(
                type(generator._process_execution_service()),
                "_prepare_macos_shell_root",
                lambda *args, **kwargs: None,
            )
        for index, command in enumerate(MACOS_NATIVE_QUERY_COMMANDS):
            pid = generator.generate_process(
                user,
                system,
                engine.start_time + timedelta(minutes=2, seconds=index * 20),
                logon,
                shlex.split(command)[0],
                command,
                parent_pid=shell,
                require_exact_parent=True,
            )
            assert pid > 0
        if fault == "none":
            engine._finalize_macos_process_coverage()
            census = next(
                host.process_census
                for host in engine.dispatcher.macos_es_ingress.coverage.hosts
                if host.hostname == system.hostname
            )
            assert census.complete
            assert (
                census.expected_forks == census.published_forks == len(MACOS_NATIVE_QUERY_COMMANDS)
            )
            assert (
                census.expected_execs == census.published_execs == len(MACOS_NATIVE_QUERY_COMMANDS)
            )
            assert census.aggregate_births == 0
        else:
            with pytest.raises(
                StateError,
                match="Incomplete native macOS process coverage.*unresolved aggregate starts",
            ):
                engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()


def test_export_verification_detects_physical_row_duplication(tmp_path: Path) -> None:
    from tests.unit.test_macos_es_ingress import _publish

    _, dispatcher, output, ingress, _ = _publish(tmp_path)
    ingress.finalize(dispatcher)
    output.close()
    ingress.verify_export(dispatcher)
    path = next(iter(output._writers.values())).output_path
    # This is a synthetic file produced by the test, never a local native log.
    path.write_bytes(path.read_bytes() * 2)
    with pytest.raises(StateError, match="omitted, duplicated or changed"):
        ingress.verify_export(dispatcher)
