# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical exit accounting and bounded natural completion regressions."""

import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import MacosCommandCompletionPolicy
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.macos_process_census import MacosOccurrenceDigest, MacosProcessCensus
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_command_exit_outcomes import _engine, _launch, _native_exits
from tests.unit.test_macos_ssh_pty_execution import _engine as _ssh_engine
from tests.unit.test_macos_terminal_applications import _engine as _terminal_engine
from tests.unit.test_process_execution_state import _START, _process


@pytest.mark.parametrize(
    "command",
    ["/bin/pwd", "/bin/df -h", "/bin/ls -la {home}/Documents", "/usr/bin/du -sh {home}/Documents"],
)
def test_declared_query_completion_has_known_exit_and_independent_count(
    tmp_path: Path, scenarios_dir: Path, command: str
) -> None:
    with _engine(tmp_path, scenarios_dir, complete=True, chronological=True) as fixture:
        engine, target, user, _session = fixture
        home = engine.macos_execution_metadata._accounts[
            target.hostname.casefold(), user.username.casefold()
        ].home
        process, at = _launch(fixture, command.format(home=home))
        engine.activity_generator.finalize_foreground_process_lifetimes(at + timedelta(seconds=1))
        assert engine.state_manager._ended_processes_by_object_id[
            process.object_id
        ].exit_outcome == PosixProcessExit(exit_code=0)
        census = dict(engine.state_manager.macos_process_census_snapshot())[target.hostname]
        assert census.known_exits.count >= 1
    assert len(_native_exits(tmp_path, process.pid)) == 1


def test_home_completion_template_cannot_certify_another_users_directory(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, _target, _user, _session = fixture
        process, at = _launch(fixture, "/bin/ls -la /Users/another-user/Documents")
        assert engine.macos_execution_metadata.command_completion(process, at) is None


def test_natural_completion_plans_owned_hold_before_certifying_result(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir, complete=True, chronological=True) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        hold = at + timedelta(seconds=5)
        engine.activity_generator._process_connection_hold_until[
            target.hostname, process.pid, process.started_at
        ] = hold
        planner = engine.activity_generator._process_foreground()
        before = engine.state_manager.materialization_digest()
        assert (
            planner.plan_macos_command_completion(
                system=target, pid=process.pid, preferred_at=at, latest_at=hold
            )
            is None
        )
        resolved = planner.plan_macos_command_completion(
            system=target,
            pid=process.pid,
            preferred_at=at,
            latest_at=session.network_close_time - timedelta(seconds=2),
        )
        assert hold < resolved < session.network_close_time
        assert engine.state_manager.materialization_digest() == before
        engine.activity_generator.generate_process_termination(
            user,
            target,
            resolved,
            process.pid,
            process.image,
            session.logon_id,
            macos_command_completed=True,
        )
        assert engine.state_manager._ended_processes_by_object_id[
            process.object_id
        ].exit_outcome == PosixProcessExit(exit_code=0)
    assert len(_native_exits(tmp_path, process.pid)) == 1


@pytest.mark.parametrize("pty", [False, True])
def test_ssh_terminal_phases_are_all_accounted_without_inventing_results(
    tmp_path: Path, pty: bool
) -> None:
    engine = _ssh_engine(tmp_path, pty=pty)
    try:
        engine.activity_generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.expected_exits == census.observed_exits == 6
        assert census.known_exits == census.published_exits == 3
        assert census.exit_accounting_complete and census.known_exit_identities_match
        assert census.exit_complete is False
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert sum(r["object"] == "PROCESS" and r["action"] == "TERMINATE" for r in rows) == 6


def test_pre_window_unknown_exit_is_not_counted_as_an_in_window_missing_result(
    tmp_path: Path,
) -> None:
    engine = _terminal_engine(tmp_path, "macos-terminal")
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time - timedelta(minutes=5)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(
            user, system, logon, at + timedelta(seconds=10)
        )
        pid = generator.generate_process(
            user,
            system,
            at + timedelta(seconds=20),
            logon,
            "/usr/bin/id",
            "/usr/bin/id -u",
            parent_pid=shell,
            require_exact_parent=True,
        )
        generator.generate_process_termination(
            user, system, at + timedelta(seconds=25), pid, "/usr/bin/id", logon
        )
        engine._finalize_macos_process_coverage()
        host = engine.dispatcher.macos_es_ingress.coverage.hosts[0]
        assert host.process_census.expected_exits == 0
        assert host.process_census.exit_complete
        assert any(
            r.phase == "exit" and r.reason == "exit_outcome_unknown" and r.status == "out_of_window"
            for r in host.observations
        )
    finally:
        engine._close_emitters()


def test_exit_census_hydrates_known_unknown_and_legacy_without_guessing() -> None:
    state, process = _process()
    state.configure_macos_process_census(process.hostname, _START, _START + timedelta(hours=1))
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        process, end_time=_START + timedelta(seconds=1), exit_outcome=PosixProcessExit(exit_code=7)
    )
    state.materialize_action_cohort(builder.seal())
    census = dict(state.macos_process_census_snapshot())[process.hostname]
    assert census.exits == census.known_exits and census.exits.count == 1
    restored = type(state)()
    _restore_head(restored, _capture_head(state))
    assert dict(restored.macos_process_census_snapshot())[process.hostname] == census
    unknown = MacosProcessCensus(
        _START,
        _START + timedelta(hours=1),
        exits=MacosOccurrenceDigest(),
        known_exits=MacosOccurrenceDigest(),
    ).terminate(process, at=_START + timedelta(seconds=1), known=False)
    assert unknown.exits.count == 1 and unknown.known_exits.count == 0
    encoded = encode_state_value(census)
    encoded[1] = "macos-process-census-v1"
    encoded[2] = encoded[2][:6]
    legacy = decode_state_value(encoded)
    assert legacy.exits is legacy.known_exits is None
    assert replace(legacy, aggregate_samples=()).forks == census.forks


@pytest.mark.parametrize("failure", ["bypassed_exit", "filtered_known_result"])
def test_complete_run_rejects_missing_native_exit_accounting(
    tmp_path: Path, scenarios_dir: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import evidenceforge.generation.macos_es_publication as native

    with _engine(tmp_path, scenarios_dir, complete=True) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        original = native.prepared_macos_es_process_publication
        decision = native._decision

        @contextmanager
        def bypass(dispatcher: object, cohort: object, events: tuple):
            if any(
                e.event_type == "process_terminate" and e.identity_plan.subject == process
                for e in events
            ):
                yield None
                return
            with original(dispatcher, cohort, events) as result:
                yield result

        def filtered(dispatcher: object, event: object) -> ObservationDecision:
            if event.event_type == "process_terminate" and event.identity_plan.subject == process:
                return ObservationDecision("filtered")
            return decision(dispatcher, event)

        with monkeypatch.context() as patch:
            if failure == "bypassed_exit":
                patch.setattr(native, "prepared_macos_es_process_publication", bypass)
            else:
                patch.setattr(native, "_decision", filtered)
            engine.activity_generator.generate_process_termination(
                user,
                target,
                at,
                process.pid,
                process.image,
                session.logon_id,
                macos_command_completed=True,
            )
        with pytest.raises(StateError, match="Incomplete macOS exit accounting"):
            engine._finalize_macos_process_coverage()


def test_uncommitted_exit_census_is_rolled_back_with_process_state() -> None:
    state, process = _process()
    state.configure_macos_process_census(process.hostname, _START, _START + timedelta(hours=1))
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        process, end_time=_START + timedelta(seconds=1), exit_outcome=PosixProcessExit(exit_code=0)
    )
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(builder.seal()) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert dict(state.macos_process_census_snapshot())[process.hostname].exits.count == 1
    assert state.materialization_digest() == before
    assert dict(state.macos_process_census_snapshot())[process.hostname].exits.count == 0


@pytest.mark.parametrize(
    "selector",
    [
        {"argument_template": ["/bin/ls", "{unknown}"]},
        {"argument_template": ["/{home}/ls", "x"]},
        {"argument_template": ["/bin/ls", "{home!r}"]},
        {"argument_template": ["/bin/ls", "{home:>3}"]},
        {"argument_template": ["/bin/ls", "literal"]},
        {"arguments": ["/bin/pwd"], "argument_template": ["/bin/ls", "{home}"]},
        {},
    ],
)
def test_completion_templates_reject_ambiguous_or_unbounded_selectors(selector: dict) -> None:
    with pytest.raises(ValidationError):
        MacosCommandCompletionPolicy.model_validate(selector | {"exit_code": 0})
