# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical exit accounting and bounded natural completion regressions."""

import json
import random
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import MacosCommandCompletionPolicy, MacosOrdinaryClosePolicy
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.macos_process_census import MacosOccurrenceDigest, MacosProcessCensus
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_command_exit_outcomes import _engine, _launch, _native_exits
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_ssh_pty_execution import _engine as _ssh_engine
from tests.unit.test_macos_terminal_applications import _engine as _terminal_engine
from tests.unit.test_process_execution_state import _START, _process


@pytest.mark.parametrize(
    "command",
    [
        "/bin/pwd",
        "/bin/df -h",
        "/bin/ls -la {home}/Documents",
        "/usr/bin/du -sh {home}/Documents",
        "/opt/homebrew/bin/ssh -V",
    ],
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
@pytest.mark.parametrize("ordinary", [False, True])
def test_ssh_terminal_phases_are_all_accounted_without_inventing_results(
    tmp_path: Path, pty: bool, ordinary: bool
) -> None:
    engine = _ssh_engine(tmp_path, pty=pty)
    try:
        if not ordinary:
            engine.macos_execution_metadata.profile = (
                engine.macos_execution_metadata.profile.model_copy(update={"ordinary_close": None})
            )
        engine.activity_generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.expected_exits == census.observed_exits == 6
        assert census.known_exits == census.published_exits == (6 if ordinary else 3)
        assert census.exit_accounting_complete and census.known_exit_identities_match
        assert census.exit_complete is ordinary
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


@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
@pytest.mark.parametrize("ordinary", [False, True])
def test_selected_terminal_logout_model_closes_exact_chain_or_preserves_unknown(
    tmp_path: Path, terminal_id: str, ordinary: bool
) -> None:
    engine = _terminal_engine(tmp_path, terminal_id)
    try:
        engine._initialize()
        if not ordinary:
            engine.macos_execution_metadata.profile = (
                engine.macos_execution_metadata.profile.model_copy(update={"ordinary_close": None})
            )
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        generator.ensure_macos_session_shell(user, system, logon, at + timedelta(seconds=10))
        generator.generate_logoff(user, system, at + timedelta(minutes=2), logon)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        expected = 3 if terminal_id == "macos-terminal" else 4
        assert census.expected_exits == census.observed_exits == expected
        assert census.published_exits == (expected if ordinary else 0)
        assert census.exit_complete is ordinary
    finally:
        engine._close_emitters()


def test_shutdown_cancellation_is_a_signal_result_not_natural_query_success(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir, complete=True, chronological=True) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        provider = engine.macos_execution_metadata
        assert provider.command_completion(process, at) == PosixProcessExit(exit_code=0)
        cancelled = provider.ordinary_close(process, at, owner="session")
        assert cancelled == PosixProcessExit(signal=15)
        engine.activity_generator.generate_process_termination(
            user,
            target,
            at,
            process.pid,
            process.image,
            session.logon_id,
            exit_outcome=cancelled,
            expected_process=process,
        )
    assert _native_exits(tmp_path, process.pid)[0].event.exit.stat == 15


def test_ssh_server_results_are_independent_of_the_shell_result(tmp_path: Path) -> None:
    engine = _ssh_engine(tmp_path)
    try:
        provider = engine.macos_execution_metadata
        policy = provider.profile.ordinary_close.model_copy(
            update={
                "ssh_worker_return": PosixProcessExit(exit_code=255),
                "ssh_receiver_return": PosixProcessExit(exit_code=255),
            }
        )
        provider.profile = provider.profile.model_copy(update={"ordinary_close": policy})
        engine.activity_generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.exit_complete
    finally:
        engine._close_emitters()
    exits = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if json.loads(line)["event_type"] == 15
    ]
    server = [
        r
        for r in exits
        if r["process"]["executable"]["path"] == "/usr/libexec/sshd-session"
        and r["event"]["exit"]["stat"] != 0
    ]
    shell = [r for r in exits if r["process"]["executable"]["path"] == "/bin/zsh"]
    assert len(server) == 2 and all(r["event"]["exit"]["stat"] == 255 << 8 for r in server)
    assert len(shell) == 1 and shell[0]["event"]["exit"]["stat"] == 0


def test_collection_end_does_not_quit_surviving_terminal_processes(tmp_path: Path) -> None:
    engine = _terminal_engine(tmp_path, "macos-iterm2")
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(
            user, system, logon, at + timedelta(seconds=10)
        )
        generator.finalize_foreground_process_lifetimes(engine.end_time)
        engine._finalize_macos_process_coverage()
        assert engine.state_manager.get_process(system.hostname, shell) is not None
        assert (
            engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.expected_exits == 0
        )
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("change", ["cancel_as_success", "quit_as_signal", "relative_image"])
def test_ordinary_close_policy_rejects_conflicting_cause_and_result(change: str) -> None:
    from evidenceforge.generation.activity.macos_execution_metadata import (
        load_macos_execution_metadata_profile,
    )

    raw = load_macos_execution_metadata_profile().ordinary_close.model_dump()
    if change == "cancel_as_success":
        raw["cancelled_command"] = {"exit_code": 0}
    elif change == "quit_as_signal":
        raw["application_quit"] = {"signal": 15}
    else:
        raw["login_image"] = "login"
    with pytest.raises(ValidationError):
        MacosOrdinaryClosePolicy.model_validate(raw)


@pytest.mark.parametrize(
    "application,image,arguments,code",
    [
        ("psql", "/opt/homebrew/opt/libpq/bin/psql", '-h absent.example.test -c "SELECT 1"', 2),
        (
            "mysql",
            "/opt/homebrew/opt/mysql-client/bin/mysql",
            '--host=absent.example.test --execute="SELECT 1"',
            1,
        ),
    ],
)
def test_failed_query_transport_supplies_nonzero_completed_native_result(
    tmp_path: Path, application: str, image: str, arguments: str, code: int
) -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [
                {"user": "alex", "applications": ["macos-terminal", application]}
            ],
        }
    ]
    raw["output"]["logs"] = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    raw["macos_process_coverage"] = "complete"
    engine = GenerationEngine(Scenario.model_validate(raw), tmp_path, generation_seed=384)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, target = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, target, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(user, target, logon, at + timedelta(seconds=1))
        start = at + timedelta(seconds=2)
        command = f"{image} {arguments}"
        pid = generator.generate_process(
            user, target, start, logon, image, command, parent_pid=shell
        )
        process = engine.state_manager.get_process_identity(target.hostname, pid)
        provider = engine.macos_execution_metadata
        assert provider.command_completion(
            process, start + timedelta(seconds=1)
        ) == PosixProcessExit(exit_code=0)
        result = generator._emit_process_network_correlation(
            target, image, command, start, pid, random.Random(384)
        )
        assert result == PosixProcessExit(exit_code=code)
        generator._generate_bounded_foreground_process_termination(
            user=user,
            system=target,
            start_time=start,
            pid=pid,
            process_name=image,
            logon_id=logon,
            lifetime=(1.0, 2.0),
            rng=random.Random(384),
            completion_outcome=result,
        )
        assert (
            engine.state_manager._ended_processes_by_object_id[process.object_id].exit_outcome
            == result
        )
        generator.execute_baseline_activity(
            user, target, start + timedelta(minutes=1), "process_query"
        )
        baseline = [
            ended
            for object_id, ended in engine.state_manager._ended_processes_by_object_id.items()
            if object_id != process.object_id and ended.image == image
        ]
        assert len(baseline) == 1 and baseline[0].exit_outcome == result
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    assert _native_exits(tmp_path, pid)[0].event.exit.stat == code << 8
    assert _native_exits(tmp_path, baseline[0].pid)[0].event.exit.stat == code << 8
