# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented command completions preserve known results without success defaults."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import MacosCommandCompletionPolicy, MacosExecutionMetadataProfile
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.process_execution import ProcessTerminationRequest
from evidenceforge.generation.checkpoints.activity_head import (
    _capture_foreground,
    _restore_foreground,
)
from evidenceforge.generation.checkpoints.engine_head import GenerationEngineParticipant
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_ssh import macos_ssh_scenario


@contextmanager
def _engine(
    tmp_path: Path, scenarios_dir: Path, *, native: bool = True
) -> Iterator[tuple[GenerationEngine, System, User, ActiveSession]]:
    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=True)
    scenario.output.logs = [{"format": "ecar"}] + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    with generation_seed_scope(336):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        try:
            engine._initialize()
            user = scenario.environment.users[0]
            target = scenario.environment.systems[-1]
            engine.activity_generator.generate_ssh_session(
                user=user,
                target_system=target,
                time=engine.start_time + timedelta(minutes=10),
                source_ip="192.0.2.55",
                source_port=50001,
                duration=600,
                emit_session_close=True,
                defer_session_close=True,
            )
            session = next(
                s
                for s in engine.state_manager.get_sessions_for_user(user.username)
                if s.system == target.hostname and s.session_kind == "ssh"
            )
            yield engine, target, user, session
        finally:
            engine._close_emitters()


def _launch(fixture: tuple, command: str = "/usr/bin/id") -> tuple:
    engine, target, user, session = fixture
    generator = engine.activity_generator
    pid = generator.generate_process(
        user,
        target,
        engine.start_time + timedelta(minutes=11),
        session.logon_id,
        command.split()[0],
        command,
        parent_pid=session.session_shell_pid,
        require_exact_parent=True,
    )
    process = engine.state_manager.get_process_identity(target.hostname, pid)
    assert process.execution_ordinal == 1
    closes_at = generator.foreground_process_termination_time(target.hostname, pid)
    assert closes_at is not None
    return process, closes_at


def _native_exits(tmp_path: Path, pid: int) -> list:
    return [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).event_type == 15
        and record.process.audit_token.pid == pid
    ]


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("owner", ["bounded_finalizer", "command_completion"])
def test_nominal_command_completion_commits_one_known_exit(
    tmp_path: Path, scenarios_dir: Path, native: bool, owner: str
) -> None:
    with _engine(tmp_path, scenarios_dir, native=native) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        if owner == "bounded_finalizer":
            engine.activity_generator.finalize_foreground_process_lifetimes(
                at + timedelta(seconds=1)
            )
        else:
            engine.activity_generator.generate_process_termination(
                user,
                target,
                at,
                process.pid,
                process.image,
                session.logon_id,
                macos_command_completed=True,
            )
        ended = engine.state_manager._ended_processes_by_object_id[process.object_id]
        assert ended.exit_outcome == PosixProcessExit(exit_code=0)
        assert engine.state_manager.get_process(target.hostname, process.pid) is None
        restored = type(engine.state_manager)()
        _restore_head(restored, _capture_head(engine.state_manager))
        assert (
            restored._ended_processes_by_object_id[process.object_id].exit_outcome
            == ended.exit_outcome
        )
        engine.dispatcher.assert_exact_projection_recoveries_drained()
    exits = _native_exits(tmp_path, process.pid)
    assert len(exits) == int(native)
    if exits:
        assert exits[0].event.exit.stat == 0
        assert exits[0].process.executable.path == process.image


@pytest.mark.parametrize(
    "reason", ["teardown", "extra_arguments", "legacy_policy", "deadline", "hold"]
)
def test_unspecified_or_truncated_completion_remains_unknown(
    tmp_path: Path, scenarios_dir: Path, reason: str
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(
            fixture, "/usr/bin/id -u" if reason == "extra_arguments" else "/usr/bin/id"
        )
        if reason == "legacy_policy":
            engine.macos_execution_metadata.profile = (
                engine.macos_execution_metadata.profile.model_copy(
                    update={"command_completions": ()}
                )
            )
        if reason == "deadline":
            at = session.network_close_time + timedelta(seconds=1)
        if reason == "hold":
            engine.activity_generator._process_connection_hold_until[
                (target.hostname, process.pid, process.started_at)
            ] = at + timedelta(seconds=1)
        engine.activity_generator.generate_process_termination(
            user,
            target,
            at,
            process.pid,
            process.image,
            session.logon_id,
            macos_command_completed=reason != "teardown",
        )
        assert (
            engine.state_manager._ended_processes_by_object_id[process.object_id].exit_outcome
            is None
        )
    assert _native_exits(tmp_path, process.pid) == []


@pytest.mark.parametrize("outcome", [PosixProcessExit(exit_code=7), PosixProcessExit(signal=15)])
@pytest.mark.parametrize("failure", [None, "before_write", "after_write"])
def test_explicit_completed_result_and_sink_recovery_preserve_exact_outcome(
    tmp_path: Path,
    scenarios_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: PosixProcessExit,
    failure: str | None,
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        failed = False
        original = ExternalSortedLineWriter._commit_exact_row

        def write_once(
            writer: ExternalSortedLineWriter, key: tuple, digest: str, row: object
        ) -> None:
            nonlocal failed
            if (
                failure is not None
                and writer.output_path.name == "macos_endpoint_security.ndjson"
                and not failed
            ):
                failed = True
                if failure == "after_write":
                    original(writer, key, digest, row)
                raise RuntimeError("invented terminal write interruption")
            original(writer, key, digest, row)

        with monkeypatch.context() as patch:
            patch.setattr(ExternalSortedLineWriter, "_commit_exact_row", write_once)
            kwargs = {"exit_outcome": outcome, "expected_process": process}
            if failure is None:
                engine.activity_generator.generate_process_termination(
                    user, target, at, process.pid, process.image, session.logon_id, **kwargs
                )
            else:
                with pytest.raises(RuntimeError, match="terminal write interruption") as caught:
                    engine.activity_generator.generate_process_termination(
                        user, target, at, process.pid, process.image, session.logon_id, **kwargs
                    )
                digest = engine.state_manager.materialization_digest()
                collector = engine.dispatcher.es_collectors.connection(
                    f"{target.hostname.casefold()}:macos_endpoint_security"
                )
                engine.dispatcher.resume_action_cohort_projection(
                    caught.value.action_cohort_receipt
                )
                assert engine.state_manager.materialization_digest() == digest
                assert (
                    engine.dispatcher.es_collectors.connection(collector.source_instance)
                    == collector
                )
        assert (
            engine.state_manager._ended_processes_by_object_id[process.object_id].exit_outcome
            == outcome
        )
        engine.dispatcher.assert_exact_projection_recoveries_drained()
    exits = _native_exits(tmp_path, process.pid)
    assert len(exits) == 1
    assert exits[0].event.exit.stat == (7 << 8 if outcome.exit_code is not None else 15)


def test_changed_explicit_execution_fails_before_state_or_source_mutation(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        before = engine.state_manager.materialization_digest()
        with pytest.raises(StateError, match="exact live execution"):
            engine.activity_generator.generate_process_termination(
                user,
                target,
                at,
                process.pid,
                process.image,
                session.logon_id,
                exit_outcome=PosixProcessExit(signal=15),
                expected_process=replace(process, execution_ordinal=process.execution_ordinal + 1),
            )
        assert engine.state_manager.materialization_digest() == before
        assert engine.state_manager.get_process_identity(target.hostname, process.pid) == process
    assert _native_exits(tmp_path, process.pid) == []


@pytest.mark.parametrize(
    "raw",
    [
        {"arguments": ["id"], "exit_code": 0},
        {"arguments": ["/usr/bin/id"], "exit_code": True},
        {"arguments": ["/usr/bin/id"], "exit_code": 256},
    ],
)
def test_completion_policy_rejects_ambiguous_inputs(raw: dict) -> None:
    with pytest.raises(ValidationError):
        MacosCommandCompletionPolicy.model_validate(raw)


def test_old_profile_preserves_unknown_and_duplicate_invocations_are_rejected() -> None:
    from evidenceforge.generation.activity.macos_execution_metadata import (
        load_macos_execution_metadata_profile,
    )

    raw = load_macos_execution_metadata_profile().model_dump()
    del raw["command_completions"]
    assert MacosExecutionMetadataProfile.model_validate(raw).command_completions == ()
    rule = {"arguments": ["/usr/bin/id"], "exit_code": 0}
    with pytest.raises(ValidationError, match="distinct argument vectors"):
        MacosExecutionMetadataProfile.model_validate({**raw, "command_completions": [rule, rule]})


def test_explicit_result_requires_exact_process_and_changes_intent_identity(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        _engine_instance, target, user, session = fixture
        process, at = _launch(fixture)
        request = ProcessTerminationRequest(
            user, target, at, process.pid, process.image, session.logon_id
        )
        with pytest.raises(ValueError, match="exact process execution"):
            replace(request, exit_outcome=PosixProcessExit(exit_code=7))
        explicit = replace(
            request, expected_process=process, exit_outcome=PosixProcessExit(exit_code=7)
        )
        assert explicit.stable_id != request.stable_id
        assert (
            replace(explicit, exit_outcome=PosixProcessExit(signal=15)).stable_id
            != explicit.stable_id
        )


@pytest.mark.parametrize("legacy", [False, True])
def test_deferred_command_completion_restores_existing_engine_and_finalizer_owners(
    tmp_path: Path, scenarios_dir: Path, legacy: bool
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        engine._queue_story_process_termination(
            actor=user,
            system=target,
            time=at,
            pid=process.pid,
            process_name=process.image,
            logon_id=session.logon_id,
        )
        if legacy:
            for field in (
                "macos_command_completed",
                "completion_process_object_id",
                "completion_execution_id",
            ):
                engine._pending_story_process_terminations[0].pop(field)
        participant = GenerationEngineParticipant(engine)
        engine._dhcp_lease_state = {}
        head = participant.prepare_checkpoint(0).head.payload
        foreground = _capture_foreground(engine.activity_generator)
        engine._pending_story_process_terminations = []
        engine.activity_generator._foreground_process_finalizers.clear()
        participant.restore_checkpoint(head, ())
        _restore_foreground(engine.activity_generator, foreground)
        engine._flush_story_process_terminations()
        outcome = engine.state_manager._ended_processes_by_object_id[process.object_id].exit_outcome
        assert outcome == (None if legacy else PosixProcessExit(exit_code=0))
    assert len(_native_exits(tmp_path, process.pid)) == int(not legacy)


def test_query_policy_does_not_borrow_unknown_or_replaced_execution_facts(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, _target, _user, _session = fixture
        process, at = _launch(fixture)
        provider = engine.macos_execution_metadata
        assert provider.command_completion(process, at) == PosixProcessExit(exit_code=0)
        alternatives = [
            replace(process, arguments=None),
            replace(process, executable_version=None),
            replace(process, exec_script=None),
            replace(process, execution_ordinal=2),
            replace(
                process,
                executable_version=replace(
                    process.executable_version, content_id="invented-other-content"
                ),
            ),
        ]
        assert all(provider.command_completion(identity, at) is None for identity in alternatives)


@pytest.mark.parametrize(
    "field,value",
    [
        ("macos_command_completed", "yes"),
        ("completion_process_object_id", "invented-other-lifetime"),
    ],
)
def test_changed_deferred_completion_owner_fails_without_ending_process(
    tmp_path: Path, scenarios_dir: Path, field: str, value: str
) -> None:
    with _engine(tmp_path, scenarios_dir) as fixture:
        engine, target, user, session = fixture
        process, at = _launch(fixture)
        engine._queue_story_process_termination(
            actor=user,
            system=target,
            time=at,
            pid=process.pid,
            process_name=process.image,
            logon_id=session.logon_id,
        )
        engine._pending_story_process_terminations[0][field] = value
        before = engine.state_manager.materialization_digest()
        with pytest.raises(StateError, match="Deferred Mac command completion"):
            engine._flush_story_process_terminations()
        assert engine.state_manager.materialization_digest() == before
        assert engine.state_manager.get_process_identity(target.hostname, process.pid) == process
    assert _native_exits(tmp_path, process.pid) == []


@pytest.mark.slow
def test_command_completion_native_bytes_are_stable_across_fresh_processes(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    import os
    import subprocess
    import sys

    script = """
import sys
from pathlib import Path
from tests.unit.test_macos_command_exit_outcomes import _engine, _launch
with _engine(Path(sys.argv[1]), Path(sys.argv[2])) as fixture:
    engine, target, user, session = fixture
    process, at = _launch(fixture)
    engine.activity_generator.generate_process_termination(
        user, target, at, process.pid, process.image, session.logon_id,
        macos_command_completed=True,
    )
"""
    outputs = []
    for seed in ("13", "97"):
        output = tmp_path / seed
        result = subprocess.run(
            [sys.executable, "-c", script, str(output), str(scenarios_dir)],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(
            [path.read_bytes() for path in sorted(output.rglob("macos_endpoint_security.ndjson"))]
        )
    assert len(outputs[0]) == 1 and outputs[0] == outputs[1]
