# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded browser roles use canonical installed identities, fork/exec and pipes."""

import shlex
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.events.dispatcher import PreparedActionCohortCapability
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import ExecutionEffectPlan
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_finder_generation import _finder_engine

MAIN = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
HELPERS = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/155.0.8059.80/Helpers"
RENDERER = (
    f"{HELPERS}/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)"
)
GENERIC = f"{HELPERS}/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
ROLES = (
    (RENDERER, ("--type=renderer",)),
    (GENERIC, ("--type=gpu-process",)),
    (GENERIC, ("--type=utility", "--utility-sub-type=network.mojom.NetworkService")),
)


@pytest.mark.parametrize("native", [True, False], ids=["native", "filtered"])
@pytest.mark.parametrize("automatic", [False, True], ids=["explicit", "catalog"])
def test_chrome_main_and_three_helper_roles_have_exact_canonical_census_and_native_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native: bool,
    automatic: bool,
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=native)
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=2)
        main = generator.generate_process(
            user,
            system,
            at,
            logon,
            MAIN,
            f'"{MAIN}"' if automatic else shlex.join((MAIN,)),
            arguments=(MAIN,),
            parent_pid=1,
            require_exact_parent=not automatic,
            macos_launch_kind=None if automatic else "finder",
            from_storyline=True,
        )
        children: list[int] = []
        pipe_ids: set[int] = set()
        for index, (image, role) in enumerate(ROLES):
            pid = generator.generate_process(
                user,
                system,
                at + timedelta(seconds=1 + index),
                logon,
                image,
                shlex.join((image, *role)),
                arguments=(image, *role),
                parent_pid=main,
                require_exact_parent=True,
                from_storyline=True,
                allow_existing_browser_reuse=False,
                allow_browser_launch_spacing=False,
            )
            children.append(pid)
            process = engine.state_manager.get_process_identity(system.hostname, pid)
            assert process.parent_pid == main and process.initial_image == MAIN
            assert process.execution_ordinal == 1
            assert process.arguments == (image, *role, "--seatbelt-client=3")
            table = engine.state_manager.process_descriptors_at(
                process, event_time=process.execution_started_at
            )
            assert [(binding.fd, binding.kind) for binding in table.bindings] == [
                (0, "file"),
                (1, "file"),
                (2, "file"),
                (3, "pipe"),
            ]
            pipe_ids.add(table.bindings[-1].native_pipe_id)
            assert process.executable_version.platform == "macos"
            assert process.image_security.validation_category == 6
        assert len(pipe_ids) == 3
        for pid in (*children, main):
            process = engine.state_manager.get_process_identity(system.hostname, pid)
            generator.generate_process_termination(
                user,
                system,
                at + timedelta(seconds=10),
                pid,
                process.image,
                logon_id=logon,
                expected_process=process,
                exit_outcome=PosixProcessExit(exit_code=0),
            )
        engine._finalize_macos_process_coverage()
        if native:
            census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
            assert census.complete and census.aggregate_births == 0
            assert census.expected_forks == census.published_forks == 4
            assert census.expected_execs == census.published_execs == 5
    finally:
        engine._close_emitters()
    records = [
        decode_endpoint_security_record(line)
        for path in (tmp_path / "run").rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    execs = [
        record
        for record in records
        if record.event_type == 9
        and record.event.exec.target.executable.path in {MAIN, RENDERER, GENERIC}
    ]
    assert len(execs) == (4 if native else 0)
    if native:
        browser = next(
            record for record in execs if record.event.exec.target.executable.path == MAIN
        )
        assert browser.event.exec.target.signing_id == "com.google.Chrome"
        for record in execs:
            payload = record.event.exec
            if payload.target.executable.path == MAIN:
                continue
            assert record.process.executable.path == MAIN
            assert payload.target.parent_audit_token == browser.event.exec.target.audit_token
            assert payload.fds[-1].fd == 3 and payload.fds[-1].fdtype == 6
            assert payload.last_fd == 3 and "--seatbelt-client=3" in payload.args
            if payload.target.executable.path == GENERIC:
                assert payload.target.signing_id == "com.google.Chrome.helper"
                assert payload.entitlements is None
            else:
                assert dict(payload.entitlements) == {"com.apple.security.cs.allow-jit": True}


def test_unsupported_browser_child_is_rejected_before_allocating_a_lifetime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True)
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=2)
        main = generator.generate_process(
            user,
            system,
            at,
            logon,
            MAIN,
            shlex.join((MAIN,)),
            arguments=(MAIN,),
            parent_pid=1,
            require_exact_parent=True,
            macos_launch_kind="finder",
        )
        before = engine.state_manager.macos_process_census_snapshot()
        with pytest.raises(StateError, match="qualified exact helper image and invocation"):
            generator.generate_process(
                user,
                system,
                at + timedelta(seconds=1),
                logon,
                GENERIC,
                shlex.join((GENERIC, "--type=unknown")),
                arguments=(GENERIC, "--type=unknown"),
                parent_pid=main,
                require_exact_parent=True,
            )
        assert engine.state_manager.macos_process_census_snapshot() == before
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("family", ["chrome", "vscode"])
@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "lost-return"])
@pytest.mark.parametrize("phase", [0, 1], ids=["fork", "exec"])
def test_browser_helper_retry_keeps_one_fork_exec_and_pipe_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    committed: bool,
    phase: int,
    family: str,
) -> None:
    from tests.unit.test_macos_vscode_generation import HELPER as CODE_HELPER
    from tests.unit.test_macos_vscode_generation import MAIN as CODE_MAIN

    main_image = MAIN if family == "chrome" else CODE_MAIN
    helper_image = GENERIC if family == "chrome" else CODE_HELPER
    pipe_count = 1 if family == "chrome" else 2
    engine = _finder_engine(
        tmp_path, monkeypatch, native=True, gui_application=None if family == "chrome" else "vscode"
    )
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=2)
        main = generator.generate_process(
            user,
            system,
            at,
            logon,
            main_image,
            shlex.join((main_image,)),
            arguments=(main_image,),
            parent_pid=1,
            require_exact_parent=True,
            macos_launch_kind="finder",
        )
        args = (
            (helper_image, "--type=gpu-process")
            if family == "chrome"
            else (helper_image, "--type=utility", "--utility-sub-type=node.mojom.NodeService")
        )
        request = ProcessExecutionRequest(
            user,
            system,
            at + timedelta(seconds=1),
            logon,
            helper_image,
            shlex.join(args),
            arguments=args,
            parent_pid=main,
            require_exact_parent=True,
            effect_plan=ExecutionEffectPlan(
                ActionAnchor("process_execution", "invented-browser-retry", source="test"), ()
            ),
        )
        original = PreparedActionCohortCapability.commit_no_fail
        failed = False
        calls = 0

        def fault(capability: PreparedActionCohortCapability) -> object:
            nonlocal failed, calls
            current = calls
            calls += 1
            if not failed and current == phase:
                failed = True
                if committed:
                    original(capability)
                raise OSError("invented browser publication interruption")
            return original(capability)

        before = dict(engine.state_manager.macos_process_census_snapshot())[system.hostname]
        first = engine.macos_execution_metadata.profile.first_pipe_id
        before_pipe = engine.state_manager._macos_pipe_counters.get(
            system.hostname, (first, first - 1)
        )
        with monkeypatch.context() as scoped:
            scoped.setattr(PreparedActionCohortCapability, "commit_no_fail", fault)
            with pytest.raises(OSError, match="invented browser publication interruption"):
                generator._process_execution_service().create(request)
        pid = generator._process_execution_service().create(request)
        after = dict(engine.state_manager.macos_process_census_snapshot())[system.hostname]
        assert after.forks.count == before.forks.count + 1
        assert after.execs.count == before.execs.count + 1
        assert engine.state_manager._macos_pipe_counters[system.hostname] == (
            first,
            before_pipe[1] + pipe_count,
        )
        process = engine.state_manager.get_process_identity(system.hostname, pid)
        table = engine.state_manager.process_descriptors_at(
            process, event_time=process.execution_started_at
        )
        assert len([binding for binding in table.bindings if binding.kind == "pipe"]) == pipe_count
        engine.dispatcher.assert_exact_projection_recoveries_drained()
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()
