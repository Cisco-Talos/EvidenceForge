# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""An independently qualified Electron-family subset retains complete process lifecycles."""

import random
import shlex
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.unit.test_macos_finder_generation import _finder_engine

MAIN = "/Applications/Visual Studio Code.app/Contents/MacOS/Code"
HELPER = "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"
ROLES = (
    ("--type=gpu-process",),
    ("--type=utility", "--utility-sub-type=network.mojom.NetworkService"),
    ("--type=utility", "--utility-sub-type=node.mojom.NodeService"),
)


class _AllRoles(random.Random):
    def randint(self, a: int, b: int) -> int:
        return b


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("automatic", [False, True])
def test_code_qualified_subset_has_shared_owner_distinct_io_and_complete_native_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native: bool,
    automatic: bool,
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=native, gui_application="vscode")
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator, state = engine.activity_generator, engine.state_manager
        residents = {
            alias: state.get_process_identity("MAC-01", engine._system_pids["MAC-01"][alias])
            for alias in ("cfprefsd", "launchservicesd")
        }
        for resident in residents.values():
            assert resident.parent_pid == 1 and resident.principal == "root"
            assert resident.started_at < engine.warmup_start_time
            assert resident.image_security is None  # No native execution qualification inferred.
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=2)
        main = generator.generate_process(
            user, system, at, logon, MAIN, shlex.join((MAIN,)), arguments=(MAIN,)
        )
        if automatic:
            profile = engine.deployment_registry.user_profile_for(
                system.hostname, user.username, "macos"
            )
            assignment = engine.deployment_registry.user_application_assignment_for_application(
                profile.profile_id, "vscode"
            )
            children = generator._generate_macos_application_children(
                user=user,
                system=system,
                time=at,
                logon_id=logon,
                parent_pid=main,
                assignment=assignment,
                rng=_AllRoles(41),
            )
            assert len(children) == 3
            assert (
                generator._generate_macos_application_children(
                    user=user,
                    system=system,
                    time=at + timedelta(minutes=1),
                    logon_id=logon,
                    parent_pid=main,
                    assignment=assignment,
                    rng=_AllRoles(42),
                )
                == ()
            )
        else:
            children = tuple(
                generator.generate_process(
                    user,
                    system,
                    at + timedelta(seconds=1 + index),
                    logon,
                    HELPER,
                    shlex.join((HELPER, *role)),
                    arguments=(HELPER, *role),
                    parent_pid=main,
                    require_exact_parent=True,
                    allow_existing_browser_reuse=False,
                    allow_browser_launch_spacing=False,
                )
                for index, role in enumerate(ROLES)
            )
        pipe_ids = set()
        for pid in children:
            process = state.get_process_identity(system.hostname, pid)
            assert process.initial_image == MAIN and process.parent_pid == main
            assert process.image_security.validation_category == 6
            assert process.arguments[0] == HELPER
            table = state.process_descriptors_at(process, event_time=process.execution_started_at)
            pipes = [binding for binding in table.bindings if binding.kind == "pipe"]
            pipe_ids.update(binding.native_pipe_id for binding in pipes)
            if "--utility-sub-type=node.mojom.NodeService" in process.arguments:
                assert [(binding.fd, binding.kind) for binding in table.bindings] == [
                    (0, "file"),
                    (1, "pipe"),
                    (2, "pipe"),
                ]
                assert (
                    table.native_last_fd == 2 and len({item.native_pipe_id for item in pipes}) == 2
                )
                assert not any(arg.startswith("--seatbelt-client=") for arg in process.arguments)
                assert (
                    "VSCODE_ESM_ENTRYPOINT=vs/code/electron-utility/sharedProcess/sharedProcessMain"
                    in process.environment
                )
            else:
                assert len(pipes) == 1 and pipes[0].fd in {21, 29}
                assert f"--seatbelt-client={pipes[0].fd}" in process.arguments
            binary = engine.dispatcher.resolve_loaded_process_binary_identity(process)
            assert (
                binary.key.version == "1.143.0"
                and binary.code_signature.signing_id == "com.microsoft.VSCode.helper"
            )
        assert len(pipe_ids) == 4
        for alias, resident in residents.items():
            assert (
                state.get_process_identity("MAC-01", engine._system_pids["MAC-01"][alias])
                == resident
            )
        if native:
            from evidenceforge.events.macos_file_operation import MacosFileOperationObservation
            from evidenceforge.generation.actions.macos_filesystem import (
                MacosFilesystemActionBundle,
                MacosFilesystemRequest,
            )
            from tests.unit.test_macos_filesystem_action import _file

            # Explicit and baseline producers share the engine-initialized owner.
            assert engine.dispatcher.local_artifact_registry is not None
            writer = state.get_process_identity(system.hostname, main)
            observed_at = at + timedelta(seconds=30)
            file = _file(engine.dispatcher, writer, observed_at)
            result = MacosFilesystemActionBundle(engine.dispatcher).execute(
                MacosFilesystemRequest(
                    "code-file-occurrence",
                    generator._process_execution_service().identity.host_context(system),
                    writer,
                    MacosFileOperationObservation("create", file, observed_at),
                )
            )
            assert result.projection_errors == (None,)
        for pid in (*children, main):
            process = state.get_process_identity(system.hostname, pid)
            generator.generate_process_termination(
                user,
                system,
                at + timedelta(minutes=2),
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
        if record.event_type == 9 and record.event.exec.target.executable.path in {MAIN, HELPER}
    ]
    assert len(execs) == (4 if native else 0)
    files = [record for record in records if record.event_type == 13]
    assert len(files) == int(native)
    if files:
        assert files[0].process.executable.path == MAIN
        assert (
            files[0].event.create.destination.existing_file.stat.st_uid
            == files[0].process.audit_token.euid
        )
    for record in execs:
        assert record.event.exec.entitlements is not None
        assert record.event.exec.target.cs_validation_category == 6
