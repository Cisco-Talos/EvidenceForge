# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The reviewed receiver stages use real canonical processes and native metadata owners."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.macos_ssh_native_startup import MacosNativeSshReceiverStartup
from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverStartupRequest,
    resolve_macos_ssh_receiver_environment,
)
from evidenceforge.generation.engine import GenerationEngine
from tests.unit.test_macos_installed_provisioning import _scenario


def test_native_receiver_stages_publish_six_execs_and_only_real_fork_only_children(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].services = ["ssh"]
    scenario.macos_process_coverage = "partial"
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=368)
    try:
        engine._initialize()
        state, generator = engine.state_manager, engine.activity_generator
        provider = generator.macos_execution_metadata
        base = engine.start_time + timedelta(seconds=10)
        authenticated, ready = base + timedelta(seconds=1), base + timedelta(seconds=2)
        environment = resolve_macos_ssh_receiver_environment(
            hostname="MAC-01",
            username="alex",
            started_at=base,
            state=state,
            identities=generator.identity_directory,
            deployment=engine.dispatcher.deployment_registry,
        )
        builder = state.begin_materialization_batch()
        session = builder.plan_session(
            username="alex",
            system="MAC-01",
            logon_type=10,
            source_ip="192.0.2.80",
            source_port=51000,
            session_kind="ssh",
            auth_protocol="ssh",
            effective_uid=environment.account.uid,
            effective_gid=environment.account.gid,
            start_time=base,
            source_ready_time=ready,
            network_close_time=base + timedelta(minutes=2),
            closure_owned_by_bundle=True,
        )
        session = builder.enrich_macos_audit_session(
            session, audit_uid=environment.account.uid, authenticated_at=authenticated
        )
        session = builder.enrich_macos_ssh_command_streams(
            session, first_pipe_id=provider.profile.first_pipe_id
        )
        fork = builder.plan_macos_ssh_receiver_fork(
            environment.parent,
            session=session,
            forked_at=base,
            execution_directory=provider.directory("MAC-01", "/", base),
            lifecycle_group_id="invented-ssh-native-startup",
        )
        builder.bind_session_processes(session, transport_plan=fork, process_tree_root_plan=fork)
        with state.prepared_materialization_batch(builder.seal()) as claim:
            claim.commit_no_fail()
        generator._lifecycle_authority.ensure_session("MAC-01", session.identity.logon_id)
        generator._lifecycle_authority.ensure_process("MAC-01", fork.identity.pid)
        times = tuple(base + timedelta(milliseconds=10 * (index + 1)) for index in range(13))
        times += (authenticated,)
        times += tuple(
            authenticated + timedelta(milliseconds=10 * (index + 1)) for index in range(5)
        )
        request = MacosSshReceiverStartupRequest(
            receiver=fork.identity,
            service_account=environment.service_account,
            wrapper=environment.wrapper,
            daemon=environment.daemon,
            session_worker=environment.session_worker,
            authentication_worker=environment.authentication_worker,
            shell=environment.shell,
            phase_times=times,
            launcher=engine.dispatcher.deployment_registry.application_descriptor(
                "macos-xpcproxy", "macos"
            ),
            service_label="com.openssh.sshd.00000000-0000-4000-8000-000000000001",
        )
        startup = MacosNativeSshReceiverStartup(
            request,
            state=state,
            dispatcher=engine.dispatcher,
            metadata=provider,
            host=HostContext(
                hostname="MAC-01",
                ip="192.0.2.81",
                os="macOS 27",
                os_category="macos",
                system_type="workstation",
            ),
        )
        while startup.result is None:
            startup.advance()
        result = startup.result
        assert result.privileged_receiver.execution_ordinal == 4
        assert result.privileged_receiver.initial_image == "/sbin/launchd"
        assert result.authenticated_child.parent_pid == result.privileged_receiver.pid
        assert result.shell.parent_pid == result.authenticated_child.pid
        assert result.shell.credentials == result.authenticated_child.credentials
        assert result.shell.job_control.session.sid == result.shell.pid
        streams = state.get_session(session.identity.logon_id).ssh_command_streams
        table = state.process_descriptors_at(result.shell, event_time=times[-1])
        assert table.bindings == streams.bindings
        census = dict(state.macos_process_census_snapshot())["MAC-01"]
        assert census.forks.count == 6 and census.execs.count == 6 and census.aggregate_births == 0
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    execs = [row for row in rows if row["event_type"] == 9]
    assert len(execs) == 6
    assert [row["event"]["exec"]["args"][0] for row in execs] == [
        "xpcproxy",
        "sshd-keygen-wrapper",
        "/usr/sbin/sshd",
        "/usr/libexec/sshd-session",
        "/usr/libexec/sshd-auth",
        "-zsh",
    ]
    # The external initial-fork publication is tested at its deferred network
    # owner separately. These retained stages contain five further real forks.
    assert sum(row["event_type"] == 11 for row in rows) == 5
    assert sum(row["event_type"] == 15 for row in rows) == 3


@pytest.mark.parametrize("failed_phase", [0, 4, 8, 10, 14, 18])
def test_native_receiver_recovers_committed_source_failure_without_repeating_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_phase: int
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original_advance = MacosNativeSshReceiverStartup.advance
    original_write = ExternalSortedLineWriter._commit_exact_row
    injected = False

    def advance(coordinator: MacosNativeSshReceiverStartup) -> object:
        nonlocal injected
        if coordinator.completed_phases != failed_phase or injected:
            return original_advance(coordinator)

        def lose_return(
            writer: ExternalSortedLineWriter,
            key: tuple[str, int, int],
            digest: str,
            frozen: object,
        ) -> None:
            nonlocal injected
            original_write(writer, key, digest, frozen)
            if not injected:
                injected = True
                raise RuntimeError("injected native SSH source lost return")

        with monkeypatch.context() as patch:
            patch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
            with pytest.raises(RuntimeError, match="injected native SSH"):
                original_advance(coordinator)
            assert coordinator.completed_phases == failed_phase
            version = coordinator._state.materialization_version
        result = original_advance(coordinator)
        assert coordinator._state.materialization_version == version
        return result

    monkeypatch.setattr(MacosNativeSshReceiverStartup, "advance", advance)
    test_native_receiver_stages_publish_six_execs_and_only_real_fork_only_children(tmp_path)
    assert injected
