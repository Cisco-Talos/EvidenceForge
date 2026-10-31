# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Installed setuid login and its forked child's drop use canonical state owners."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.process import process_credential_identities, process_fork_identities
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.actions.macos_finder import MacosFinderStartup
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_terminal_applications import _engine


@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_installed_login_exec_and_child_drop_preserve_real_and_audit_identity(
    tmp_path: Path, terminal_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _engine(tmp_path, terminal_id, native=False)
    try:
        engine._initialize()
        generator, state = engine.activity_generator, engine.state_manager
        system, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        owner = state.get_session_identity(logon)
        provider, registry = (
            generator.macos_execution_metadata,
            engine.dispatcher.deployment_registry,
        )
        descriptor = registry.application_descriptor(terminal_id, "macos")
        app_binary = registry.resolve_binary(
            system.hostname, descriptor.image_path, "macos", principal=user.username
        )
        startup = MacosFinderStartup(
            state=state,
            dispatcher=engine.dispatcher,
            metadata=provider,
            host=generator._build_host_context(system),
            parent=state.get_process_identity(system.hostname, 1),
            session=owner,
            launcher=registry.resolve_binary(
                system.hostname, "/usr/libexec/xpcproxy", "macos", principal="root"
            ),
            app=app_binary,
            arguments=(descriptor.image_path,),
            service_label="application.org.example.terminal.1.2",
            times=tuple(at + timedelta(seconds=i) for i in (1, 2, 3, 4)),
            lifecycle_group_id="test-terminal-app",
            concurrency_group_id="",
            storyline=False,
        )
        while not startup.complete:
            startup.advance()
        app = startup.process
        responsibility = ProcessResponsibility(
            ResponsibleProcessReference(app.hostname, app.object_id, app.pid, app.started_at)
        )
        builder = state.begin_action_cohort_materialization()
        birth = builder.fork_process(
            app,
            forked_at=at + timedelta(seconds=5),
            execution_directory=provider.directory(system.hostname, "/", at + timedelta(seconds=5)),
            responsibility=responsibility,
        )
        event = process_fork_occurrence(
            host=generator._build_host_context(system),
            parent=app,
            child=birth.identity,
            integrity_level="Medium",
            session=owner,
        )
        assert process_fork_identities(event) == (app, birth.identity)
        state.materialize_action_cohort(builder.seal())
        builder = state.begin_action_cohort_materialization()
        before = builder.change_posix_job_control(
            birth.identity,
            operation="setsid",
            changed_at=at + timedelta(seconds=6),
            macos_terminal=provider.profile.terminal,
        )
        state.materialize_action_cohort(builder.seal())
        login_binary = registry.resolve_binary(
            system.hostname, "/usr/bin/login", "macos", principal=user.username
        )
        original_observe = provider._filesystem.observe_image
        for stat_change in ({"mode": 0o100755}, {"uid": before.credentials.real_uid}, {"gid": 20}):

            def bad_stat(
                _filesystem: object,
                *args: object,
                _changes: dict[str, int] = stat_change,
                **kwargs: object,
            ) -> object:
                observed = original_observe(*args, **kwargs)
                return replace(observed, metadata=observed.metadata.model_copy(update=_changes))

            digest = state.materialization_digest()
            with monkeypatch.context() as patch:
                patch.setattr(type(provider._filesystem), "observe_image", bad_stat)
                with pytest.raises(StateError, match="provisioned root-owned 04555"):
                    provider.plan_exec(
                        state.begin_action_cohort_materialization(),
                        state,
                        before,
                        at=at + timedelta(seconds=7),
                        image="/usr/bin/login",
                        requested_path="/usr/bin/login",
                        arguments=("login", "-pf", user.username),
                        binary=login_binary,
                    )
            assert state.materialization_digest() == digest
        builder = state.begin_action_cohort_materialization()
        login = provider.plan_exec(
            builder,
            state,
            before,
            at=at + timedelta(seconds=7),
            image="/usr/bin/login",
            requested_path="/usr/bin/login",
            arguments=("login", "-pf", user.username),
            binary=login_binary,
        ).process
        assert before.credentials.real_uid == before.credentials.effective_uid != 0
        assert login.credentials == replace(before.credentials, effective_uid=0)
        state.materialize_action_cohort(builder.seal())
        builder = state.begin_action_cohort_materialization()
        child = provider.plan_fork(builder, state, login, at=at + timedelta(seconds=8)).identity
        state.materialize_action_cohort(builder.seal())
        digest = state.materialization_digest()
        with pytest.raises(StateError):
            state.begin_action_cohort_materialization().drop_macos_ssh_child_privileges(
                child, dropped_at=at + timedelta(seconds=9)
            )
        with pytest.raises(StateError):
            state.begin_action_cohort_materialization().drop_macos_login_child_privileges(
                login, dropped_at=at + timedelta(seconds=9)
            )
        assert state.materialization_digest() == digest
        builder = state.begin_action_cohort_materialization()
        after = builder.drop_macos_login_child_privileges(
            child, dropped_at=at + timedelta(seconds=9)
        )
        event = process_credential_occurrence(
            host=generator._build_host_context(system),
            before=child,
            after=after,
            timestamp=at + timedelta(seconds=9),
            kind="process_privilege_drop",
            integrity_level="Medium",
            session=owner,
        )
        assert process_credential_identities(event) == (child, after)
        assert after.credentials == before.credentials
        assert after.responsibility == responsibility
        assert after.execution_ordinal == child.execution_ordinal == 0
        plan, digest = builder.seal(), state.materialization_digest()
        with state.prepared_action_cohort_materialization(plan) as claim:
            claim.certify_composite_commit(claim.expected_result)
            claim.apply_provisional()
        assert state.materialization_digest() == digest
        state.materialize_action_cohort(plan)
        restored = StateManager()
        _restore_head(restored, _capture_head(state))
        for manager in (state, restored):
            assert (
                manager.get_process_identity_at(system.hostname, child.pid, child.started_at)
                == child
            )
            assert manager.get_process_identity(system.hostname, child.pid) == after
            assert (
                manager.get_process_identity_at(
                    system.hostname, login.pid, login.execution_started_at
                )
                == login
            )
            with pytest.raises((StateError, ValueError)):
                manager.begin_action_cohort_materialization().drop_macos_login_child_privileges(
                    after, dropped_at=at + timedelta(seconds=10)
                )
    finally:
        engine._close_emitters()
