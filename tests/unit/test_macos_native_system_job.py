# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented system-job workloads exercise the public canonical persistence owner."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_persistence import (
    MacosPersistenceActionBundle,
    MacosPersistenceRequest,
)
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_finder_generation import _finder_engine


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    native: bool = True,
    program: str = "/usr/bin/true",
    explicit_profile: bool = True,
    arguments: tuple[str, ...] | None = None,
    complete: bool = True,
) -> tuple:
    engine = _finder_engine(tmp_path, monkeypatch, native=native, complete=complete)
    with effective_config_scope(engine.compiled_scenario.effective_config):
        engine._initialize()
    generator, dispatcher = engine.activity_generator, engine.dispatcher
    if dispatcher.local_artifact_registry is None:
        dispatcher.bind_local_artifact_registry(LocalArtifactVersionRegistry())
    state = engine.state_manager
    host = generator._build_host_context(engine.scenario.environment.systems[0])
    root = state.get_process_identity(host.hostname, 1)
    bundle = MacosPersistenceActionBundle(
        state=state,
        lifecycle=engine.lifecycle_registry,
        authority=engine.lifecycle_authority,
        dispatcher=dispatcher,
        deployments=dispatcher.deployment_registry,
        content=RuntimeContentIdentityManager(dispatcher.local_artifact_registry),
        metadata_provider=engine.macos_execution_metadata,
        native_startups=generator._macos_finder_startups,
    )
    spec = LaunchdSystemJobSpec(
        label="org.example.native-job",
        program=program,
        arguments=arguments if arguments is not None else (program,),
        principal="root",
        launch_profile="root_xpcproxy_v11" if explicit_profile else None,
    )

    def request(operation: str, seconds: int) -> MacosPersistenceRequest:
        return MacosPersistenceRequest(
            caller=root,
            host=host,
            timestamp=engine.start_time + timedelta(seconds=seconds),
            action_id=f"job-{operation}-{seconds}",
            operation=operation,
            label=spec.label,
            path="/Library/LaunchDaemons/org.example.native-job.plist"
            if operation in {"write", "bootstrap", "remove"}
            else None,
            definition=spec if operation == "write" else None,
            size_bytes=1024 if operation == "write" else None,
            exit_code=0 if operation == "exit" else None,
        )

    bundle.execute(request("write", 60))
    bundle.execute(request("bootstrap", 61))
    return engine, bundle, request


@pytest.mark.parametrize("native", [False, True], ids=["filtered", "complete-native"])
@pytest.mark.parametrize(
    "program,flags", [("/usr/bin/true", 0x26011B11), ("/usr/bin/sw_vers", 0x24000001)]
)
def test_native_system_job_keeps_real_fork_two_execs_and_loaded_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: bool, program: str, flags: int
) -> None:
    engine, bundle, request = _setup(tmp_path, monkeypatch, native=native, program=program)
    try:
        # The loaded definition is authoritative after its modeled file is removed.
        bundle.execute(request("remove", 62))
        bundle.metadata_provider.profile = bundle.metadata_provider.profile.model_copy(
            update={"system_job_environment": ("LANG=changed-after-load",)}
        )
        first = bundle.execute(request("activate", 63)).process
        assert first.execution_ordinal == 2 and first.initial_image == "/sbin/launchd"
        assert first.arguments == (program,) and first.logon_id == ""
        assert first.job_control.pgid == first.job_control.session.sid == first.pid
        assert first.credentials.is_unattributed_root and first.credentials.audit_session_id > 0
        assert first.environment == (
            "PATH=/usr/bin:/bin",
            "LANG=C",
            "LC_ALL=C",
            "OSLogRateLimit=64",
            "XPC_FLAGS=1",
            "XPC_SERVICE_NAME=org.example.native-job",
        )
        assert not engine.activity_generator._macos_finder_startups
        with pytest.raises(StateError, match="active process binding"):
            bundle.execute(request("activate", 64))
        bundle.execute(request("exit", 65))
        second = bundle.execute(request("activate", 66)).process
        assert second.object_id != first.object_id
        bundle.execute(request("exit", 67))
        bundle.execute(request("unload", 68))
        engine._finalize_macos_process_coverage()
        if native:
            census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
            assert census.complete and census.aggregate_births == 0
            assert census.expected_forks == census.published_forks == 2
            assert census.expected_execs == census.published_execs == 4
    finally:
        engine._close_emitters()
    rows = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    if native:
        assert [row.event_type for row in rows] == [11, 9, 9, 15] * 2
        fork, launcher, target, exit_row = rows[:4]
        assert (
            fork.process.executable.path == fork.event.fork.child.executable.path == "/sbin/launchd"
        )
        assert launcher.event.exec.env == ("XPC_FLAGS=0x0",)
        assert launcher.event.exec.target.group_id == launcher.event.exec.target.session_id == 1
        assert target.process.group_id == target.process.session_id == first.pid
        assert target.process.audit_token.asid == fork.process.audit_token.asid
        assert target.event.exec.target.responsible_audit_token == exit_row.process.audit_token
        assert target.event.exec.target.codesigning_flags == flags
        assert [fd.fdtype for fd in target.event.exec.fds] == [1, 1, 1]
        assert target.event.exec.last_fd == 2 and exit_row.event.exit.stat == 0
    else:
        assert not rows


def test_optional_mac_start_displaced_after_collection_allocates_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.models.scenario import User

    engine, _bundle, _request = _setup(tmp_path, monkeypatch)
    try:
        generator = engine.activity_generator
        service = generator._process_execution_service()
        monkeypatch.setattr(
            type(service.scheduling),
            "_space_interactive_shell_child_launch",
            lambda _self, **_kwargs: engine.end_time + timedelta(seconds=1),
        )
        before = engine.state_manager.macos_process_census_snapshot()
        pid = generator.generate_process(
            User(username="root", full_name="Root", email="root@example.test"),
            engine.scenario.environment.systems[0],
            engine.end_time - timedelta(seconds=1),
            "",
            "/usr/bin/sw_vers",
            "/usr/bin/sw_vers",
            parent_pid=1,
            require_exact_parent=True,
        )
        assert pid == 0
        assert engine.state_manager.macos_process_census_snapshot() == before
    finally:
        engine._close_emitters()


def test_installed_job_outside_reference_inventory_uses_shared_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, bundle, request = _setup(
        tmp_path, monkeypatch, program="/usr/bin/id", explicit_profile=False
    )
    try:
        process = bundle.execute(request("activate", 63)).process
        assert process.execution_ordinal == 2 and process.arguments == ("/usr/bin/id",)
        bundle.execute(request("exit", 65))
        bundle.execute(request("unload", 66))
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
        assert census.expected_execs == census.published_execs == 2
        assert not engine.activity_generator._macos_finder_startups
        assert bundle.services.service_preparation_census().publication_reservations == 0
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("native", [False, True], ids=["filtered", "native"])
@pytest.mark.parametrize("qualified", [False, True], ids=["unknown-validation", "qualified"])
def test_sleep_job_keeps_real_start_and_known_exit_without_inventing_signer_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: bool, qualified: bool
) -> None:
    engine, bundle, request = _setup(
        tmp_path,
        monkeypatch,
        native=native,
        program="/bin/sleep",
        arguments=("/bin/sleep", "600"),
        explicit_profile=False,
        complete=False,
    )
    try:
        if not qualified:
            provider = bundle.metadata_provider
            provider.profile = provider.profile.model_copy(
                update={
                    "code_validation": tuple(
                        rule
                        for rule in provider.profile.code_validation
                        if not (rule.product_id == "apple-macos" and "sleep" in rule.artifact_names)
                    )
                }
            )
        process = bundle.execute(request("activate", 63)).process
        assert process.initial_image == "/sbin/launchd" and process.execution_ordinal == 2
        assert process.arguments == ("/bin/sleep", "600")
        assert (process.image_security is not None) == qualified
        binary = engine.dispatcher.resolve_loaded_process_binary_identity(process)
        assert binary.code_signature.entitlements == "absent"
        assert process.executable_version is not None
        result = bundle.execute(request("exit", 664))
        assert result.terminated == (process,)
        bundle.execute(request("unload", 665))
        engine._finalize_macos_process_coverage()
        if native:
            host = engine.dispatcher.macos_es_ingress.coverage.hosts[0]
            assert host.process_census.aggregate_births == 0
            assert host.process_census.expected_forks == host.process_census.published_forks == 1
            assert host.process_census.expected_execs == 2
            assert host.process_census.published_execs == 1 + int(qualified)
            assert host.process_census.complete == qualified
            if not qualified:
                assert any(row.reason == "image_security_unknown" for row in host.observations)
    finally:
        engine._close_emitters()
    rows = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    if native:
        assert [row.event_type for row in rows] == ([11, 9, 9, 15] if qualified else [11, 9])
        assert rows[1].event.exec.target.executable.path == "/usr/libexec/xpcproxy"
        if qualified:
            assert rows[2].event.exec.args == ("/bin/sleep", "600")
            assert rows[3].event.exit.stat == 0
    else:
        assert not rows


def test_native_service_binding_cannot_use_ordinary_registry_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, bundle, request = _setup(tmp_path, monkeypatch)
    original = engine.lifecycle_authority.publish_existing_process_service

    def direct(process: object, token: object) -> None:
        with bundle.services.claimed_service_publication(token) as capability:
            capability.commit_no_fail()

    try:
        monkeypatch.setattr(engine.lifecycle_authority, "publish_existing_process_service", direct)
        with pytest.raises(StateError, match="State/lifecycle authority"):
            bundle.execute(request("activate", 63))
        assert engine.activity_generator._macos_finder_startups
        monkeypatch.setattr(
            engine.lifecycle_authority, "publish_existing_process_service", original
        )
        result = bundle.execute(request("activate", 63))
        assert result.process.execution_ordinal == 2
        bundle.execute(request("exit", 65))
        bundle.execute(request("unload", 66))
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.expected_forks == census.published_forks == 1
        assert census.expected_execs == census.published_execs == 2
    finally:
        engine._close_emitters()


def test_legacy_spec_serialization_and_file_seed_stay_exact() -> None:
    original = LaunchdSystemJobSpec(
        label="example", program="/usr/bin/true", arguments=("/usr/bin/true",), principal="root"
    )
    assert "launch_profile" not in original.model_dump()
    assert (
        original.model_dump_json()
        == '{"schema_version":1,"label":"example","program":"/usr/bin/true","arguments":["/usr/bin/true"],"principal":"root","run_at_load":false}'
    )
    selected = original.model_copy(update={"launch_profile": "root_xpcproxy_v11"})
    assert selected.content_seed != original.content_seed


@pytest.mark.parametrize(
    "lost_return", [False, True], ids=["before-binding", "binding-lost-return"]
)
def test_binding_retry_reuses_the_completed_native_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lost_return: bool
) -> None:
    from evidenceforge.generation.checkpoints.activity_head import _assert_transient_empty
    from evidenceforge.generation.checkpoints.errors import CheckpointError

    engine, bundle, request = _setup(tmp_path, monkeypatch)
    original = engine.lifecycle_authority.publish_existing_process_service

    def interrupted(process: object, token: object) -> None:
        if lost_return:
            original(process, token)
        else:
            bundle.services.cancel_service_publication(token)
        raise OSError("invented binding cut")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(
                engine.lifecycle_authority, "publish_existing_process_service", interrupted
            )
            with pytest.raises(OSError, match="invented binding cut"):
                bundle.execute(request("activate", 63))
        with pytest.raises(CheckpointError, match="_macos_finder_startups"):
            _assert_transient_empty(engine.activity_generator)
        with pytest.raises(StateError, match="pending Mac startup"):
            bundle.execute(request("unload", 64))
        process = bundle.execute(request("activate", 63)).process
        assert (
            process.execution_ordinal == 2 and not engine.activity_generator._macos_finder_startups
        )
        bundle.execute(request("exit", 65))
        bundle.execute(request("unload", 66))
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.expected_forks == 1 and census.expected_execs == 2
        assert bundle.services.service_preparation_census().publication_reservations == 0
    finally:
        engine._close_emitters()


@pytest.mark.slow
@pytest.mark.parametrize("phase", [0, 1, 2], ids=["fork-launcher", "setsid", "target"])
@pytest.mark.parametrize("cut", ["before-commit", "lost-return", "source-release"])
def test_each_native_job_phase_resumes_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: int, cut: str
) -> None:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    engine, bundle, request = _setup(tmp_path, monkeypatch)
    original, release = (
        PreparedActionCohortCapability.commit_no_fail,
        ExactPublicationBatch.release_no_fail,
    )
    attempts = 0

    def interrupted(capability: object) -> object:
        nonlocal attempts
        current = attempts
        attempts += 1
        if current == phase and cut == "before-commit":
            raise OSError("invented native phase cut")
        result = original(capability)
        if current == phase and cut == "lost-return":
            raise OSError("invented native phase cut")
        return result

    def interrupted_release(batch: object) -> None:
        nonlocal attempts
        current = attempts
        attempts += 1
        if current == phase:
            raise OSError("invented native phase cut")
        release(batch)

    try:
        with monkeypatch.context() as fault:
            fault.setattr(
                ExactPublicationBatch, "release_no_fail", interrupted_release
            ) if cut == "source-release" else fault.setattr(
                PreparedActionCohortCapability, "commit_no_fail", interrupted
            )
            with pytest.raises(OSError, match="invented native phase cut"):
                bundle.execute(request("activate", 63))
        engine.dispatcher.drain_exact_projection_recoveries()
        result = bundle.execute(request("activate", 63))
        assert result.process.execution_ordinal == 2
        bundle.execute(request("exit", 65))
        bundle.execute(request("unload", 66))
        engine.dispatcher.assert_exact_projection_recoveries_drained()
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.expected_forks == 1 and census.expected_execs == 2
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("explicit_profile", [False, True], ids=["automatic", "explicit"])
def test_loaded_native_job_and_post_exec_group_survive_checkpoint_hydration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit_profile: bool
) -> None:
    from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng, stable_uuid

    outputs = []
    for hydrate in (False, True):
        with generation_seed_scope(372):
            reset_thread_rng()
            root = tmp_path / ("restored" if hydrate else "plain")
            engine, bundle, request = _setup(root, monkeypatch, explicit_profile=explicit_profile)
            try:
                process = bundle.execute(request("activate", 63)).process
                before = engine.lifecycle_registry.get_process(process.object_id)
                if hydrate:
                    engine.lifecycle_registry.prune_action_cohort_receipt_authorities()
                    state_head = _capture_head(engine.state_manager)
                    lifecycle_head = _capture(engine.lifecycle_registry)
                    _restore_head(engine.state_manager, state_head)
                    _restore(engine.lifecycle_registry, lifecycle_head)
                assert (
                    engine.state_manager.get_process_identity(process.hostname, process.pid)
                    == process
                )
                assert engine.lifecycle_registry.get_process(process.object_id) == before
                owner = engine.lifecycle_registry.service_for_logical_at(
                    process.hostname,
                    stable_uuid(
                        "macos-launchd-system-job",
                        bundle.deployments.host_deployment(process.hostname).hostname,
                        "org.example.native-job",
                    ),
                    process.execution_started_at,
                )
                assert owner.process_group == process.job_control
                definition = owner.identity.launchd_job
                assert definition.launch_profile == (
                    "root_xpcproxy_v11" if explicit_profile else None
                )
                assert definition.launch_environment == (
                    ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C") if explicit_profile else None
                )
                bundle.execute(request("exit", 65))
                bundle.execute(request("unload", 66))
                engine._finalize_macos_process_coverage()
                census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
                assert census.complete and census.expected_forks == 1 and census.expected_execs == 2
            finally:
                engine._close_emitters()
            outputs.append(
                [path.read_bytes() for path in sorted(root.rglob("macos_endpoint_security.ndjson"))]
            )
    assert outputs[0] and outputs[0] == outputs[1]
