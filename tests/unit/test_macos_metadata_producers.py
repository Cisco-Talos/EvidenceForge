# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.events.macos_exec_descriptors import MacosExecDescriptorObservation
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.activity.macos_execution_metadata import (
    load_macos_execution_metadata_profile,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationBuilder,
    ProcessMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import resolve_time_window
from tests.unit.test_macos_installed_provisioning import _compile, _deployments, _scenario


@dataclass(frozen=True)
class _Fixture:
    producer: MacosExecutionMetadataProducer
    state: StateManager
    root: ProcessIdentity
    start: datetime
    end: datetime


@pytest.fixture
def modeled() -> _Fixture:
    scenario = _scenario()
    start, end = resolve_time_window(scenario.time_window)
    registry = _deployments(scenario)
    installed = _compile(scenario, registry)
    provider = MacosExecutionMetadataProducer(
        installed.filesystem,
        IdentityDirectory.from_scenario(scenario),
        load_macos_execution_metadata_profile(),
        window_start=start,
        window_end=end,
    )
    state = StateManager()
    state.set_current_time(start)
    metadata = provider.deployed_launch(
        "MAC-01", "root", at=start, path="/sbin/launchd", kind="system"
    )
    root = state.plan_process_materialization(
        system="MAC-01",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        arguments=("/sbin/launchd",),
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=start,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
        macos_terminal="absent",
        new_posix_session=True,
        macos_standard_io="null",
        environment=metadata.environment,
        execution_directory=metadata.directory,
        exec_image=metadata.image,
        exec_script=metadata.script,
    )
    state.materialize_process(root)
    return _Fixture(provider, state, root.identity, start, end)


def _terminal(
    fixture: _Fixture,
    *,
    seconds: int = 1,
    builder: ActionCohortMaterializationBuilder | None = None,
) -> ProcessMaterializationPlan:
    at = fixture.start + timedelta(seconds=seconds)
    metadata = fixture.producer.deployed_launch(
        "MAC-01", "alex", at=at, path="/bin/zsh", kind="user"
    )
    arguments = dict(
        system="MAC-01",
        parent_pid=1,
        image="/bin/zsh",
        command_line="-zsh",
        arguments=("-zsh",),
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=at,
        credentials=PosixProcessCredentials(501, 501, 20, 20),
        new_posix_session=True,
        macos_terminal=fixture.producer.profile.terminal,
        macos_standard_io="terminal",
        environment=metadata.environment,
        execution_directory=metadata.directory,
        exec_image=metadata.image,
        exec_script=metadata.script,
    )
    return (
        builder.plan_process(**arguments)
        if builder is not None
        else fixture.state.plan_process_materialization(**arguments)
    )


def test_terminal_allocation_and_descriptors_share_birth_rollback_and_exact_retry(
    modeled: _Fixture,
) -> None:
    state = modeled.state
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    process = _terminal(modeled, builder=builder)
    plan = builder.seal()
    assert state.materialization_digest() == before
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        observation = state.known_macos_terminal(
            process.identity.job_control.session, process.identity.started_at
        )
        assert observation.native_path == "/dev/ttys000"
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    observation = state.known_macos_terminal(
        process.identity.job_control.session, process.identity.started_at
    )
    assert observation.metadata.uid == 501 and observation.metadata.gid == 20
    assert observation.metadata.mode & 0o170000 == 0o020000
    table = state.process_descriptors_at(process.identity, event_time=process.identity.started_at)
    assert table.native_last_fd == 2
    assert len({item.object_id for item in table.bindings}) == 1
    assert MacosExecDescriptorObservation.from_modeled_table(table).last_fd == 2


def test_staged_terminals_allocate_distinct_slots_and_reuse_only_after_canonical_watermark(
    modeled: _Fixture,
) -> None:
    state = modeled.state
    builder = state.begin_action_cohort_materialization()
    first = _terminal(modeled, builder=builder)
    second = _terminal(modeled, builder=builder, seconds=2)
    state.materialize_action_cohort(builder.seal())
    at = modeled.start + timedelta(seconds=3)
    a = state.known_macos_terminal(first.identity.job_control.session, at)
    b = state.known_macos_terminal(second.identity.job_control.session, at)
    assert (a.native_path, b.native_path) == ("/dev/ttys000", "/dev/ttys001")
    assert a.metadata.inode != b.metadata.inode
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(first.identity, end_time=at)
    state.materialize_action_cohort(builder.seal())
    assert state.known_macos_terminal(first.identity.job_control.session, at) == a
    assert (
        state.known_macos_terminal(
            first.identity.job_control.session, at + timedelta(microseconds=1)
        )
        is None
    )
    third = _terminal(modeled, seconds=4)
    state.materialize_process(third)
    assert (
        state.known_macos_terminal(
            third.identity.job_control.session, third.identity.started_at
        ).native_path
        == "/dev/ttys002"
    )
    state.advance_pid_allocation_watermark(at + timedelta(microseconds=1))
    fourth = _terminal(modeled, seconds=5)
    state.materialize_process(fourth)
    reused = state.known_macos_terminal(
        fourth.identity.job_control.session, fourth.identity.started_at
    )
    assert reused.native_path == a.native_path and reused.metadata.inode != a.metadata.inode


def test_collection_producer_observes_exact_session_device_and_rejects_false_absence(
    modeled: _Fixture,
) -> None:
    process = _terminal(modeled)
    modeled.state.materialize_process(process)
    owner = ESCollectionActionOwner(modeled.state, ESCollectorRegistry())
    owner.declare_complete_membership(
        ESClientMembershipCoverage(
            hostname="MAC-01", known_from=modeled.start, known_until=modeled.end
        )
    )
    observation = owner.observe_process_collection(
        process.identity, observed_at=process.identity.started_at
    )
    assert not observation.is_es_client and observation.terminal.native_path == "/dev/ttys000"
    with pytest.raises(StateError, match="terminal"):
        owner.validate_client_observation(replace(observation, terminal="absent"))
    root = owner.observe_process_collection(modeled.root, observed_at=process.identity.started_at)
    assert root.terminal == "absent"


def test_native_pipe_allocation_is_atomic_shared_by_fork_and_restored_without_reuse(
    modeled: _Fixture,
) -> None:
    state = modeled.state
    plan = _terminal(modeled)
    state.materialize_process(plan)
    process = plan.identity
    before = state.materialization_digest()
    at = modeled.start + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    table = builder.open_macos_pipe(
        process, at=at, read_fd=5, write_fd=6, first_pipe_id=modeled.producer.profile.first_pipe_id
    )
    sealed = builder.seal()
    assert state.materialization_digest() == before
    with state.prepared_action_cohort_materialization(sealed) as claim:
        claim.certify_composite_commit(claim.expected_result)
        claim.apply_provisional()
    assert state.materialization_digest() == before
    state.materialize_action_cohort(sealed)
    native_id = table.bindings[-1].native_pipe_id
    assert native_id == table.bindings[-2].native_pipe_id == modeled.producer.profile.first_pipe_id
    at += timedelta(seconds=1)
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        process,
        forked_at=at,
        execution_directory=modeled.producer.directory(
            "MAC-01", process.execution_directory.native_path, at
        ),
    )
    state.materialize_action_cohort(builder.seal())
    inherited = state.process_descriptors_at(child.identity, event_time=at)
    assert inherited.bindings == table.bindings
    recovered = StateManager()
    _restore_head(recovered, _capture_head(state))
    assert recovered.process_descriptors_at(child.identity, event_time=at) == inherited
    for manager in (state, recovered):
        builder = manager.begin_action_cohort_materialization()
        later = builder.open_macos_pipe(
            child.identity,
            at=at + timedelta(seconds=1),
            read_fd=8,
            write_fd=9,
            first_pipe_id=modeled.producer.profile.first_pipe_id,
        )
        manager.materialize_action_cohort(builder.seal())
        assert later.bindings[-1].native_pipe_id == native_id + 1


def test_exec_producer_uses_current_directory_environment_and_close_on_exec_owner(
    modeled: _Fixture,
) -> None:
    state = modeled.state
    process = _terminal(modeled)
    state.materialize_process(process)
    at = modeled.start + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    builder.open_macos_pipe(
        process.identity,
        at=at,
        read_fd=8,
        write_fd=9,
        first_pipe_id=modeled.producer.profile.first_pipe_id,
        close_on_exec=True,
    )
    state.materialize_action_cohort(builder.seal())
    at += timedelta(seconds=1)
    builder = state.begin_action_cohort_materialization()
    binary = modeled.producer._filesystem.deployed_binary("MAC-01", "/bin/zsh", "alex")
    prepared = modeled.producer.plan_exec(
        builder,
        state,
        process.identity,
        at=at,
        image="/bin/zsh",
        requested_path="/bin/zsh",
        arguments=("/bin/zsh", "-f"),
        binary=binary,
    )
    assert prepared.process.environment == process.identity.environment
    assert prepared.process.exec_script == MacosExecScript()
    assert prepared.process.exec_image.dyld_exec_path == "/bin/zsh"
    assert prepared.process.execution_directory.observed_at == at
    assert prepared.descriptors.last_fd == 2 and len(prepared.descriptors.descriptors) == 3
    state.materialize_action_cohort(builder.seal())
    assert (
        state.known_macos_terminal(prepared.process.job_control.session, at).native_path
        == "/dev/ttys000"
    )


@pytest.mark.parametrize("damage", ["slots", "counter", "pipe_counter", "session"])
def test_checkpoint_rejects_corrupt_native_ownership_before_state_mutation(
    modeled: _Fixture, damage: str
) -> None:
    state = modeled.state
    process = _terminal(modeled)
    state.materialize_process(process)
    builder = state.begin_action_cohort_materialization()
    builder.open_macos_pipe(
        process.identity,
        at=modeled.start + timedelta(seconds=2),
        read_fd=4,
        write_fd=5,
        first_pipe_id=modeled.producer.profile.first_pipe_id,
    )
    state.materialize_action_cohort(builder.seal())
    document = loads(_capture_head(state))
    field = {
        "slots": "_macos_terminal_slots",
        "counter": "_macos_terminal_ordinals",
        "pipe_counter": "_macos_pipe_counters",
        "session": "_macos_terminal_sessions",
    }[damage]
    document["simple"][field] = encode_state_value({})
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError):
        _restore_head(restored, dumps(document))
    assert restored.materialization_digest() == before


def test_legacy_descriptors_keep_unknown_native_extent_and_pipe_identity() -> None:
    from tests.unit.test_process_execution_state import _START

    binding = decode_state_value(
        ["record", "macos-descriptor-binding-v1", [3, "pipe", "old-object", False]]
    )
    table = decode_state_value(
        [
            "record",
            "macos-descriptor-table-v1",
            ["MAC-A", encode_state_value(_START), encode_state_value((binding,))],
        ]
    )
    assert binding.native_pipe_id is None and table.native_last_fd is None
    with pytest.raises(ValueError, match="known complete"):
        MacosExecDescriptorObservation.from_modeled_table(table)


def test_engine_terminal_chain_uses_produced_metadata_and_restores_actual_device(
    tmp_path: Path,
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "run", generation_seed=318)
    try:
        engine._initialize()
        generator = engine.activity_generator
        system = next(
            item for item in engine.scenario.environment.systems if item.hostname == "MAC-01"
        )
        user = next(item for item in engine.scenario.environment.users if item.username == "alex")
        at = engine.start_time + timedelta(minutes=10)
        logon = generator.generate_logon(user, system, at)
        shell_pid = generator.ensure_macos_session_shell(
            user, system, logon, at + timedelta(seconds=30)
        )
        shell = engine.state_manager.get_process_identity(system.hostname, shell_pid)
        assert shell.environment and "HOME=/Users/alex" in shell.environment
        assert shell.execution_directory.native_path == "/Users/alex"
        assert shell.exec_image.cpu_subtype == engine.macos_execution_metadata.profile.cpu_subtype
        assert shell.exec_script == MacosExecScript()
        terminal = engine.state_manager.known_macos_terminal(
            shell.job_control.session, shell.started_at
        )
        assert terminal.native_path == "/dev/ttys000"
        recovered = StateManager()
        _restore_head(recovered, _capture_head(engine.state_manager))
        assert (
            recovered.known_macos_terminal(shell.job_control.session, shell.started_at) == terminal
        )
        root = engine.state_manager.get_process_identity(system.hostname, 1)
        assert (
            engine.state_manager.known_macos_terminal(root.job_control.session, shell.started_at)
            == "absent"
        )
    finally:
        engine._close_emitters()


def test_unknown_launch_or_foreign_directory_is_not_filled_with_defaults(modeled: _Fixture) -> None:
    with pytest.raises(StateError, match="exact local"):
        modeled.producer.deployed_launch(
            "MAC-01", "unknown", at=modeled.start, path="/bin/zsh", kind="user"
        )
    with pytest.raises(StateError, match="provisioned"):
        modeled.producer.directory("MAC-01", "/unprovisioned/path", modeled.start)
    with pytest.raises(StateError, match="exact local"):
        modeled.producer.deployed_launch(
            "MAC-01", "alex", at=modeled.start, path="/bin/zsh", kind="system"
        )


def test_system_job_metadata_retains_canonical_process_hostname(tmp_path: Path) -> None:
    from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
    from evidenceforge.generation.actions.macos_persistence import (
        MacosPersistenceActionBundle,
        MacosPersistenceRequest,
    )
    from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils import load_yaml

    scenario = Scenario.model_validate(
        load_yaml(Path("scenarios/macos-persistence-example/scenario.yaml"))
    )
    engine = GenerationEngine(scenario, tmp_path / "job", generation_seed=318)
    try:
        engine._initialize()
        system = next(
            item for item in engine.scenario.environment.systems if item.hostname == "MAC-01"
        )
        caller = engine.state_manager.get_process_identity(system.hostname, 1)
        assert engine.deployment_registry.host_deployment(system.hostname).hostname == "mac-01"
        bundle = MacosPersistenceActionBundle(
            state=engine.state_manager,
            lifecycle=engine.lifecycle_registry,
            authority=engine.lifecycle_authority,
            dispatcher=engine.dispatcher,
            deployments=engine.deployment_registry,
            content=RuntimeContentIdentityManager(engine.dispatcher.local_artifact_registry),
            metadata_provider=engine.macos_execution_metadata,
        )
        definition = LaunchdSystemJobSpec(
            label="org.example.metadata",
            program="/bin/zsh",
            arguments=("/bin/zsh",),
            principal="root",
        )
        for offset, operation in enumerate(("write", "bootstrap", "activate"), 1):
            result = bundle.execute(
                MacosPersistenceRequest(
                    caller=caller,
                    host=engine.activity_generator._build_host_context(system),
                    timestamp=engine.start_time + timedelta(seconds=offset),
                    action_id=f"metadata-job-{operation}",
                    operation=operation,
                    label=definition.label,
                    path="/Library/LaunchDaemons/org.example.metadata.plist"
                    if operation != "activate"
                    else None,
                    definition=definition if operation == "write" else None,
                    size_bytes=512 if operation == "write" else None,
                )
            )
        process = result.process
        assert process.hostname == caller.hostname == "MAC-01"
        assert process.execution_directory.hostname == process.hostname
        assert process.execution_directory.observed_at == process.started_at
        assert process.execution_directory.native_path == "/"
        assert process.environment and "USER=root" in process.environment
        assert (
            engine.state_manager.known_macos_terminal(
                process.job_control.session, process.started_at
            )
            == "absent"
        )
    finally:
        engine._close_emitters()


def test_known_native_fields_cannot_be_replaced_by_conflicting_source_observations(
    modeled: _Fixture,
) -> None:
    plan = _terminal(modeled)
    modeled.state.materialize_process(plan)
    at = modeled.start + timedelta(seconds=2)
    builder = modeled.state.begin_action_cohort_materialization()
    table = builder.open_macos_pipe(
        plan.identity,
        at=at,
        read_fd=8,
        write_fd=9,
        first_pipe_id=modeled.producer.profile.first_pipe_id,
    )
    modeled.state.materialize_action_cohort(builder.seal())
    observation = MacosExecDescriptorObservation.from_modeled_table(table)
    with pytest.raises(ValueError, match="extent"):
        replace(observation, last_fd=17)
    with pytest.raises(ValueError, match="pipe identity"):
        replace(
            observation,
            descriptors=(
                *observation.descriptors[:-1],
                replace(observation.descriptors[-1], pipe_id=12345),
            ),
        )
    builder = modeled.state.begin_action_cohort_materialization()
    forged = replace(
        table,
        observed_at=at + timedelta(seconds=1),
        bindings=tuple(
            replace(item, native_pipe_id=None) if item.kind == "pipe" else item
            for item in table.bindings
        ),
    )
    with pytest.raises(StateError, match="Native pipe identity"):
        builder.record_macos_descriptors(plan.identity, table=forged)


def test_pipe_creation_failure_consumes_neither_fd_nor_native_id(modeled: _Fixture) -> None:
    plan = _terminal(modeled)
    modeled.state.materialize_process(plan)
    before = modeled.state.materialization_digest()
    builder = modeled.state.begin_action_cohort_materialization()
    with pytest.raises(ValueError, match="unused"):
        builder.open_macos_pipe(
            plan.identity,
            at=modeled.start + timedelta(seconds=2),
            read_fd=8,
            write_fd=1,
            first_pipe_id=modeled.producer.profile.first_pipe_id,
        )
    assert modeled.state.materialization_digest() == before
    table = builder.open_macos_pipe(
        plan.identity,
        at=modeled.start + timedelta(seconds=2),
        read_fd=8,
        write_fd=9,
        first_pipe_id=modeled.producer.profile.first_pipe_id,
    )
    modeled.state.materialize_action_cohort(builder.seal())
    assert table.bindings[-1].native_pipe_id == modeled.producer.profile.first_pipe_id


def test_frozen_execution_profile_scopes_and_old_inputs_keep_unknown_policy(tmp_path: Path) -> None:
    from evidenceforge.composition.compiler import build_management_effective_config
    from evidenceforge.config.provider import effective_config_scope

    defaults = build_management_effective_config(tmp_path)
    path = tmp_path / ".eforge/config/activity/macos_execution_metadata.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("terminal: {permissions: 400}\ncpu_subtype: 2\n")
    selected = build_management_effective_config(tmp_path)
    with effective_config_scope(selected):
        original = load_macos_execution_metadata_profile()
        assert original.terminal.permissions == 400 and original.cpu_subtype == 2
        with effective_config_scope(defaults):
            assert load_macos_execution_metadata_profile().cpu_subtype == 0
        assert load_macos_execution_metadata_profile() is original
    old = defaults.model_copy(
        update={
            "packaged_defaults": {
                name: value
                for name, value in defaults.packaged_defaults.items()
                if name != "activity/macos_execution_metadata.yaml"
            }
        }
    )
    with effective_config_scope(old):
        assert load_macos_execution_metadata_profile() is None


def test_shebang_intent_produces_exact_argv_and_retains_script_with_interpreter() -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.events.macos_exec_script import MacosShebangExecutionIntent
    from evidenceforge.generation.activity import ActivityGenerator
    from tests.unit.test_macos_exec_script import _script
    from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user
    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable, _manager

    state = StateManager()
    _seed_launchd(state)
    content = _manager()
    image = replace(_executable(), hostname="MAC-TEST", principal="alex")
    descriptor, record = _script(content, "MAC-TEST")
    _publish(content, image, _TIME)
    _publish(content, descriptor, _TIME)
    dispatcher = EventDispatcher(
        state,
        {},
        local_artifact_registry=content.registry,
        output_end_time=_TIME + timedelta(days=7),
    )
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    intent = MacosShebangExecutionIntent(
        MacosExecScript.from_runtime_record(record),
        image.native_path,
        ("--literal",),
        ("an argument with spaces", ""),
    )
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    pid = generator.generate_macos_shebang_process(
        user, system, _TIME + timedelta(seconds=30), logon, parent_pid=1, intent=intent
    )
    identity = state.get_process_identity(system.hostname, pid)
    assert identity.exec_script == intent.script
    assert identity.arguments == (
        image.native_path,
        "--literal",
        descriptor.native_path,
        "an argument with spaces",
        "",
    )
    assert content.registry.census().active_leases == 2


def test_terminal_reservation_can_follow_an_independent_future_planned_session(
    modeled: _Fixture,
) -> None:
    later = _terminal(modeled, seconds=10)
    modeled.state.materialize_process(later)
    earlier = _terminal(modeled, seconds=2)
    modeled.state.materialize_process(earlier)
    first = modeled.state.known_macos_terminal(
        later.identity.job_control.session, later.identity.started_at
    )
    second = modeled.state.known_macos_terminal(
        earlier.identity.job_control.session, earlier.identity.started_at
    )
    assert first.native_path != second.native_path


def test_setsid_detaches_controlling_terminal_without_closing_inherited_streams(
    modeled: _Fixture,
) -> None:
    process = _terminal(modeled)
    state = modeled.state
    state.materialize_process(process)
    at = modeled.start + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        process.identity,
        forked_at=at,
        execution_directory=modeled.producer.directory(
            "MAC-01", process.identity.execution_directory.native_path, at
        ),
    )
    state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    after = builder.change_posix_job_control(
        child.identity, operation="setsid", changed_at=at + timedelta(seconds=1)
    )
    plan = builder.seal()
    with state.prepared_action_cohort_materialization(plan) as claim:
        claim.certify_composite_commit(claim.expected_result)
        claim.apply_provisional()
        assert (
            state.known_macos_terminal(after.job_control.session, at + timedelta(seconds=1))
            == "absent"
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert (
        state.known_macos_terminal(after.job_control.session, at + timedelta(seconds=1)) == "absent"
    )
    old_table = state.process_descriptors_at(child.identity, event_time=at)
    new_table = state.process_descriptors_at(after, event_time=at + timedelta(seconds=1))
    assert new_table.bindings == old_table.bindings


def test_validation_policy_is_explicit_and_does_not_create_static_signer_facts(
    modeled: _Fixture,
) -> None:
    from evidenceforge.events.macos_runtime import MacosImageSecurity

    binary = replace(
        modeled.producer._filesystem.deployed_binary("MAC-01", "/bin/zsh", "alex"),
        code_signature=None,
    )
    expected = MacosImageSecurity(0x24000001, True, 1)
    assert modeled.producer.image_security(binary) == expected
    assert binary.code_signature is None
    metadata = modeled.producer.deployed_launch(
        "MAC-01", "alex", at=modeled.start, path="/bin/zsh", kind="user"
    )
    assert metadata.image_security == expected
    assert modeled.producer.image_security(None) is None
    unlisted = replace(binary, key=replace(binary.key, artifact_name="unlisted"))
    assert modeled.producer.image_security(unlisted) is None
    assert modeled.producer.image_security(replace(binary, mach_o_image=None)) is None
    old = modeled.producer.profile.model_dump()
    old.pop("code_validation")
    from evidenceforge.config.schemas import MacosExecutionMetadataProfile

    legacy = MacosExecutionMetadataProducer(
        modeled.producer._filesystem,
        IdentityDirectory.from_scenario(_scenario()),
        MacosExecutionMetadataProfile.model_validate(old),
        window_start=modeled.start,
        window_end=modeled.end,
    )
    assert legacy.image_security(binary) is None


def test_runtime_validation_decision_is_bound_to_exact_content_and_exec(modeled: _Fixture) -> None:
    from evidenceforge.events.content_identity import LocalArtifactBinaryIdentity
    from evidenceforge.events.macos_runtime import MacosCodeValidationDecision, MacosImageSecurity

    installed = modeled.producer._filesystem.deployed_binary("MAC-01", "/bin/zsh", "alex")
    runtime = LocalArtifactBinaryIdentity(
        artifact_version_id="invented-validation-artifact-v1",
        content_id=installed.content_id,
        digests=installed.digests,
        platform="macos",
        architecture="arm64",
        artifact_name="invented-worker",
        mach_o_image=installed.mach_o_image,
    )
    decision = MacosCodeValidationDecision(runtime.content_id, MacosImageSecurity(3, False, 7))
    assert modeled.producer.image_security(runtime) is None
    assert modeled.producer.image_security(runtime, validation=decision) == decision.security
    with pytest.raises(StateError, match="exact selected"):
        modeled.producer.image_security(runtime, validation=replace(decision, content_id="other"))
    birth = _terminal(modeled)
    modeled.state.materialize_process(birth)
    builder = modeled.state.begin_action_cohort_materialization()
    after = modeled.producer.plan_exec(
        builder,
        modeled.state,
        birth.identity,
        at=modeled.start + timedelta(seconds=2),
        image="/tmp/invented-worker",
        requested_path="/tmp/invented-worker",
        arguments=("/tmp/invented-worker",),
        binary=runtime,
        validation=decision,
    ).process
    plan = builder.seal()
    before = modeled.state.materialization_digest()
    with modeled.state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            modeled.state.get_process_identity(after.hostname, after.pid).image_security
            == decision.security
        )
    assert modeled.state.materialization_digest() == before
    modeled.state.materialize_action_cohort(plan)
    restored = StateManager()
    _restore_head(restored, _capture_head(modeled.state))
    assert (
        restored.get_process_identity(after.hostname, after.pid).image_security == decision.security
    )
    builder = restored.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=modeled.start + timedelta(seconds=3))
    restored.materialize_action_cohort(builder.seal())
    assert child.identity.image_security == decision.security


@pytest.mark.parametrize("damage", ["platform", "category", "invalid", "duplicates"])
def test_execution_validation_policy_rejects_contradictions(modeled: _Fixture, damage: str) -> None:
    from pydantic import ValidationError

    from evidenceforge.config.schemas import MacosExecutionMetadataProfile

    raw = modeled.producer.profile.model_dump()
    rule = raw["code_validation"][0]
    if damage == "platform":
        rule["is_platform_binary"] = False
    elif damage == "category":
        rule["validation_category"] = 6
    elif damage == "invalid":
        rule["codesigning_flags"] &= ~1
    else:
        raw["code_validation"] = (*raw["code_validation"], dict(rule))
    with pytest.raises(ValidationError, match="coherent|disjoint"):
        MacosExecutionMetadataProfile.model_validate(raw)
