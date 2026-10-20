# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Synthetic installed-file production uses frozen deployment and identity owners."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config import get_activity_directory
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.schemas import MacosInstalledFileProfile
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.activity import macos_installed_files as profiles
from evidenceforge.generation.deployment_compiler import (
    compile_deployment_registry,
    compile_native_deployment_registry,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_installed_provisioning import (
    MacosInstalledProvisioning,
    compile_macos_installed_provisioning,
)
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml
from evidenceforge.utils.rng import generation_seed_scope
from evidenceforge.utils.time import resolve_time_window

_SUBPATH = "activity/macos_installed_files.yaml"


def _scenario(*, two_macs: bool = False) -> Scenario:
    data = load_yaml(Path("scenarios/macos-workstation-example/mixed-fleet.yaml"))
    if two_macs:
        other = deepcopy(data["environment"]["systems"][0])
        other.update(hostname="MAC-02", ip="192.0.2.11")
        data["environment"]["systems"].append(other)
        data["environment"]["network"]["segments"][0]["systems"].append("MAC-02")
    return Scenario.model_validate(data)


def _deployments(scenario: Scenario) -> DeploymentContentRegistry:
    return compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))


def _process(
    deployments: DeploymentContentRegistry,
    scenario: Scenario,
    host: str,
    path: str,
    *,
    principal: str = "alex",
) -> ProcessIdentity:
    start, _ = resolve_time_window(scenario.time_window)
    binary = deployments.resolve_binary(host, path, "macos", principal=principal)
    assert binary is not None
    return ProcessIdentity(
        host,
        "invented-observer",
        100,
        1,
        path,
        path,
        principal,
        "invented-login",
        start,
        "invented-lifetime",
        executable_version=ProcessExecutableVersion.from_binary(binary),
    )


def _compile(
    scenario: Scenario,
    deployments: DeploymentContentRegistry,
    identities: IdentityDirectory | None = None,
) -> MacosInstalledProvisioning | None:
    start, end = resolve_time_window(scenario.time_window)
    return compile_macos_installed_provisioning(
        scenario,
        deployments,
        identities or IdentityDirectory.from_scenario(scenario),
        window_start=start - timedelta(hours=1),
        window_end=end,
    )


def test_provisioning_shares_binary_size_and_build_time_but_keeps_local_objects_distinct() -> None:
    scenario = _scenario(two_macs=True)
    deployments = _deployments(scenario)
    compiled = _compile(scenario, deployments)
    assert compiled.provisioned_files > 100 and not compiled.unavailable
    first = _process(deployments, scenario, "MAC-01", "/bin/zsh")
    second = _process(deployments, scenario, "MAC-02", "/bin/zsh")
    at = first.started_at
    before = compiled.filesystem.observe(deployments, first, observed_at=at)
    after = compiled.filesystem.observe(deployments, second, observed_at=at)
    assert before.binary == after.binary
    assert before.metadata.size_bytes == after.metadata.size_bytes
    assert before.metadata.modified == after.metadata.modified
    assert before.metadata.file_object_id != after.metadata.file_object_id
    assert before.metadata.born != after.metadata.born
    assert before.metadata.mode == 0o100755
    assert before.metadata.uid == before.metadata.gid == 0
    assert before.metadata.allocated_blocks * 512 >= before.metadata.size_bytes
    assert before.metadata.allocated_blocks * 512 < before.metadata.size_bytes + 4096
    assert before.metadata.modified.seconds < before.metadata.born.seconds


def test_binary_size_survives_seed_changes_and_order_does_not_change_local_stat() -> None:
    scenario = _scenario(two_macs=True)
    deployments = _deployments(scenario)
    process = _process(deployments, scenario, "MAC-01", "/bin/zsh")
    with generation_seed_scope(17):
        first = _compile(scenario, deployments).filesystem.observe(
            deployments, process, observed_at=process.started_at
        )
        reordered = scenario.model_copy(deep=True)
        reordered.environment.systems.reverse()
        second = _compile(reordered, deployments).filesystem.observe(
            deployments, process, observed_at=process.started_at
        )
    with generation_seed_scope(91):
        other_seed = _compile(scenario, deployments).filesystem.observe(
            deployments, process, observed_at=process.started_at
        )
    assert first == second
    assert first.metadata.size_bytes == other_seed.metadata.size_bytes
    assert first.metadata.modified == other_seed.metadata.modified
    assert first.metadata.file_object_id != other_seed.metadata.file_object_id


def test_provisioning_respects_release_availability_compiled_from_the_catalog() -> None:
    from tests.unit.test_macos_code_signature import _application

    scenario = _scenario()
    application = _application()
    application.platforms["macos"].command_templates = [application.platforms["macos"].image_path]
    available = date(2026, 10, 19)
    application.platforms["macos"].available_from = available
    deployments = compile_deployment_registry(
        scenario,
        WorldModel(scenario, "example.test"),
        application_entries=(application,),
    )
    path = application.platforms["macos"].image_path
    process = _process(deployments, scenario, "MAC-01", path)
    binary = process.executable_version
    assert deployments.binary_available_from(binary.content_id) == available
    result = _compile(scenario, deployments)
    metadata = result.filesystem.observe(
        deployments, process, observed_at=process.started_at
    ).metadata
    floor = int(datetime(2026, 10, 19, tzinfo=UTC).timestamp())
    assert metadata.born.seconds >= floor and metadata.modified.seconds >= floor
    assert metadata.changed.seconds >= floor and metadata.accessed.seconds >= metadata.born.seconds


@pytest.mark.parametrize("bound", ["unknown", datetime(2026, 10, 19, tzinfo=UTC)])
def test_release_availability_requires_exact_existing_content_and_calendar_dates(
    bound: object,
) -> None:
    scenario = _scenario()
    deployments = _deployments(scenario)
    binary = deployments.resolve_binary("MAC-01", "/bin/zsh", "macos")
    content = "unknown" if bound == "unknown" else binary.content_id
    date_value = date(2026, 10, 19) if bound == "unknown" else bound
    with pytest.raises(ValueError, match="exact binary and calendar"):
        DeploymentContentRegistry(
            binary_releases=(binary,), binary_available_from=((content, date_value),)
        )


def test_user_installed_files_use_exact_local_uid_and_never_borrow_root() -> None:
    scenario = _scenario()
    deployments = _deployments(scenario)
    # Bind a known binary in an explicitly user-scoped installation.
    machine = deployments.installation_for_image("MAC-01", "/bin/zsh", "macos")
    profile_id = "invented-user-profile"
    user_installation = replace(
        machine,
        scope="user",
        principal="alex",
        user_profile_id=profile_id,
        image_paths=("/Users/alex/bin/zsh",),
    )
    binary = deployments.resolve_binary("MAC-01", "/bin/zsh", "macos")
    # The registry validates user profiles; use the profile already compiled for alex.
    user_profile = deployments.user_profile_for("MAC-01", "alex", "macos")
    assert user_profile is not None
    user_installation = replace(user_installation, user_profile_id=user_profile.profile_id)
    selected = DeploymentContentRegistry(
        binary_releases=(binary,),
        user_profiles=(user_profile,),
        installations=(user_installation,),
    )
    identities = IdentityDirectory.from_scenario(scenario)
    process = _process(selected, scenario, "MAC-01", "/Users/alex/bin/zsh")
    result = _compile(scenario, selected, identities)
    stat = result.filesystem.observe(selected, process, observed_at=process.started_at).metadata
    assert (stat.uid, stat.gid) == (501, 20)
    identities.macos_accounts.pop(("alex", "mac-01"))
    missing = _compile(scenario, selected, identities)
    assert missing.provisioned_files == 0
    assert len(missing.unavailable) == 1 and missing.unavailable[0].principal == "alex"
    with pytest.raises(StateError, match="no provisioned file"):
        missing.filesystem.observe(selected, process, observed_at=process.started_at)


def test_non_mac_fleets_do_not_load_a_mac_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    import evidenceforge.generation.macos_installed_provisioning as production

    scenario = _scenario()
    scenario.environment.systems[0].os = "Ubuntu 24.04"
    loader = Mock(side_effect=AssertionError("No Mac policy may be read for another platform"))
    monkeypatch.setattr(production, "load_macos_installed_file_profile", loader)
    assert _compile(scenario, DeploymentContentRegistry()) is None
    loader.assert_not_called()


def test_profile_overlay_is_frozen_and_nested_scopes_restore_their_cached_owner(
    tmp_path: Path,
) -> None:
    defaults = build_management_effective_config(tmp_path)
    path = tmp_path / ".eforge" / "config" / _SUBPATH
    path.parent.mkdir(parents=True)
    path.write_text(
        "permissions: 448\nlogical_size_bytes: {min: 12345, max: 12345}\nsize_median_bytes: 12345\n"
    )
    selected = build_management_effective_config(tmp_path)
    with effective_config_scope(selected):
        original = profiles.load_macos_installed_file_profile()
        assert original.permissions == 0o700
        with effective_config_scope(defaults):
            assert profiles.load_macos_installed_file_profile().permissions == 0o755
        assert profiles.load_macos_installed_file_profile() is original
    path.write_text("permissions: 511\n")
    with effective_config_scope(selected):
        scenario = _scenario()
        deployments = _deployments(scenario)
        process = _process(deployments, scenario, "MAC-01", "/bin/zsh")
        stat = (
            _compile(scenario, deployments)
            .filesystem.observe(deployments, process, observed_at=process.started_at)
            .metadata
        )
        assert stat.size_bytes == 12345 and stat.mode == 0o100700


def test_older_frozen_inputs_do_not_acquire_new_packaged_stat_policy(tmp_path: Path) -> None:
    defaults = build_management_effective_config(tmp_path)
    packaged = {
        name: value for name, value in defaults.packaged_defaults.items() if name != _SUBPATH
    }
    old = defaults.model_copy(update={"packaged_defaults": packaged})
    scenario = _scenario()
    deployments = _deployments(scenario)
    with effective_config_scope(old):
        assert profiles.load_macos_installed_file_profile() is None
        assert _compile(scenario, deployments) is None


@pytest.mark.parametrize(
    "change",
    [
        {"permissions": True},
        {"permissions": 0o100755},
        {"size_log_sigma": 0},
        {"size_log_sigma": True},
        {"size_median_bytes": 1},
        {"volume_device": {"min": 3, "max": 2}},
        {"allocation_unit_bytes": 513},
        {"allocation_policy": "compressed"},
    ],
)
def test_invalid_policy_is_rejected_before_allocating_files(change: dict[str, object]) -> None:
    data = yaml.safe_load((get_activity_directory() / "macos_installed_files.yaml").read_text())
    with pytest.raises(ValidationError):
        MacosInstalledFileProfile.model_validate(data | change)


def test_engine_lazily_prepares_once_using_the_runs_seed_after_configuration_scope_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import evidenceforge.generation.engine.core as core

    scenario = _scenario()
    engine = GenerationEngine(scenario, tmp_path, generation_seed=123)
    with pytest.raises(StateError, match="Initialize engine deployment"):
        _ = engine.macos_installed_provisioning
    # Supply the initialized production inputs without opening emitters or reading output.
    engine.start_time, engine.end_time = resolve_time_window(scenario.time_window)
    engine.warmup_start_time = engine.start_time - timedelta(hours=1)
    engine.deployment_registry = _deployments(engine.scenario)
    engine._identity_directory = IdentityDirectory.from_scenario(engine.scenario)
    original = core.compile_macos_installed_provisioning
    calls = 0

    def counted(*args: object, **kwargs: object) -> MacosInstalledProvisioning | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StateError("injected provisioning preparation failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(core, "compile_macos_installed_provisioning", counted)
    assert not engine._macos_installed_provisioning_ready
    with pytest.raises(StateError, match="injected provisioning"):
        _ = engine.macos_installed_provisioning
    assert not engine._macos_installed_provisioning_ready
    assert engine._macos_installed_provisioning is None
    with generation_seed_scope(999), ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: engine.macos_installed_provisioning, range(6)))
    assert calls == 2 and all(result is results[0] for result in results)
    process = _process(engine.deployment_registry, scenario, "MAC-01", "/bin/zsh")
    with (
        generation_seed_scope(123),
        effective_config_scope(engine.compiled_scenario.effective_config),
    ):
        expected = _compile(engine.scenario, engine.deployment_registry)
    assert results[0].filesystem.observe(
        engine.deployment_registry, process, observed_at=process.started_at
    ) == expected.filesystem.observe(
        engine.deployment_registry, process, observed_at=process.started_at
    )


def test_real_engine_checkpoint_rebuilds_previously_requested_installed_files(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.engine_head import GenerationEngineParticipant

    scenario = _scenario()
    first = GenerationEngine(scenario, tmp_path / "first", generation_seed=123)
    second = GenerationEngine(scenario, tmp_path / "second", generation_seed=123)
    try:
        with generation_seed_scope(123):
            first._initialize()
            observed = first.macos_installed_provisioning
            # The hourly baseline normally creates this empty journal before
            # the first checkpoint boundary; no DHCP activity ran in this fixture.
            first._dhcp_lease_state = {}
            seal = GenerationEngineParticipant(first).prepare_checkpoint(1)
            second._initialize()
            GenerationEngineParticipant(second).restore_checkpoint(seal.head.payload, ())
            # Production launch metadata now requests this deterministic owner during initialization.
            assert second._macos_installed_provisioning_ready
            rebuilt = second.macos_installed_provisioning
        process = _process(first.deployment_registry, scenario, "MAC-01", "/bin/zsh")
        expected = observed.filesystem.observe(
            first.deployment_registry, process, observed_at=process.started_at
        )
        actual = rebuilt.filesystem.observe(
            second.deployment_registry, process, observed_at=process.started_at
        )
        assert actual == expected
    finally:
        first._close_emitters()
        second._close_emitters()


@pytest.mark.slow
def test_scoped_generation_and_external_native_preparation_cannot_invert_locks(
    tmp_path: Path,
) -> None:
    script = """
from contextlib import contextmanager
from pathlib import Path
from threading import Event, Thread, current_thread
import evidenceforge.config.provider as provider
from tests.unit.test_macos_installed_provisioning import _scenario, _deployments
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.utils.time import resolve_time_window
from datetime import timedelta
import sys
engine = GenerationEngine(_scenario(), Path(sys.argv[1]))
engine.start_time, engine.end_time = resolve_time_window(engine.scenario.time_window)
engine.warmup_start_time = engine.start_time - timedelta(hours=1)
engine.deployment_registry = _deployments(engine.scenario)
engine._identity_directory = IdentityDirectory.from_scenario(engine.scenario)
original = provider.effective_config_scope
entered = Event()
values = []
@contextmanager
def watched(config):
    if current_thread().name == "outside":
        entered.set()
    with original(config):
        yield
provider.effective_config_scope = watched
with original(engine.compiled_scenario.effective_config):
    thread = Thread(target=lambda: values.append(engine.macos_installed_provisioning), name="outside", daemon=True)
    thread.start()
    assert entered.wait(5)
    inside = engine.macos_installed_provisioning
thread.join(5)
assert not thread.is_alive() and values == [inside]
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
