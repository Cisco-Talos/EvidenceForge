# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A shared Finder producer publishes the complete measured root-to-app chain."""

from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from evidenceforge.composition.compiler import compile_scenario
from evidenceforge.config import get_activity_directory
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import ProcessEventSpec, Scenario
from tests.unit.test_macos_installed_provisioning import _scenario

_APP = "/Applications/EForgeReference.app/Contents/MacOS/EForgeReference"


@pytest.mark.parametrize("complete", [False, True], ids=["explicit-partial", "complete-rejects"])
def test_unknown_boot_parent_wire_fact_keeps_both_execs_and_exposes_missing_fork(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    complete: bool,
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True, boot_policy=None, complete=complete)
    try:
        engine._initialize()
        generator = engine.activity_generator
        system, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        logon = generator.generate_logon(
            user,
            system,
            engine.start_time - timedelta(minutes=5),
            allow_local_session_reuse=False,
        )
        pid = generator.generate_process(
            user,
            system,
            engine.start_time + timedelta(minutes=2),
            logon,
            _APP,
            _APP,
            parent_pid=1,
            require_exact_parent=True,
            arguments=(_APP,),
            macos_launch_kind="finder",
            from_storyline=True,
        )
        assert (
            engine.state_manager.get_process_identity(system.hostname, pid).execution_ordinal == 2
        )
        if complete:
            with pytest.raises(StateError, match="Incomplete native macOS process coverage"):
                engine._finalize_macos_process_coverage()
        else:
            engine._finalize_macos_process_coverage()
            host = engine.dispatcher.macos_es_ingress.coverage.hosts[0]
            summary = host.process_census
            assert not summary.complete and summary.aggregate_births == 0
            assert summary.expected_forks == 1 and summary.published_forks == 0
            assert summary.expected_execs == summary.published_execs == 2
            assert any(
                row.reason == "boot_parent_token_unknown" and row.count == 1
                for row in host.observations
            )
    finally:
        engine._close_emitters()


def _finder_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    native: bool,
    boot_policy: str | None = "all_zero",
    complete: bool = True,
) -> GenerationEngine:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    if native:
        raw["output"]["logs"].append({"format": "macos_endpoint_security"})
        raw["macos_process_coverage"] = "complete" if complete else "partial"
    overlay = tmp_path / ".eforge/config/activity/application_catalog.yaml"
    overlay.parent.mkdir(parents=True)
    catalog = yaml.safe_load((get_activity_directory() / "application_catalog.yaml").read_text())
    overlay.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "default_deployment": catalog["default_deployment"],
                "applications": [
                    {
                        "id": application["id"],
                        "personas": ["developer"]
                        if application["id"] == "macos-reference-app"
                        else [],
                        "_replace": True,
                    }
                    for application in catalog["applications"]
                    if "macos" in application["platforms"] and "code" in application["categories"]
                ],
            }
        )
    )
    scenario = tmp_path / "invented-finder.yaml"
    # This is an invented no-parent export observation, pending separate reference
    # qualification. It does not change the production profile's unknown policy.
    from evidenceforge.config.schemas import MacosEndpointSecurityProfilesConfig
    from evidenceforge.generation.activity import macos_endpoint_security_profiles as profiles

    original_profiles = profiles.load_macos_endpoint_security_profiles

    def invented_profiles() -> MacosEndpointSecurityProfilesConfig:
        catalog = original_profiles()
        return catalog.model_copy(
            update={
                "profiles": tuple(
                    entry.model_copy(update={"boot_parent_token": boot_policy})
                    for entry in catalog.profiles
                )
            }
        )

    monkeypatch.setattr(profiles, "load_macos_endpoint_security_profiles", invented_profiles)
    scenario.write_text(yaml.safe_dump(raw, sort_keys=False))
    compiled = compile_scenario(scenario, project_root=tmp_path)
    engine = GenerationEngine(
        Scenario.model_validate(raw),
        tmp_path / "run",
        generation_seed=349,
        compiled_scenario=compiled,
    )
    engine._chronological_es_delivery = True
    return engine


@pytest.mark.parametrize("authored", [False, True], ids=["baseline-owner", "authored"])
@pytest.mark.parametrize("native", [False, True], ids=["filtered", "native"])
def test_finder_app_exec_and_known_exit_use_the_shared_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, authored: bool, native: bool
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=native)
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        system = next(s for s in engine.scenario.environment.systems if s.hostname == "MAC-01")
        user = next(u for u in engine.scenario.environment.users if u.username == "alex")
        # Pre-existing GUI login is outside the census; only this launch starts
        # in the lossless collection window. The in-window login gate is tested
        # separately and remains an explicit unresolved startup obligation.
        at = engine.start_time - timedelta(minutes=5)
        logon = engine.activity_generator.generate_logon(
            user, system, at, allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=10)
        if authored:
            result = engine._execute_typed_event(
                ProcessEventSpec(process_name=_APP, launch_method="finder", supplementary="none"),
                user,
                system,
                at,
                "Invented reference app",
                {"process"},
            )
            assert result["native_process_model"] == "gui_exec"
            pid = result["pid"]
        else:
            registry = engine.dispatcher.deployment_registry
            profile = registry.user_profile_for(system.hostname, user.username, "macos")
            assert (
                registry.count_user_application_assignments_for_category(profile.profile_id, "code")
                == 1
            )
            engine.activity_generator.execute_baseline_activity(user, system, at, "process_code")
            process = next(
                item
                for item in engine.state_manager.get_processes_for_session(logon)
                if item.image == _APP
            )
            pid = process.pid
        assert pid > 1
        process = engine.state_manager.get_process_identity(system.hostname, pid)
        assert process.image == _APP and process.execution_ordinal == 2
        assert process.initial_image == "/sbin/launchd"
        assert not engine.activity_generator._macos_finder_startups
        launcher_binary = engine.dispatcher.resolve_process_binary_identity(
            system.hostname, user.username, "/usr/libexec/xpcproxy", "macos"
        )
        assert engine.macos_execution_metadata.image_cpu_subtype(launcher_binary) == -2147483646
        assert type(launcher_binary.code_signature.entitlements) is tuple
        assert process.parent_pid == process.parentage.original_pid == 1
        assert process.job_control.pgid == pid and process.job_control.session.sid == 1
        assert process.arguments == (_APP,) and process.environment
        assert process.execution_directory.native_path == "/"
        assert process.credentials.audit_uid == process.credentials.real_uid
        engine.activity_generator.generate_process_termination(
            user,
            system,
            process.execution_started_at + timedelta(seconds=5),
            pid,
            _APP,
            logon_id=process.logon_id,
            expected_process=process,
            exit_outcome=PosixProcessExit(exit_code=0),
        )
        engine._finalize_macos_process_coverage()
        if native:
            coverage = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
            assert coverage.complete and coverage.aggregate_births == 0
            assert coverage.expected_forks == coverage.published_forks == 1
            assert coverage.expected_execs == coverage.published_execs == 2
    finally:
        engine._close_emitters()
    records = [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).process.audit_token.pid == pid
        or record.event_type == 11
        and record.event.fork.child.audit_token.pid == pid
    ]
    assert [record.event_type for record in records] == ([11, 9, 9, 15] if native else []), (
        engine.dispatcher.macos_es_ingress.coverage.model_dump()
    )
    if native:
        fork, launcher_exec, exec_record, exit_record = records
        assert fork.process.audit_token.pid == 1
        assert (
            fork.process.executable.path == fork.event.fork.child.executable.path == "/sbin/launchd"
        )
        assert launcher_exec.process.executable.path == "/sbin/launchd"
        assert launcher_exec.event.exec.target.executable.path == "/usr/libexec/xpcproxy"
        assert (
            launcher_exec.process.audit_token.euid
            == launcher_exec.event.exec.target.audit_token.euid
            == 0
        )
        assert launcher_exec.event.exec.image_cpusubtype == -2147483646
        assert launcher_exec.event.exec.entitlements == launcher_binary.code_signature.entitlements
        assert launcher_exec.event.exec.args[0] == "xpcproxy"
        assert launcher_exec.event.exec.env == ("XPC_FLAGS=0x2",)
        assert f"XPC_SERVICE_NAME={launcher_exec.event.exec.args[1]}" in exec_record.event.exec.env
        assert (
            launcher_exec.event.exec.target.audit_token.pidversion
            == exec_record.process.audit_token.pidversion
        )
        assert exec_record.process.executable.path == "/usr/libexec/xpcproxy"
        assert exec_record.process.signing_id == "com.apple.xpc.proxy"
        assert exec_record.process.codesigning_flags == 0x26015B11
        assert exec_record.event.exec.target.executable.path == _APP
        assert exec_record.process.responsible_audit_token.euid == 0
        assert exec_record.process.audit_token.euid == process.credentials.effective_uid
        assert (
            exec_record.event.exec.target.responsible_audit_token == exit_record.process.audit_token
        )
        assert [fd.fdtype for fd in exec_record.event.exec.fds] == [1, 1, 1]
        assert exit_record.event.exit.stat == 0
