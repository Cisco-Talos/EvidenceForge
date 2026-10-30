# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A shared Finder producer materializes the app exec without inventing a fork."""

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
from evidenceforge.models.scenario import ProcessEventSpec, Scenario
from tests.unit.test_macos_installed_provisioning import _scenario

_APP = "/Applications/EForgeReference.app/Contents/MacOS/EForgeReference"


@pytest.mark.parametrize("authored", [False, True], ids=["baseline-owner", "authored"])
@pytest.mark.parametrize("native", [False, True], ids=["filtered", "native"])
def test_finder_app_exec_and_known_exit_use_the_shared_engine(
    tmp_path: Path, authored: bool, native: bool
) -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    if native:
        raw["output"]["logs"].append({"format": "macos_endpoint_security"})
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
    scenario.write_text(yaml.safe_dump(raw, sort_keys=False))
    compiled = compile_scenario(scenario, project_root=tmp_path)
    engine = GenerationEngine(
        Scenario.model_validate(raw),
        tmp_path / "run",
        generation_seed=349,
        compiled_scenario=compiled,
    )
    engine._chronological_es_delivery = True
    try:
        with effective_config_scope(compiled.effective_config):
            engine._initialize()
        system = next(s for s in engine.scenario.environment.systems if s.hostname == "MAC-01")
        user = next(u for u in engine.scenario.environment.users if u.username == "alex")
        at = engine.start_time + timedelta(minutes=10)
        logon = engine.activity_generator.generate_logon(
            user, system, at, allow_local_session_reuse=False
        )
        at += timedelta(seconds=5)
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
        assert process.image == _APP and process.execution_ordinal == 1
        assert process.initial_image == "/usr/libexec/xpcproxy"
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
        engine.dispatcher.macos_es_ingress.finalize(engine.dispatcher)
    finally:
        engine._close_emitters()
    records = [
        record
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (record := decode_endpoint_security_record(line)).process.audit_token.pid == pid
    ]
    assert [record.event_type for record in records] == ([9, 15] if native else []), (
        engine.dispatcher.macos_es_ingress.coverage.model_dump()
    )
    if native:
        exec_record, exit_record = records
        assert exec_record.process.executable.path == "/usr/libexec/xpcproxy"
        assert exec_record.process.signing_id == "com.apple.xpc.proxy"
        assert exec_record.event.exec.target.executable.path == _APP
        assert exec_record.process.responsible_audit_token.euid == 0
        assert exec_record.process.audit_token.euid == process.credentials.effective_uid
        assert (
            exec_record.event.exec.target.responsible_audit_token == exit_record.process.audit_token
        )
        assert [fd.fdtype for fd in exec_record.event.exec.fds] == [1, 1, 1]
        assert exit_record.event.exit.stat == 0
