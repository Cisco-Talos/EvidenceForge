# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Mounted operation completion reaches the exact native process close owner."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_smb import macos_smb_scenario


@pytest.mark.slow
@pytest.mark.parametrize("server_platform", ["windows", "linux"])
@pytest.mark.parametrize("operation", ["read", "browse", "update", "denied"])
def test_mounted_helper_completion_publishes_only_declared_success(
    scenarios_dir: Path, tmp_path: Path, server_platform: str, operation: str
) -> None:
    data = macos_smb_scenario(scenarios_dir, server_platform=server_platform).model_dump()
    data["macos_process_coverage"] = "complete"
    data["output"]["logs"].append({"format": "macos_endpoint_security"})
    spec = data["storyline"][0]["events"][0]
    spec["operation"] = "read" if operation == "denied" else operation
    if operation == "denied":
        spec["outcome"] = "access_denied"
        data["environment"]["storage"]["servers"][0]["shares"][0]["access"]["deny"] = ["test_user"]
    scenario = Scenario.model_validate(data)
    with generation_seed_scope(scenario.generation_seed):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        engine._chronological_es_delivery = True
        image = (
            "/bin/ls"
            if operation == "browse"
            else "/usr/bin/tee"
            if operation == "update"
            else "/bin/cat"
        )
        try:
            engine._initialize()
            generator = engine.activity_generator
            user, client = scenario.environment.users[0], scenario.environment.systems[0]
            with generation_seed_scope(scenario.generation_seed):
                reset_thread_rng()
                logon = generator.generate_logon(
                    user, client, engine.start_time + timedelta(minutes=1)
                )
                generator.ensure_macos_session_shell(
                    user, client, logon, engine.start_time + timedelta(minutes=2)
                )
                result = generator.generate_smb_activity(
                    spec=scenario.storyline[0].events[0],
                    actor=user,
                    parent_system=client,
                    time=engine.start_time + timedelta(minutes=10),
                    activity_source="storyline",
                )
                ended = [
                    p
                    for p in engine.state_manager._ended_processes_by_object_id.values()
                    if p.system == client.hostname and p.image == image
                ]
                assert len(ended) == 1
                process = ended[0]
                assert process.exit_outcome == (
                    None if operation == "denied" else PosixProcessExit(exit_code=0)
                )
                assert process.end_time > result.completed_at
                pid = process.pid
                engine._finalize_macos_process_coverage()
                census = next(
                    h.process_census
                    for h in engine.dispatcher.macos_es_ingress.coverage.hosts
                    if h.hostname == client.hostname
                )
                assert census.complete and census.known_exit_identities_match
        finally:
            engine._close_emitters()
        exits = [
            record
            for path in tmp_path.rglob("macos_endpoint_security.ndjson")
            for line in path.read_text().splitlines()
            if (record := decode_endpoint_security_record(line)).event_type == 15
            and record.process.audit_token.pid == pid
        ]
        assert len(exits) == (0 if operation == "denied" else 1)
        if exits:
            assert exits[0].event.exit.stat == 0
