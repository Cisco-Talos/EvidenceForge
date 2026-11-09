# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The initial native SSH fork shares the existing exact deferred source journal."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.engine import GenerationEngine
from tests.unit.test_macos_installed_provisioning import _scenario


@pytest.mark.parametrize("lost_return", [False, True])
def test_initial_native_fork_source_failure_retains_one_root_and_recovers_complete_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lost_return: bool
) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].services = ["ssh"]
    scenario.macos_process_coverage = "complete"
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=369)
    engine._chronological_es_delivery = True
    original = ExternalSortedLineWriter._commit_exact_row
    injected = False

    def inject(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal injected
        if not injected and "es-occurrences.snapshot" in writer.output_path.name:
            row = json.loads(frozen)
            body = json.loads(row["native_body"]) if row.get("native_body") else None
            if (
                body is not None
                and body["event_type"] == 11
                and body["process"]["executable"]["path"] == "/sbin/launchd"
            ):
                injected = True
                if lost_return:
                    original(writer, key, digest, frozen)
                raise OSError("injected initial native SSH fork publication")
        original(writer, key, digest, frozen)

    try:
        engine._initialize()
        generator = engine.activity_generator
        monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", inject)
        with pytest.raises(OSError, match="initial native SSH fork"):
            generator.generate_ssh_session(
                scenario.environment.users[0],
                scenario.environment.systems[0],
                engine.start_time + timedelta(minutes=10),
                source_ip="192.0.2.80",
                source_port=51000,
                duration=120,
                emit_session_close=True,
                defer_session_close=True,
            )
        assert injected
        assert (
            generator.ssh_responder_pid_for_tuple(
                "192.0.2.80", 51000, scenario.environment.systems[0].ip
            )
            is not None
        )
        assert engine.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
        version = engine.state_manager.materialization_version
        recovered = engine.dispatcher.drain_exact_projection_recoveries()
        assert len(recovered) == 1
        assert engine.state_manager.materialization_version == version
        assert len(generator._pending_ssh_session_closures) == 1
        generator._pending_ssh_session_closures[0].prepared.drain_receiver_startup(generator)
        generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
        assert census.expected_forks == census.published_forks == 6
        assert census.expected_execs == census.published_execs == 6
        engine.dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert sum(row["event_type"] == 11 for row in rows) == 6
    assert sum(row["event_type"] == 9 for row in rows) == 6
