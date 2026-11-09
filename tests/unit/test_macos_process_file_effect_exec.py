# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A process-owned file read must not suppress the process's native exec."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.command_effects import FileEffectAction, FileEffectIntent
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectSpec,
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
)
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_installed_provisioning import _scenario


@pytest.mark.parametrize(
    "native,collected,occurrences,fault",
    [
        (True, True, 1, "none"),
        (False, True, 1, "none"),
        (True, False, 3, "none"),
        (True, True, 3, "none"),
        (True, True, 1, "before"),
        (True, True, 3, "after"),
        (True, True, 1, "early"),
        (True, True, 1, "capacity"),
    ],
)
@pytest.mark.parametrize("chronological", [False, True], ids=["immediate", "ordered-ingress"])
def test_file_read_and_native_process_phases_share_one_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native: bool,
    collected: bool,
    occurrences: int,
    fault: str,
    chronological: bool,
) -> None:
    scenario = _scenario()
    scenario.output.logs = ([{"format": "ecar"}] if collected else []) + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = chronological
    try:
        engine._initialize()
        generator = engine.activity_generator
        system, user = scenario.environment.systems[0], scenario.environment.users[0]
        at = engine.start_time - timedelta(minutes=5)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(minutes=1))
        assert shell is not None
        at = engine.start_time + timedelta(minutes=1)
        path = "/Users/alex/Documents"
        effect = PreparedEndpointEffect(
            spec=EndpointEffectSpec(
                intent=FileEffectIntent(
                    FileEffectAction.READ, path, occurrence_cardinality=occurrences
                ),
                occurrence_times=tuple(
                    at + timedelta(seconds=1, milliseconds=index * 20)
                    for index in range(occurrences)
                ),
                instance_key="invented-directory-read",
            ),
            event_type="file_read",
            payload=PreparedFileEffectPayload(path, FileEffectAction.READ),
        )
        request = ProcessExecutionRequest(
            user,
            system,
            at,
            logon,
            "/bin/ls",
            "/bin/ls " + path,
            parent_pid=shell,
            require_exact_parent=True,
            from_storyline=True,
            arguments=("/bin/ls", path),
            suppress_command_file_effect=True,
            requested_endpoint_effects=(effect,),
        )
        if fault in {"early", "capacity"}:
            if fault == "early":
                request = replace(
                    request,
                    requested_endpoint_effects=(
                        replace(effect, spec=replace(effect.spec, occurrence_times=(at,))),
                    ),
                )
                message = "file effects must follow"
            else:
                monkeypatch.setattr(
                    "evidenceforge.generation.actions.process_execution_service."
                    "_PROCESS_ENDPOINT_ACTION_COHORT_MEMBER_LIMIT",
                    2,
                )
                message = "exceed the process cohort member limit"
            census = engine.state_manager.macos_process_census_snapshot()
            processes = engine.state_manager.get_processes_for_session(logon)
            with pytest.raises(StateError, match=message):
                ProcessExecutionActionBundle(generator, request).execute()
            assert engine.state_manager.macos_process_census_snapshot() == census
            assert engine.state_manager.get_processes_for_session(logon) == processes
            return
        if fault == "none":
            pid = ProcessExecutionActionBundle(generator, request).execute()
        else:
            from evidenceforge.generation.emitters.base import ExactPublicationBatch

            commit = ExactPublicationBatch.commit
            attempted = False

            def fail_once(batch: ExactPublicationBatch) -> None:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    if fault == "after":
                        commit(batch)
                    raise RuntimeError("invented file-chain journal failure")
                commit(batch)

            with monkeypatch.context() as scoped:
                scoped.setattr(ExactPublicationBatch, "commit", fail_once)
                if fault == "after":
                    # A positively committed journal acknowledges itself after a
                    # lost acknowledgement; it need not surface a retry request.
                    ProcessExecutionActionBundle(generator, request).execute()
                else:
                    with pytest.raises(RuntimeError, match="invented file-chain") as caught:
                        ProcessExecutionActionBundle(generator, request).execute()
                    census = engine.state_manager.macos_process_census_snapshot()
                    engine.dispatcher.resume_action_cohort_projection(
                        caught.value.action_cohort_receipt
                    )
                    assert engine.state_manager.macos_process_census_snapshot() == census
                assert attempted
            process = next(
                p
                for p in engine.state_manager.get_processes_for_session(logon)
                if p.image == "/bin/ls"
            )
            pid = process.pid
        process = engine.state_manager.get_process_identity(system.hostname, pid)
        assert process.execution_ordinal == 1
        audit = generator.execution_effect_audit_snapshot()
        assert audit.realized_effect_occurrence_count == occurrences
        assert (
            engine.state_manager.get_session(logon).last_activity_time
            >= effect.spec.occurrence_times[-1]
        )
        if chronological:
            engine._finalize_macos_process_coverage()
            summary = next(
                host.process_census
                for host in engine.dispatcher.macos_es_ingress.coverage.hosts
                if host.hostname == system.hostname
            )
            assert summary.expected_forks == summary.expected_execs == 1
            assert summary.aggregate_births == 0 and summary.complete is native
        else:
            # Immediate publication remains a source-level seam. Public engine
            # completeness always requires ordered ingress and its export receipts.
            with pytest.raises(StateError, match="lost its source occurrence owner"):
                engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    files = [row for row in rows if row["object"] == "FILE" and row["pid"] == pid]
    assert len(files) == (occurrences if collected else 0)
    assert all(row["action"] == "READ" for row in files)
    native_rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert sorted(row["event_type"] for row in native_rows) == ([9, 11] if native else [])
