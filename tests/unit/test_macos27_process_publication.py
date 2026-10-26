# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented bounded v11 phases share canonical identity, filtering and recovery."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.posix_process import (
    process_exec_occurrence,
    process_exit_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.runtime_content import RuntimeArtifactDescriptor
from tests.unit import test_macos_runtime_es_preparation as runtime_fixture
from tests.unit.test_macos_es_source_integration import _routed
from tests.unit.test_macos_execution_directory import _directory
from tests.unit.test_macos_native_sink_publication import _prepare


@pytest.mark.parametrize("known_entitlements", [False, True])
@pytest.mark.parametrize("exit_code", [None, 7])
@pytest.mark.parametrize("failure", [None, "before_write", "after_write"])
def test_active_profile_exports_only_known_phases_with_all_counter_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    known_entitlements: bool,
    exit_code: int | None,
    failure: str | None,
) -> None:
    original = runtime_fixture._executable
    if known_entitlements:

        def executable() -> RuntimeArtifactDescriptor:
            descriptor = original()
            return replace(
                descriptor, code_signature=replace(descriptor.code_signature, entitlements="absent")
            )

        monkeypatch.setattr(runtime_fixture, "_executable", executable)
    source, dispatcher, output, _, old_event, _, parent, _ = _routed(tmp_path, known_stdio=True)
    state = dispatcher.state_manager
    at = old_event.timestamp
    builder = state.begin_action_cohort_materialization()
    birth = builder.fork_process(parent, forked_at=at)
    executed_at = at + timedelta(seconds=1)
    after = builder.execute_process(
        birth,
        image=parent.image,
        command_line=parent.image,
        executed_at=executed_at,
        arguments=(parent.image,),
        environment=("LANG=C",),
        execution_directory=replace(
            _directory(), hostname=parent.hostname, observed_at=executed_at
        ),
        executable_version=parent.executable_version,
        image_security=parent.image_security,
        exec_image=MacosExecImage(0, parent.image),
        exec_script=MacosExecScript(),
    )
    end = at + timedelta(seconds=2)
    builder.terminate_process(
        after,
        end_time=end,
        exit_outcome=PosixProcessExit(exit_code=exit_code) if exit_code is not None else None,
    )
    cohort = builder.seal()
    host = old_event.src_host
    events = (
        process_fork_occurrence(
            host=host, parent=parent, child=birth.identity, integrity_level="Medium"
        ),
        process_exec_occurrence(
            host=host, before=birth.identity, after=after, integrity_level="Medium"
        ),
        process_exit_occurrence(
            host=host,
            process=after,
            timestamp=end,
            integrity_level="Medium",
            exit_outcome=PosixProcessExit(exit_code=exit_code) if exit_code is not None else None,
        ),
    )
    if failure is None:
        batch = _prepare(
            dispatcher, cohort, events, root=f"macos-process-cohort:{cohort.semantic_id}"
        )
        dispatcher.publish_prepared_action_cohort_batch(batch)
    else:
        original_write = ExternalSortedLineWriter._commit_exact_row
        failed = False

        def write_once(
            writer: ExternalSortedLineWriter, key: tuple, digest: str, row: object
        ) -> None:
            nonlocal failed
            if not failed:
                failed = True
                if failure == "after_write":
                    original_write(writer, key, digest, row)
                raise RuntimeError("invented v11 sink interruption")
            original_write(writer, key, digest, row)

        with monkeypatch.context() as scoped:
            scoped.setattr(ExternalSortedLineWriter, "_commit_exact_row", write_once)
            batch = _prepare(
                dispatcher, cohort, events, root=f"macos-process-cohort:{cohort.semantic_id}"
            )
            with pytest.raises(RuntimeError, match="invented v11 sink interruption") as caught:
                dispatcher.publish_prepared_action_cohort_batch(batch)
            committed = state.materialization_digest()
            counter_state = source.connection()
            dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
            assert state.materialization_digest() == committed
            assert source.connection() == counter_state
    assert source.connection().next_delivery == 3
    assert [
        (item.event_type, item.next_sequence) for item in source.connection().event_counters
    ] == [(9, 1), (11, 1), (15, 1)]
    assert state.get_process(after.hostname, after.pid) is None
    dispatcher.assert_exact_projection_recoveries_drained()
    output.close()
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    records = [decode_endpoint_security_record(line) for line in paths[0].read_text().splitlines()]
    expected = [11] + ([9] if known_entitlements else []) + ([15] if exit_code is not None else [])
    assert [record.event_type for record in records] == expected
    assert all(record.version == 11 for record in records)
    assert [record.global_seq_num for record in records] == [
        index for index, kind in enumerate((11, 9, 15)) if kind in expected
    ]
    if known_entitlements:
        execution = next(record for record in records if record.event_type == 9)
        assert execution.event.exec.entitlements is None
        assert execution.event.exec.target.audit_token.pid == after.pid
        assert execution.event.exec.args == (parent.image,)
        assert len(execution.event.exec.fds) == 3
    if exit_code is not None:
        terminal = records[-1]
        assert terminal.event.exit.stat == exit_code << 8
