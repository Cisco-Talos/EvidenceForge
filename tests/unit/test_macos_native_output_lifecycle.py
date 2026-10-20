# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented historical records exercise the shared output lifecycle, not admission."""

from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.macos_endpoint_security import MacosEndpointSecurityEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_dispatch_publication import _setup
from tests.unit.test_macos_native_sink_publication import _prepare


def _output(
    root: Path, *, checkpoint: bool = False, threaded: bool = False
) -> MacosEndpointSecurityEmitter:
    # This explicit private definition is intentionally absent from the source
    # catalog and loader. Historical codec coverage is not a generation profile.
    definition = FormatDefinition.model_validate(
        {
            "name": "macos_endpoint_security",
            "description": "Internal exact native output lifecycle test",
            "category": "host",
            "fields": [],
            "output": {
                "format": "json",
                "file_extension": ".ndjson",
                "template": "{{ native_json }}",
            },
        }
    )
    output = MacosEndpointSecurityEmitter(definition, root, threaded=threaded)
    if checkpoint:
        output.enable_incremental_checkpointing()
    return output


def _host(hostname: str = "invented-mac", *, os_category: str = "macos") -> HostContext:
    return HostContext(
        hostname=hostname,
        ip="192.0.2.41",
        os="macOS 26",
        os_category=os_category,
        system_type="workstation",
    )


def _bind_output(tmp_path: Path, *, checkpoint: bool = False, threaded: bool = False) -> tuple:
    native, dispatcher, ecar, old, frozen = _setup(tmp_path, threaded=threaded)
    assert dispatcher.cancel_prepared_action_cohort_batch(old)
    output = _output(tmp_path, checkpoint=checkpoint, threaded=threaded)
    subject = native.process.process
    host = _host(subject.hostname)
    sink = output.native_sink(host)
    event = process_exit_occurrence(
        host=host,
        process=subject,
        timestamp=native.process.observed_at,
        integrity_level="Medium",
    )
    event.process.exit_outcome = native.cohort.process_terminations[0].exit_outcome
    batch = _prepare(
        dispatcher,
        native.cohort,
        (event,),
        root=f"process-exit:{subject.object_id}",
        es_delivery=native.delivery,
        es_collector_process=native.collector,
        es_native_sink=sink,
    )
    return native, dispatcher, ecar, output, sink, batch, frozen


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("checkpoint", [False, True])
def test_exact_output_counts_and_defers_export_until_shared_close(
    tmp_path: Path, threaded: bool, checkpoint: bool
) -> None:
    native, dispatcher, ecar, output, sink, batch, frozen = _bind_output(
        tmp_path, checkpoint=checkpoint, threaded=threaded
    )
    assert output.event_count == 0
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert output.event_count == 1
    assert output.profiling_snapshot()["rendered_rows"] == 1
    assert output.native_sink(_host(native.process.process.hostname)) is sink
    output.barrier_flush()
    assert not sink.output_path.exists()
    ecar.close()
    output.close()
    output.close()
    assert sink.output_path.read_text() == frozen
    assert output.event_count == 1
    with pytest.raises(RuntimeError, match="clos"):
        output.native_sink(_host(native.process.process.hostname))


@pytest.mark.parametrize("aborted", [False, True])
def test_standard_checkpoint_restores_native_bytes_counters_and_state(
    tmp_path: Path, aborted: bool
) -> None:
    native, dispatcher, ecar, output, sink, batch, frozen = _bind_output(
        tmp_path / "original", checkpoint=True
    )
    participant = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": output}, output_root=tmp_path / "original"
    )
    with pytest.raises(RuntimeError, match="exact publication"):
        participant.prepare_checkpoint(1)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    output.barrier_flush()
    seal = participant.prepare_checkpoint(1)
    assert participant.last_bytes_read == len(frozen.encode())
    assert len(seal.segments) == 1
    if aborted:
        participant.checkpoint_aborted(1)
        assert sink.exact_journal_census().admitted_rows == 1
        retried = participant.prepare_checkpoint(1)
        assert retried == seal
    participant.checkpoint_committed(1)
    assert sink.exact_journal_census().admitted_rows == 0
    state_head = _capture_head(native.owner.state)
    counters = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)

    restored_state = StateManager()
    _restore_head(restored_state, state_head)
    restored_dispatcher = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored_dispatcher).restore_checkpoint(
        counters.head.payload, ()
    )
    restored_output = _output(tmp_path / "restored", checkpoint=True)
    restored = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": restored_output}, output_root=tmp_path / "restored"
    )
    restored.restore_checkpoint(seal.head.payload, tuple(item.payload for item in seal.segments))
    assert restored_output.event_count == 1
    assert restored_dispatcher.es_collectors.snapshot() == dispatcher.es_collectors.snapshot()
    assert restored_state.materialization_digest() == native.owner.state.materialization_digest()
    restored_output.barrier_flush()
    next_seal = restored.prepare_checkpoint(2)
    assert next_seal.segments == ()
    assert restored.last_bytes_read == 0
    restored.checkpoint_committed(2)
    restored_output.close()
    output.close()
    ecar.close()
    restored_sink = next(iter(restored_output._writers.values()))._sorted_writer
    assert restored_sink.output_path.read_text() == sink.output_path.read_text() == frozen


@pytest.mark.parametrize("after_export", [False, True])
def test_native_terminal_export_failure_retains_exact_rows_for_close_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_export: bool
) -> None:
    native, dispatcher, ecar, output, sink, batch, frozen = _bind_output(tmp_path)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    state_version = native.owner.state.materialization_version
    counters = native.owner.collectors.snapshot()
    original = ExternalSortedLineWriter._publish_runs_unlocked

    def fail(writer: ExternalSortedLineWriter) -> None:
        if after_export:
            original(writer)
        raise OSError("invented terminal native export failure")

    with monkeypatch.context() as patch:
        patch.setattr(ExternalSortedLineWriter, "_publish_runs_unlocked", fail)
        with pytest.raises(OSError, match="terminal native export failure"):
            output.close()
    assert output.event_count == 1
    output.close()
    ecar.close()
    assert sink.output_path.read_text() == frozen
    assert native.owner.state.materialization_version == state_version
    assert native.owner.collectors.snapshot() == counters


@pytest.mark.parametrize("after_write", [False, True])
def test_native_checkpoint_rejects_partial_publication_until_exact_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    sink = None
    failed = False
    original = ExternalSortedLineWriter._commit_exact_row

    def fail(writer: ExternalSortedLineWriter, key: tuple, digest: str, row: object) -> None:
        nonlocal failed
        if writer is sink and not failed:
            failed = True
            if after_write:
                original(writer, key, digest, row)
            raise OSError("invented checkpoint native row failure")
        original(writer, key, digest, row)

    with monkeypatch.context() as patch:
        patch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
        native, dispatcher, ecar, output, sink, batch, frozen = _bind_output(
            tmp_path, checkpoint=True
        )
        with pytest.raises(OSError, match="checkpoint native row failure") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
    participant = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": output}, output_root=tmp_path
    )
    counters = native.owner.collectors.snapshot()
    version = native.owner.state.materialization_version
    with pytest.raises(RuntimeError, match="exact publication"):
        participant.prepare_checkpoint(1)
    assert output.event_count == int(after_write)
    dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    output.barrier_flush()
    seal = participant.prepare_checkpoint(1)
    assert len(seal.segments) == 1
    participant.checkpoint_committed(1)
    output.close()
    ecar.close()
    assert output.event_count == 1
    assert sink.output_path.read_text() == frozen
    assert native.owner.collectors.snapshot() == counters
    assert native.owner.state.materialization_version == version


@pytest.mark.parametrize("filtered", [False, True])
@pytest.mark.parametrize("retire", [False, True])
def test_native_checkpoint_retains_entire_mixed_cohort_and_collector_close(
    tmp_path: Path, filtered: bool, retire: bool
) -> None:
    from tests.unit.test_macos_process_cohort_publication import _setup as setup_cohort

    output = _output(tmp_path / "original", checkpoint=True)
    owner, dispatcher, ecar, sink, batch, delivery, frozen, _, _ = setup_cohort(
        tmp_path / "original", retire=retire, filtered=filtered, output=output
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert output.event_count == (0 if filtered else 3)
    output.barrier_flush()
    participant = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": output}, output_root=tmp_path / "original"
    )
    seal = participant.prepare_checkpoint(1)
    participant.checkpoint_committed(1)
    counters = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    restored_dispatcher = EventDispatcher(owner.state, {})
    DispatcherObservationParticipant(restored_dispatcher).restore_checkpoint(
        counters.head.payload, ()
    )
    restored_output = _output(tmp_path / "restored", checkpoint=True)
    restored_participant = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": restored_output}, output_root=tmp_path / "restored"
    )
    restored_participant.restore_checkpoint(
        seal.head.payload, tuple(item.payload for item in seal.segments)
    )
    assert restored_output.event_count == output.event_count
    profile = restored_dispatcher.es_collectors.connection(delivery.observations[0].source_instance)
    assert profile.next_delivery == 3
    assert (profile.closed_at is not None) == retire
    restored_output.close()
    output.close()
    ecar.close()
    expected = "" if filtered else "".join(frozen)
    restored_paths = tuple((tmp_path / "restored").rglob("*.ndjson"))
    assert (restored_paths[0].read_text() if restored_paths else "") == expected
    assert (sink.output_path.read_text() if sink.output_path.exists() else "") == expected


def test_native_output_requires_mac_host_and_checkpoint_mode_before_route_allocation(
    tmp_path: Path,
) -> None:
    output = _output(tmp_path)
    for category in ("linux", "windows"):
        with pytest.raises(StateError, match="modeled Mac host"):
            output.native_sink(_host(os_category=category))
    assert output._writers == {}
    first = output.native_sink(_host("first.example.test"))
    second = output.native_sink(_host("second.example.test"))
    assert first is not second
    assert first.output_path != second.output_path
    with pytest.raises(StateError, match="precede sink allocation"):
        output.enable_incremental_checkpointing()
    output.close()
    assert not tuple(tmp_path.rglob("*.ndjson"))


def test_native_output_never_selects_or_renders_generic_events(tmp_path: Path) -> None:
    output = _output(tmp_path)
    assert not output.can_handle(None)
    for call in (
        lambda: output.emit(None),
        lambda: output.emit_event({"native_json": "{}"}),
        lambda: output.emit_raw({"native_json": "{}"}),
        lambda: output.emit_to_host("{}", "invented-mac"),
    ):
        with pytest.raises(StateError, match="authenticated exact native publication"):
            call()
    assert output._writers == {}
    assert output.event_count == 0
    output.close()


def test_native_output_preserves_existing_destination(tmp_path: Path) -> None:
    path = tmp_path / "invented-mac" / "macos_endpoint_security.ndjson"
    path.parent.mkdir()
    path.write_bytes(b"invented prior output\n")
    output = _output(tmp_path)
    with pytest.raises(FileExistsError, match="fresh output path"):
        output.native_sink(_host())
    assert output._writers == {}
    output.close()
    assert path.read_bytes() == b"invented prior output\n"


@pytest.mark.slow
def test_native_checkpoint_output_is_identical_in_fresh_processes(tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""\
        import hashlib
        import json
        import sys
        from pathlib import Path
        from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
        from tests.unit.test_macos_native_output_lifecycle import _bind_output, _output

        root = Path(sys.argv[1])
        native, dispatcher, ecar, output, sink, batch, frozen = _bind_output(
            root / "original", checkpoint=True
        )
        dispatcher.publish_prepared_action_cohort_batch(batch)
        output.barrier_flush()
        participant = EmitterSpoolParticipant(
            emitters={"macos_endpoint_security": output}, output_root=root / "original"
        )
        seal = participant.prepare_checkpoint(1)
        participant.checkpoint_committed(1)
        restored = _output(root / "restored", checkpoint=True)
        recovery = EmitterSpoolParticipant(
            emitters={"macos_endpoint_security": restored}, output_root=root / "restored"
        )
        recovery.restore_checkpoint(seal.head.payload, tuple(s.payload for s in seal.segments))
        restored.close()
        output.close()
        ecar.close()
        recovered_path = next((root / "restored").rglob("*.ndjson"))
        assert recovered_path.read_bytes() == sink.output_path.read_bytes() == frozen.encode()
        print(json.dumps({
            "sha256": hashlib.sha256(recovered_path.read_bytes()).hexdigest(),
            "count": restored.event_count,
        }))
    """)
    results: list[dict[str, object]] = []
    for seed in ("19", "941"):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / seed)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(json.loads(result.stdout))
    assert results[0] == results[1]
    assert results[0]["count"] == 1
