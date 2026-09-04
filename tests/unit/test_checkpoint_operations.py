"""Operational checkpoint status and planned-suspension contracts."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import build_resolved_document, serialize_resolved_document
from evidenceforge.generation.checkpoints.control import (
    read_suspension_record,
    read_suspension_request,
    request_suspension,
)
from evidenceforge.generation.checkpoints.fingerprint import (
    run_fingerprint,
    run_fingerprint_components,
)
from evidenceforge.generation.checkpoints.models import CheckpointCursor
from evidenceforge.generation.checkpoints.packed import dumps
from evidenceforge.generation.checkpoints.participants import OwnerStateField, ParticipantSeal
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.checkpoints.status import inspect_checkpoint
from evidenceforge.generation.checkpoints.store import (
    HeadDraft,
    IncrementalCheckpointStore,
    SegmentDraft,
)

runner = CliRunner()


class _Participant:
    checkpoint_owner = "operation-test"
    checkpoint_schema_version = "1"
    checkpoint_state_fields = (
        OwnerStateField("head", "bounded-live-head"),
        OwnerStateField("delta", "immutable-incremental-segments"),
    )

    def __init__(self) -> None:
        self.prepared: int | None = None

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        self.prepared = sequence
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps({"sequence": sequence}),
            ),
            segments=(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps([sequence]),
                    record_count=1,
                ),
            ),
        )

    def checkpoint_committed(self, sequence: int) -> None:
        assert self.prepared == sequence
        self.prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        assert self.prepared == sequence
        self.prepared = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        del head, segments


def _controller(
    output: Path,
    scenario_path: Path,
) -> tuple[IncrementalCheckpointStore, IncrementalCheckpointController, _Participant]:
    compiled = compile_scenario(scenario_path)
    formats = [str(item["format"]) for item in compiled.scenario.output.logs]
    fingerprint = run_fingerprint(
        compiled,
        output_target="default",
        formats=formats,
        oob_hosts=(),
    )
    store = IncrementalCheckpointStore(output)
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint=fingerprint,
        checkpoint_hours=6,
        resolved_scenario=serialize_resolved_document(build_resolved_document(compiled)),
        run_options={"formats_filter": None, "oob_hosts": [], "output_target": "default"},
        fingerprint_components=run_fingerprint_components(
            compiled,
            output_target="default",
            formats=formats,
            oob_hosts=(),
        ),
    )
    return store, controller, _Participant()


def _cursor(hour: int) -> CheckpointCursor:
    return CheckpointCursor(
        phase="collection",
        completed_simulated_hours=hour,
        next_hour=f"2026-01-02T{hour:02d}:00:00+00:00",
    )


def test_status_absent_is_read_only(tmp_path: Path) -> None:
    output = tmp_path / "missing"

    report = inspect_checkpoint(output)
    result = runner.invoke(app, ["checkpoint", "status", str(output)])

    assert report.state == "absent"
    assert result.exit_code == 1
    assert "Checkpoint state: no checkpoints found" in " ".join(result.stdout.split())
    assert "Validation:" not in result.stdout
    assert "Storage:" not in result.stdout
    assert not output.exists()


def test_status_and_suspend_explain_generated_data_directory(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    data = output / "data"
    _controller(output, Path("tests/fixtures/scenarios/minimal.yaml"))
    data.mkdir()
    report = inspect_checkpoint(data)

    status = runner.invoke(
        app,
        ["checkpoint", "status", str(data)],
        terminal_width=300,
    )
    suspend = runner.invoke(
        app,
        ["checkpoint", "suspend", str(data)],
        terminal_width=300,
    )

    status_text = " ".join(status.stdout.split())
    suspend_text = " ".join(suspend.stdout.split())
    assert status.exit_code == 1
    assert "Checkpoint state: no checkpoints found" in status_text
    assert "generated data directory" in status_text
    assert report.warnings == (
        "This appears to be the generated data directory. Use the bundle root instead: "
        f"eforge checkpoint status {output}",
    )
    assert "Storage:" not in status.stdout
    assert suspend.exit_code == 1
    assert "generated data directory" in suspend_text
    assert "eforge checkpoint suspend" in suspend_text


def test_status_json_validates_recovery_and_reports_nonoverlapping_storage(
    tmp_path: Path,
) -> None:
    output = tmp_path / "bundle"
    store, controller, participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    controller.commit(cursor=_cursor(6), participants=(participant,))
    store.staged_bundle.mkdir()
    (store.staged_bundle / "generated.log").write_bytes(b"generated")

    result = runner.invoke(app, ["checkpoint", "status", str(output), "--json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["state"] == "resumable"
    assert payload["integrity"] == "passed"
    assert payload["compatibility"] == "passed"
    assert payload["simulated_hour"] == 6
    assert payload["checkpoint_hours"] == 6
    assert payload["storage"]["generated_bytes"] == len(b"generated")
    assert payload["storage"]["checkpoint_bytes"] > 0
    assert "active_spool_bytes" not in payload["storage"]
    assert payload["storage"]["total_managed_bytes"] == (
        payload["storage"]["generated_bytes"] + payload["storage"]["recovery_overhead_bytes"]
    )
    assert payload["diagnostics"]["participant_heads"] == 1


def test_status_human_output_keeps_developer_details_verbose(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    _store, controller, participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    controller.commit(cursor=_cursor(6), participants=(participant,))

    ordinary = runner.invoke(app, ["checkpoint", "status", str(output)])
    verbose = runner.invoke(app, ["checkpoint", "status", str(output), "--verbose"])

    assert ordinary.exit_code == 0, ordinary.stdout
    assert "Recovery point:" in ordinary.stdout
    assert "Total known managed working footprint:" in ordinary.stdout
    assert "spool" not in ordinary.stdout.lower()
    assert "Developer diagnostics" not in ordinary.stdout
    assert verbose.exit_code == 0, verbose.stdout
    assert "Recovery generations" in verbose.stdout
    assert "Developer diagnostics" in verbose.stdout
    assert "spool" not in verbose.stdout.lower()


def test_suspend_command_requires_live_owner_and_is_idempotent(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, _controller_value, _participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    store.lock.acquire()
    try:
        first = runner.invoke(app, ["checkpoint", "suspend", str(output)])
        second = runner.invoke(app, ["checkpoint", "suspend", str(output)])
    finally:
        store.lock.release()

    assert first.exit_code == 0, first.stdout
    normalized = " ".join(first.stdout.split())
    assert "not immediate" in normalized.lower()
    assert "end of its current simulated hour" in normalized
    assert "still running" in normalized
    assert second.exit_code == 0
    assert read_suspension_request(store) is not None
    assert first.stdout.rsplit("(", 1)[-1][:12] == second.stdout.rsplit("(", 1)[-1][:12]


def test_concurrent_suspend_callers_converge_on_one_request(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, _controller_value, _participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    store.lock.acquire()
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            requests = tuple(executor.map(lambda _index: request_suspension(store), range(16)))
    finally:
        store.lock.release()

    assert len({request.request_id for request in requests}) == 1
    assert read_suspension_request(store) == requests[0]


def test_status_reports_active_controller_before_first_recovery(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, _controller_value, _participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    store.lock.acquire()
    try:
        report = inspect_checkpoint(output)
        result = runner.invoke(app, ["checkpoint", "status", str(output)])
    finally:
        store.lock.release()

    assert report.state == "active"
    assert report.integrity == "pending"
    assert report.checkpoint_hours == 6
    assert report.simulated_hour is None
    assert result.exit_code == 0, result.stdout
    normalized = " ".join(result.stdout.split())
    assert "Checkpoint state: active — no checkpoint yet" in normalized
    assert "Validation: waiting for the first checkpoint" in normalized


def test_status_validates_both_recoveries_and_warns_on_fallback(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, controller, participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    first = controller.commit(cursor=_cursor(6), participants=(participant,))
    second = controller.commit(cursor=_cursor(12), participants=(participant,))
    newest_head = store.workspace / second.participant_heads[0].relative_path
    newest_head.write_bytes(b"tampered")

    report = inspect_checkpoint(output)

    assert report.state == "resumable"
    assert report.used_fallback
    assert report.simulated_hour == first.cursor.completed_simulated_hours
    assert [point.valid for point in report.recovery_points] == [False, True]
    assert any("previous recovery" in warning for warning in report.warnings)


def test_suspend_rejects_inactive_checkpoint_workspace(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    _controller(output, Path("tests/fixtures/scenarios/minimal.yaml"))

    result = runner.invoke(app, ["checkpoint", "suspend", str(output)])

    assert result.exit_code == 1
    assert "not immediate" in " ".join(result.stdout.split()).lower()
    assert "no active generation owns this output" in result.stdout


def test_off_cadence_suspension_commits_and_preserves_cadence_anchor(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, controller, participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    store.lock.acquire()
    try:
        result = runner.invoke(app, ["checkpoint", "suspend", str(output)])
        assert result.exit_code == 0, result.stdout
        request = read_suspension_request(store)
        assert request is not None
        manifest = controller.commit_suspension(
            request=request,
            cursor=_cursor(5),
            participants=(participant,),
        )
    finally:
        store.lock.release()

    assert manifest.cursor.completed_simulated_hours == 5
    assert controller.cadence.is_due(6)
    assert not controller.cadence.is_due(11)
    assert read_suspension_request(store) is None
    suspended = read_suspension_record(store)
    assert suspended is not None
    assert suspended.cursor.completed_simulated_hours == 5


def test_suspend_rejects_request_after_suspension_was_committed(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, controller, participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    store.lock.acquire()
    try:
        first = runner.invoke(app, ["checkpoint", "suspend", str(output)])
        request = read_suspension_request(store)
        assert first.exit_code == 0
        assert request is not None
        controller.commit_suspension(
            request=request,
            cursor=_cursor(5),
            participants=(participant,),
        )

        second = runner.invoke(app, ["checkpoint", "suspend", str(output)])
    finally:
        store.lock.release()

    assert second.exit_code == 1
    assert "already committed its suspension" in second.stdout


def test_status_rejects_symlinked_run_lock(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    store, _controller_value, _participant = _controller(
        output,
        Path("tests/fixtures/scenarios/minimal.yaml"),
    )
    target = tmp_path / "foreign-lock.json"
    target.write_text('{"hostname":"example","pid":1}', encoding="utf-8")
    store.lock.path.symlink_to(target)

    report = inspect_checkpoint(output)

    assert report.state == "invalid"
    assert report.diagnostics["lock"]["state"] == "invalid"
    assert any("unreadable lock" in error for error in report.errors)
