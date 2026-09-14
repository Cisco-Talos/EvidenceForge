"""Native Windows checkpoint recovery from simulated power-loss storage images."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.models import CheckpointCursor
from evidenceforge.generation.checkpoints.store import (
    HeadDraft,
    IncrementalCheckpointStore,
    SegmentDraft,
)
from tests.support.checkpoint_power_loss import CrashImage, PowerLossModel, StorageEvent, read_trace
from tests.support.output_equivalence import deterministic_bundle_files
from tests.support.windows_checkpoint_trace import trace_checkpoint_io

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.name != "nt", reason="Native Windows checkpoint durability matrix"),
]


def _cursor(hour: int) -> CheckpointCursor:
    return CheckpointCursor(
        phase="collection",
        completed_simulated_hours=hour,
        next_hour=f"2026-01-01T{hour:02d}:00:00+00:00",
    )


def _assert_recovery(image: CrashImage, root: Path) -> int | None:
    image.materialize(root)
    store = IncrementalCheckpointStore(root / "run")
    index = root / "run" / ".eforge-generation" / "CURRENT.json"
    if not index.exists():
        assert image.acknowledged_sequence < 0, "lost acknowledged recovery index"
        return None
    try:
        recovery = store.recover(read_only=True)
    except CheckpointError:
        if image.acknowledged_sequence >= 0:
            raise AssertionError("lost an acknowledged recovery") from None
        return None
    assert recovery.manifest.sequence >= image.acknowledged_sequence, (
        "recovered an older checkpoint"
    )
    for segment in recovery.segments:
        store.read_segment(segment)
    return recovery.manifest.sequence


@pytest.fixture
def publication_trace(tmp_path: Path) -> list[StorageEvent]:
    from evidenceforge.generation.checkpoints.control import mark_suspended, new_suspension_request

    root = tmp_path / "native"
    root.mkdir()
    with trace_checkpoint_io(root, tmp_path / "publication-trace.jsonl") as events:
        store = IncrementalCheckpointStore(root / "run")
        inherited = ()
        for sequence in range(3):
            if sequence == 2:
                # A fresh store must adopt dependencies written by another
                # process/session instead of trusting its empty durability cache.
                store = IncrementalCheckpointStore(root / "run")
            manifest = store.commit(
                sequence=sequence,
                run_id="power-loss",
                run_fingerprint="a" * 64,
                checkpoint_hours=1,
                cursor=_cursor(sequence + 1),
                resolved_scenario=b"schema_version: '2.0'\n",
                inherited_catalogs=inherited if sequence == 2 else (),
                new_segments=(
                    ()
                    if sequence == 2
                    else (
                        SegmentDraft(
                            owner="engine",
                            schema_version="1",
                            payload=bytes([sequence + 1]) * 8193,
                            record_count=1,
                        ),
                    )
                ),
                heads=(HeadDraft(owner="engine", schema_version="1", payload=b"head"),),
            )
            inherited = manifest.segment_catalogs
        mark_suspended(store, request=new_suspension_request(), cursor=manifest.cursor)
        store.collect_garbage()
    return events


def test_every_publication_boundary_survives_modeled_power_loss(
    tmp_path: Path, publication_trace: list[StorageEvent]
) -> None:
    model = PowerLossModel()
    verified: set[str] = set()
    counts: dict[str, int] = {}
    profiles = [(name, 512) for name in ("drop", "all", "reverse", "partial", "torn")]
    profiles.append(("torn", 4096))
    # The initial snapshot and every post-operation snapshot cover both sides
    # of every mutation/barrier. Duplicate images need only one full validation.
    for cut in range(len(publication_trace) + 1):
        if cut:
            model.apply(publication_trace[cut - 1])
        for profile, sector in profiles:
            image = model.crash(profile, sector_size=sector)
            digest = hashlib.sha256(
                repr((image.acknowledged_sequence, image.directories)).encode()
                + b"".join(
                    name.encode() + hashlib.sha256(data).digest()
                    for name, data in sorted(image.files.items())
                )
            ).hexdigest()
            if digest in verified:
                continue
            case = tmp_path / "image"
            try:
                _assert_recovery(image, case)
            except (AssertionError, CheckpointError, OSError):
                (tmp_path / "failure-profile.json").write_text(
                    json.dumps({"cut": cut, "profile": profile, "sector": sector}), encoding="utf-8"
                )
                raise
            shutil.rmtree(case)
            verified.add(digest)
            counts[profile] = counts.get(profile, 0) + 1
    assert model.acknowledged_sequence == 2
    assert sum(counts.values()) > 20
    (tmp_path / "matrix-summary.json").write_text(
        json.dumps({"cuts": len(publication_trace) + 1, "distinct_images": counts}),
        encoding="utf-8",
    )


@pytest.mark.parametrize("defect", ["missing-write-through", "index-before-recovery"])
def test_model_rejects_broken_publication_protocols(
    tmp_path: Path, publication_trace: list[StorageEvent], defect: str
) -> None:
    end = next(i for i, event in enumerate(publication_trace) if event.operation == "ack")
    events = publication_trace[: end + 1]
    model = PowerLossModel()
    for event in events:
        if defect == "missing-write-through" and event.target.endswith("/CURRENT.json"):
            event = replace(event, write_through=False)
        if defect == "index-before-recovery" and event.target.endswith(
            "/recovery/00000000000000000000"
        ):
            # Defer the real recovery-directory publication until after the
            # index/acknowledgment, creating a deliberately inverted protocol.
            continue
        model.apply(event)
    with pytest.raises(AssertionError, match="acknowledged"):
        _assert_recovery(model.crash(), tmp_path / "broken")


def _run(arguments: list[str], log: Path, *, environment: dict[str, str]) -> None:
    with log.open("w+b") as output:
        process = subprocess.Popen(
            arguments, stdout=output, stderr=subprocess.STDOUT, env=environment
        )
        try:
            process.wait(timeout=180)
            output.seek(0)
            assert process.returncode == 0, output.read().decode("utf-8", errors="replace")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)


def test_real_cli_resumes_power_loss_images_with_identical_evidence(tmp_path: Path) -> None:
    scenario = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_text())
    scenario["time_window"].update(warmup="1h", duration="3h")
    scenario["baseline_activity"]["intensity"] = "low"
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(yaml.safe_dump(scenario), encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EFORGE_TEST_CHECKPOINT_")
    } | {"PYTHONUTF8": "1"}
    native = tmp_path / "native"
    native.mkdir()
    trace = tmp_path / "cli-trace.jsonl"
    _run(
        [
            sys.executable,
            "-m",
            "tests.support.windows_checkpoint_driver",
            str(native),
            str(trace),
            "--",
            "generate",
            str(scenario_path),
            "--output",
            str(native / "run"),
            "--seed",
            "42",
            "--checkpoint-hours",
            "1",
        ],
        tmp_path / "native-cli.log",
        environment=environment,
    )
    events = read_trace(trace)
    model = PowerLossModel()
    images: dict[str, CrashImage] = {}
    for event in events:
        model.apply(event)
        if event.sequence == 2 and event.operation == "stage":
            if event.stage == "recovery_published":
                images["before-index"] = model.crash()
            elif event.stage == "index_published":
                images["before-ack"] = model.crash()
        if event.operation == "ack" and event.sequence == 2:
            images["after-ack"] = model.crash()
    assert set(images) == {"before-index", "before-ack", "after-ack"}
    control = tmp_path / "control"
    _run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario_path),
            "--output",
            str(control),
            "--seed",
            "42",
            "--checkpoint-hours",
            "0",
        ],
        tmp_path / "control.log",
        environment=environment,
    )
    expected = deterministic_bundle_files(control)
    assert any(b"<Event " in data for name, data in expected.items() if name.startswith("data/"))
    assert any(data.strip() for name, data in expected.items() if name.endswith("/conn.json"))
    for label, image in images.items():
        root = tmp_path / label
        image.materialize(root)
        output = root / "run"
        index = output / ".eforge-generation" / "CURRENT.json"
        before = index.read_bytes()
        _run(
            [sys.executable, "-m", "evidenceforge", "checkpoint", "verify", str(output)],
            tmp_path / f"{label}-verify.log",
            environment=environment,
        )
        assert index.read_bytes() == before
        _run(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                "--output",
                str(output),
                "--resume",
            ],
            tmp_path / f"{label}-resume.log",
            environment=environment,
        )
        assert deterministic_bundle_files(output) == expected
        assert not (output / ".eforge-generation").exists()

    # Crash during real spool reconstruction, then rebuild from the same durable
    # checkpoint again. Restore output is disposable; its checkpoint is retained.
    restoring = tmp_path / "restoring"
    images["after-ack"].materialize(restoring)
    restore_trace = tmp_path / "restore-trace.jsonl"
    _run(
        [
            sys.executable,
            "-m",
            "tests.support.windows_checkpoint_driver",
            str(restoring),
            str(restore_trace),
            "--restore",
            "--",
            "generate",
            "--output",
            str(restoring / "run"),
            "--resume",
        ],
        tmp_path / "restore-interruption.log",
        environment=environment,
    )
    assert any(event.stage == "restore-interrupted" for event in read_trace(restore_trace))
    # Apply observed restore mutations to the prior model state rather than copy
    # the runner's cached live files and mislabel that as a power failure.
    model = PowerLossModel.from_image(images["after-ack"])
    for event in read_trace(restore_trace):
        model.apply(event)
    restarted = tmp_path / "restore-restarted"
    model.crash().materialize(restarted)
    _run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            "--output",
            str(restarted / "run"),
            "--resume",
        ],
        tmp_path / "restore-restarted.log",
        environment=environment,
    )
    assert deterministic_bundle_files(restarted / "run") == expected
    assert not (restarted / "run" / ".eforge-generation").exists()
