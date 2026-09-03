"""Tests for content-addressed incremental generation checkpoints."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.generation.checkpoints.errors import (
    CheckpointCompatibilityError,
    CheckpointCorruptionError,
    CheckpointLockError,
)
from evidenceforge.generation.checkpoints.models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointStoreMetrics,
)
from evidenceforge.generation.checkpoints.store import (
    HeadDraft,
    IncrementalCheckpointStore,
    RunLock,
    SegmentDraft,
)

_FINGERPRINT = "1" * 64


def _cursor(hour: int, *, tail: bool = False) -> CheckpointCursor:
    return CheckpointCursor(
        phase="tail" if tail else "collection",
        completed_simulated_hours=hour,
        next_hour=None if tail else f"2026-01-01T{hour:02d}:00:00+00:00",
    )


def _commit(
    store: IncrementalCheckpointStore,
    *,
    sequence: int,
    hour: int,
    inherited: tuple = (),
    payload: bytes | None = None,
    references: tuple[str, ...] = (),
    metrics: CheckpointStoreMetrics | None = None,
) -> CheckpointManifest:
    segments = (
        ()
        if payload is None
        else (
            SegmentDraft(
                owner="lifecycle",
                schema_version="1",
                payload=payload,
                record_count=1,
                compression="zlib-1",
            ),
        )
    )
    return store.commit(
        sequence=sequence,
        run_id="run-1",
        run_fingerprint=_FINGERPRINT,
        checkpoint_hours=6,
        cursor=_cursor(hour),
        resolved_scenario=b"schema_version: '2.0'\n",
        inherited_segments=inherited,
        new_segments=segments,
        heads=(
            HeadDraft(
                owner="engine",
                schema_version="1",
                payload=f'{{"hour":{hour}}}'.encode(),
                referenced_segments=references,
            ),
        ),
        metrics=metrics,
    )


def test_cursor_requires_exact_phase_position() -> None:
    with pytest.raises(ValidationError, match="require next_hour"):
        CheckpointCursor(phase="warmup", completed_simulated_hours=6)
    with pytest.raises(ValidationError, match="cannot name a next hour"):
        CheckpointCursor(
            phase="tail",
            completed_simulated_hours=6,
            next_hour="2026-01-01T06:00:00+00:00",
        )


def test_store_shares_inherited_segments_without_reprocessing_them(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first_metrics = CheckpointStoreMetrics()
    first = _commit(
        store,
        sequence=0,
        hour=6,
        payload=b"first delta" * 100,
        metrics=first_metrics,
    )
    first_segment = first.segments[0]
    first_path = store.workspace / first_segment.relative_path
    first_stat = first_path.stat()

    second_metrics = CheckpointStoreMetrics()
    second = _commit(
        store,
        sequence=1,
        hour=12,
        inherited=first.segments,
        payload=b"second delta" * 100,
        references=(first_segment.sha256,),
        metrics=second_metrics,
    )

    assert len(second.segments) == 2
    assert second_metrics.reused_segment_bytes == first_segment.size
    assert second_metrics.bytes_read == 0
    assert second_metrics.bytes_hashed < sum(segment.size for segment in second.segments)
    assert first_path.stat().st_ino == first_stat.st_ino
    assert first_path.stat().st_mtime_ns == first_stat.st_mtime_ns
    recovery = store.recover(expected_fingerprint=_FINGERPRINT)
    assert recovery.manifest.sequence == 1
    assert store.read_segment(recovery.manifest.segments[0]) in {
        b"first delta" * 100,
        b"second delta" * 100,
    }


def test_store_rotates_manifests_and_collects_unreferenced_segments(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"retired")
    retired_path = store.workspace / first.segments[0].relative_path
    second = _commit(
        store,
        sequence=1,
        hour=12,
        inherited=first.segments,
        payload=b"retained",
    )
    retained = tuple(
        segment for segment in second.segments if segment.sha256 != first.segments[0].sha256
    )
    _commit(store, sequence=2, hour=18, inherited=retained)
    assert retired_path.exists()
    _commit(store, sequence=3, hour=24, inherited=retained)
    assert not retired_path.exists()
    assert [path.name for path in store._recovery_directories()] == [
        "00000000000000000003",
        "00000000000000000002",
    ]


def test_store_falls_back_when_newest_head_is_corrupt(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"first")
    second = _commit(store, sequence=1, hour=12, inherited=first.segments, payload=b"second")
    newest_head = store.workspace / second.participant_heads[0].relative_path
    newest_head.write_bytes(b"tampered")

    recovery = store.recover(expected_fingerprint=_FINGERPRINT)

    assert recovery.used_fallback
    assert recovery.manifest.sequence == 0
    assert recovery.warning is not None
    assert "newest generation checkpoint was corrupt" in recovery.warning


def test_store_rejects_fingerprint_mismatch_without_falling_back(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit(store, sequence=0, hour=6, payload=b"first")
    with pytest.raises(CheckpointCompatibilityError, match="fingerprint"):
        store.recover(expected_fingerprint="2" * 64)


def test_store_rejects_symlinked_content(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    manifest = _commit(store, sequence=0, hour=6, payload=b"first")
    segment_path = store.workspace / manifest.segments[0].relative_path
    replacement = tmp_path / "replacement"
    replacement.write_bytes(segment_path.read_bytes())
    segment_path.unlink()
    segment_path.symlink_to(replacement)
    with pytest.raises(CheckpointCorruptionError, match="symlink"):
        store.recover(expected_fingerprint=_FINGERPRINT)


def test_store_rejects_resealing_an_inherited_segment(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"same")
    with pytest.raises(ValueError, match="reseal"):
        _commit(
            store,
            sequence=1,
            hour=12,
            inherited=first.segments,
            payload=b"same",
        )


def test_run_lock_rejects_live_owner_and_reclaims_dead_local_owner(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first = RunLock(workspace)
    first.acquire()
    with pytest.raises(CheckpointLockError, match="live process"):
        RunLock(workspace).acquire()
    first.release()

    workspace.mkdir(exist_ok=True)
    lock_path = workspace / "run.lock"
    lock_path.write_text(
        json.dumps({"hostname": socket.gethostname(), "pid": 2**31 - 1}),
        encoding="utf-8",
    )
    replacement = RunLock(workspace)
    replacement.acquire()
    assert json.loads(lock_path.read_text(encoding="utf-8"))["pid"] == os.getpid()
    replacement.release()


def test_manifest_rejects_unknown_segment_reference() -> None:
    with pytest.raises(ValidationError, match="unknown segments"):
        CheckpointManifest(
            sequence=0,
            run_id="run",
            run_fingerprint=_FINGERPRINT,
            checkpoint_hours=6,
            cursor=_cursor(6),
            resolved_scenario_sha256="2" * 64,
            resolved_scenario_relative_path="objects/resolved/22/input.yaml",
            participant_heads=(
                {
                    "owner": "engine",
                    "schema_version": "1",
                    "relative_path": "recovery/0/heads/engine.bin",
                    "size": 1,
                    "sha256": "3" * 64,
                    "referenced_segments": ("4" * 64,),
                },
            ),
        )
