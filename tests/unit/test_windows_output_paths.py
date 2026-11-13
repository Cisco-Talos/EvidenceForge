"""Native output I/O must not depend on the machine's long-path policy."""

from __future__ import annotations

import builtins
import errno
import io
import os
import shutil
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from evidenceforge._windows_paths import filesystem_path, resolve_path
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.utils.paths import safe_write_text

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows output path contract")


@pytest.fixture
def legacy_path_limit(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Reject ordinary long paths even when the runner enables long-path policy."""
    denied: list[str] = []
    stacks: dict[str, str] = {}

    def guard(function: Callable[..., Any], path_count: int = 1) -> Callable[..., Any]:
        def checked(*args: Any, **kwargs: Any) -> Any:
            for argument in args[:path_count]:
                if isinstance(argument, (str, bytes, os.PathLike)):
                    path = os.fsdecode(argument)
                    if len(path) >= 260 and not path.startswith("\\\\?\\"):
                        denied.append(path)
                        stacks[path] = "".join(traceback.format_stack(limit=10))
                        raise FileNotFoundError(errno.ENOENT, "Legacy Windows path limit", path)
            return function(*args, **kwargs)

        return checked

    for name in ("open", "stat", "lstat", "mkdir", "unlink", "rmdir", "scandir"):
        monkeypatch.setattr(os, name, guard(getattr(os, name)))
    monkeypatch.setattr(os, "replace", guard(os.replace, 2))
    monkeypatch.setattr(io, "open", guard(io.open))
    monkeypatch.setattr(builtins, "open", guard(builtins.open))
    yield denied
    assert denied == [], "Unprefixed long-path I/O:\n" + "\n".join(
        f"{path}\n{stacks[path]}" for path in denied
    )


@pytest.mark.parametrize("checkpoint", [False, True])
def test_long_sorted_exact_retry_checkpoint_merge_and_cleanup(
    tmp_path: Path, legacy_path_limit: list[str], monkeypatch: pytest.MonkeyPatch, checkpoint: bool
) -> None:
    parent = tmp_path / ("workspace 汉 ü " + "a" * 95) / ("runs " + "b" * 95)
    output = parent / ("source-" + "c" * 210 + ".ndjson")
    assert len(str(output)) > 300
    # Negative control proves this runner really exercises the policy-independent path.
    with pytest.raises(FileNotFoundError, match="Legacy Windows path limit"):
        os.open(output, os.O_RDONLY)
    assert legacy_path_limit == [str(output)]
    legacy_path_limit.clear()
    writer = ExternalSortedLineWriter(
        output, sort_key=str, buffer_size=1, merge_fan_in=2, checkpoint_mode=checkpoint
    )
    original_replace = os.replace
    failed = False

    def lost_return(source: Path, target: Path) -> None:
        nonlocal failed
        original_replace(source, target)
        if not failed and Path(target).name.startswith("exact-"):
            failed = True
            raise OSError("rename succeeded before lost return")

    monkeypatch.setattr(os, "replace", lost_return)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: writer.write("02|exact"))
    with pytest.raises(OSError, match="lost return"):
        batch.commit()
    batch.commit()
    batch.release_no_fail()
    assert failed and writer.event_count == 1
    for index in reversed(range(8)):
        writer.write(f"{index:02d}|ordinary")
    writer.flush()
    assert writer.output_path == output
    if checkpoint:
        count, sequence, runs = writer.checkpoint_snapshot()
        assert count == 9 and runs
        assert all(not str(path).startswith("\\\\?\\") for path in runs)
        restored_output = parent / "restored" / output.name
        restored_spool = restored_output.parent / ".restored-runs"
        filesystem_path(restored_spool).mkdir(parents=True)
        restored_runs = tuple(restored_spool / path.name for path in runs)
        for source, target in zip(runs, restored_runs, strict=True):
            shutil.copyfile(filesystem_path(source), filesystem_path(target))
        restored = ExternalSortedLineWriter(
            restored_output, sort_key=str, checkpoint_mode=True, merge_fan_in=2
        )
        restored.restore_checkpoint_runs(
            paths=restored_runs, event_count=count, run_sequence=sequence
        )
        restored.write("09|after-resume")
        restored.close()
        assert filesystem_path(restored_output).read_text().splitlines() == sorted(
            ["02|exact", *(f"{index:02d}|ordinary" for index in range(8)), "09|after-resume"]
        )
        assert not filesystem_path(restored_spool).exists()
        writer.checkpoint_committed()
    else:
        # Flush normalizes to the logical output; subsequent merge must read it safely.
        writer.write("09|after-flush")
    writer.close()
    expected = ["02|exact", *(f"{index:02d}|ordinary" for index in range(8))]
    if not checkpoint:
        expected.append("09|after-flush")
    assert resolve_path(output, strict=True) == output
    assert resolve_path(filesystem_path(output), strict=True) == filesystem_path(output)
    assert filesystem_path(output).read_text().splitlines() == sorted(expected)
    assert not list(filesystem_path(parent).glob(".efsort-*"))
    assert not list(filesystem_path(parent).glob(".efmerge-*"))
    assert writer.exact_journal_census().admitted_rows == 0


def test_long_atomic_text_write_replaces_only_destination(
    tmp_path: Path, legacy_path_limit: list[str]
) -> None:
    parent = tmp_path / ("workspace ü " + "a" * 95) / ("draft " + "b" * 95)
    target = parent / ("scenario-" + "c" * 210 + ".yaml")
    safe_write_text(target, "first\n")
    safe_write_text(target, "replacement\n")
    assert filesystem_path(target).read_text() == "replacement\n"
    assert not list(filesystem_path(parent).glob(".efwrite-*"))
    sentinel = parent / "authored-sentinel.yaml"
    filesystem_path(sentinel).write_text("preserve unrelated authored work")
    safe_write_text(target, "third\n")
    assert filesystem_path(sentinel).read_text() == "preserve unrelated authored work"


def test_long_checkpoint_publication_recovery_integrity_and_reclamation(
    tmp_path: Path, legacy_path_limit: list[str]
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from evidenceforge.generation.checkpoints.models import CheckpointCursor
    from evidenceforge.generation.checkpoints.store import HeadDraft, IncrementalCheckpointStore

    root = tmp_path / ("workspace 汉 ü " + "a" * 95) / ("runs " + "b" * 95)
    assert len(str(root)) > 260
    assert resolve_path(root) == root
    store = IncrementalCheckpointStore(root)
    assert store.output_root == root
    for sequence in range(3):
        store.commit(
            sequence=sequence,
            run_id="native-long-path",
            run_fingerprint="a" * 64,
            checkpoint_hours=1,
            cursor=CheckpointCursor(
                phase="collection",
                completed_simulated_hours=sequence + 1,
                next_hour=f"2026-01-01T0{sequence + 1}:00:00+00:00",
            ),
            resolved_scenario=b"resolved",
            inherited_catalogs=(),
            new_segments=(),
            heads=(HeadDraft(owner="engine", schema_version="1", payload=b"head"),),
        )
    restarted = IncrementalCheckpointStore(root)
    recovery = restarted.recover(read_only=True)
    assert recovery.manifest.sequence == 2
    assert restarted.read_resolved_scenario(recovery) == b"resolved"
    assert restarted.read_head(recovery, "engine") == b"head"
    assert [sequence for sequence, _ in restarted.recovery_index_entries()] == [2, 1]
    dependency = store.workspace / recovery.manifest.resolved_scenario_relative_path
    filesystem_path(dependency).write_bytes(b"tampered")
    with pytest.raises(CheckpointCorruptionError):
        restarted.read_resolved_scenario(recovery)
    store.remove_workspace()
    assert not filesystem_path(store.workspace).exists()


@pytest.mark.parametrize("host_writer", [False, True])
def test_long_direct_writer_headers_exact_rows_and_footers(
    tmp_path: Path, legacy_path_limit: list[str], host_writer: bool
) -> None:
    from evidenceforge.formats import load_format
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.emitters.host_base import _SingleHostWriter

    root = tmp_path / ("workspace ü " + "a" * 95) / ("runs " + "b" * 95)
    output = root / "events.xml"
    assert len(str(output)) > 260
    if host_writer:
        writer = _SingleHostWriter(output, buffer_size=1)
        writer.write_header("<Events>")
        writer.write("ordinary")
        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        batch.publish(lambda: writer.write("exact"))
        batch.release_no_fail()
        writer.write_footer("</Events>")
        writer.close()
    else:

        class RowEmitter(LogEmitter):
            def emit_event(self, event_data: dict[str, Any]) -> None:
                self._buffer_event(self._render_event(event_data))

            def _render_event(self, event_data: dict[str, Any]) -> str:
                return event_data["row"]

        emitter = RowEmitter(load_format("windows_event_security"), output, buffer_size=1)
        emitter.emit_event({"row": "ordinary"})
        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        batch.publish(lambda: emitter.emit_event({"row": "exact"}))
        batch.release_no_fail()
        emitter.close()
    text = filesystem_path(output).read_text()
    assert text.count("ordinary") == text.count("exact") == 1
    assert "<Events>" in text and "</Events>" in text
