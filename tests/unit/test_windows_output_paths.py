"""Native output I/O must not depend on the machine's long-path policy."""

from __future__ import annotations

import builtins
import errno
import io
import os
import shutil
import stat
import subprocess
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
    os.chmod(filesystem_path(dependency), stat.S_IREAD)
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


def test_long_uninstall_inventory_staging_and_removal(
    tmp_path: Path, legacy_path_limit: list[str]
) -> None:
    from evidenceforge.studio.state_io import private_directory
    from evidenceforge.studio.windows_uninstall import UserLocations, build_plan, execute
    from evidenceforge.utils.windows_filesystem import current_user_sid

    profile = tmp_path / "account 汉 ü"
    private_directory(profile)
    local = profile / "AppData/Local"
    private = local / "EvidenceForge"
    deep = (
        private
        / "runtimes/retained/Lib/site-packages"
        / ("catalog-" + "a" * 140)
        / ("b" * 90)
        / "resource.yaml"
    )
    assert len(str(deep)) > 300
    filesystem_path(deep.parent).mkdir(parents=True)
    filesystem_path(deep).write_text("selected runtime resource")
    unrelated = profile / "unrelated.txt"
    unrelated.write_text("preserve")
    plan = build_plan(
        UserLocations(
            profile=profile,
            local=local,
            documents=profile / "Documents",
            account=current_user_sid(),
        )
    )
    execute(plan, set())
    assert filesystem_path(deep).read_text() == "selected runtime resource"
    execute(plan, {"private"})
    assert not private.exists()
    assert unrelated.read_text() == "preserve"
    assert legacy_path_limit == []


@pytest.mark.parametrize("persistent", [False, True])
def test_sorted_close_releases_native_delete_block_without_losing_retry_state(
    tmp_path: Path,
    legacy_path_limit: list[str],
    monkeypatch: pytest.MonkeyPatch,
    persistent: bool,
) -> None:
    from evidenceforge import _windows_cleanup as cleanup
    from evidenceforge.utils.windows_filesystem import open_directory

    output = tmp_path / ("workspace ü " + "a" * 95) / ("runs " + "b" * 95) / "rows.log"
    writer = ExternalSortedLineWriter(output, sort_key=str, buffer_size=1)
    writer.write("02|second")
    writer.write("01|first")
    spool = writer._spool_dir
    assert spool is not None
    descriptor = open_directory(spool)
    waits: list[float] = []

    def release_after_denial(delay: float) -> None:
        nonlocal descriptor
        waits.append(delay)
        if not persistent and descriptor is not None:
            os.close(descriptor)
            descriptor = None

    monkeypatch.setattr(cleanup, "sleep", release_after_denial)
    try:
        if persistent:
            with pytest.raises(PermissionError):
                writer.close()
            assert writer._spool_dir == spool
            assert writer._close_state == "cleanup-pending" and not writer._closed
            assert len(waits) == len(cleanup._DELETE_RETRY_DELAYS)
            os.close(descriptor)
            descriptor = None
        writer.close()
        assert waits
        assert filesystem_path(output).read_text().splitlines() == ["01|first", "02|second"]
        assert writer.event_count == 2 and writer._closed
        assert writer._spool_dir is None and not filesystem_path(spool).exists()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        writer.close()


@pytest.mark.parametrize("persistent", [False, True])
def test_native_es_ingress_cleanup_retries_without_changing_exported_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, persistent: bool
) -> None:
    from evidenceforge import _windows_cleanup as cleanup
    from evidenceforge.utils.windows_filesystem import open_directory
    from tests.unit.test_macos_es_ingress import _publish

    _, dispatcher, output, ingress, _ = _publish(tmp_path)
    ingress.finalize(dispatcher)
    output.close()
    ingress.verify_export(dispatcher)
    exported = next((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    retained = exported.read_bytes()
    descriptor = open_directory(ingress.root)
    waits: list[float] = []

    def release_after_denial(delay: float) -> None:
        nonlocal descriptor
        waits.append(delay)
        if not persistent and descriptor is not None:
            os.close(descriptor)
            descriptor = None

    monkeypatch.setattr(cleanup, "sleep", release_after_denial)
    try:
        # The original unguarded cleanup really fails on this native handle;
        # this is not an injected Python PermissionError.
        with pytest.raises(PermissionError) as denied:
            shutil.rmtree(filesystem_path(ingress.root))
        assert denied.value.winerror in {5, 32}
        if persistent:
            with pytest.raises(PermissionError):
                ingress.cleanup()
            assert ingress.root.is_dir() and ingress.finalized
            assert len(waits) == len(cleanup._DELETE_RETRY_DELAYS)
            os.close(descriptor)
            descriptor = None
        ingress.cleanup()
        assert waits and not ingress.root.exists()
        assert exported.read_bytes() == retained
        ingress.verify_export(dispatcher)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        ingress.cleanup()


@pytest.mark.parametrize("directory", [False, True])
def test_native_scratch_cleanup_clears_only_readonly_attribute(
    tmp_path: Path, directory: bool
) -> None:
    from evidenceforge._windows_cleanup import remove_temporary_tree

    root = tmp_path / "owned scratch"
    root.mkdir()
    entry = root / "readonly"
    if directory:
        entry.mkdir()
    else:
        entry.write_text("temporary")
    os.chmod(entry, stat.S_IREAD)
    assert entry.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    remove_temporary_tree(root)
    assert not root.exists()


def test_native_readonly_repair_never_changes_junction_target(tmp_path: Path) -> None:
    from evidenceforge._windows_cleanup_native import clear_readonly_for_removal

    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "authored.txt"
    sentinel.write_text("preserve")
    junction = tmp_path / "junction"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=True,
        capture_output=True,
    )
    os.chmod(outside, stat.S_IREAD)
    try:
        assert clear_readonly_for_removal(junction) is False
        assert outside.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
        assert sentinel.read_text() == "preserve"
    finally:
        os.chmod(outside, stat.S_IWRITE)
        junction.rmdir()


def test_native_readonly_repair_refuses_multiply_linked_file(tmp_path: Path) -> None:
    from evidenceforge._windows_cleanup_native import clear_readonly_for_removal

    outside = tmp_path / "outside.txt"
    outside.write_text("preserve")
    linked = tmp_path / "linked.txt"
    os.link(outside, linked)
    os.chmod(outside, stat.S_IREAD)
    try:
        assert clear_readonly_for_removal(linked) is False
        assert outside.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
        assert outside.read_text() == "preserve"
    finally:
        os.chmod(outside, stat.S_IWRITE)


def test_native_registered_output_rollback_cleans_readonly_generated_data(tmp_path: Path) -> None:
    from evidenceforge.composition.sidecars import SIDECAR_REGISTRY

    data = tmp_path / "data"
    data.mkdir()
    generated = data / "generated.log"
    generated.write_text("generated output")
    os.chmod(generated, stat.S_IREAD)
    sentinel = tmp_path / "ENVIRONMENT.md"
    sentinel.write_text("preserve authored collateral")
    SIDECAR_REGISTRY._remove(data)
    assert not data.exists()
    assert sentinel.read_text() == "preserve authored collateral"
