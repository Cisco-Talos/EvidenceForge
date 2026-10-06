"""Real native termination/restart matrix; no in-process cleanup can mask publication faults."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from evidenceforge.studio.state_upgrade import StateCoordinator
from tests.integration.test_studio_state_migrations import MOVES
from tests.integration.test_studio_state_upgrade import BOUNDARIES, fail_once
from tests.support.studio_state import committed_wal, inventory, legacy, paths
from tests.support.studio_state_boundaries import RESTORE_JOURNALS, UPGRADE_JOURNALS


def terminate_at(root: Path, boundary: str, action: str = "upgrade") -> None:
    process = subprocess.Popen(
        [sys.executable, "-m", "tests.support.studio_state_worker", str(root), boundary, action],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    assert process.stdout is not None
    with ThreadPoolExecutor(max_workers=1) as executor:
        reading = executor.submit(process.stdout.readline)
        try:
            line = reading.result(timeout=20)
            assert json.loads(line) == {"boundary": boundary}, line
        finally:
            if process.poll() is None:
                process.kill()  # This exact Popen child has not been reaped, so PID reuse is impossible.
            process.communicate(timeout=10)
            assert process.returncode != 0


def recover_in_fresh_process(root: Path, expected: str = "ready", action: str = "recover") -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tests.support.studio_state_worker", str(root), "none", action],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    status = json.loads(result.stdout)
    assert status["result"] == expected, status


def test_native_crash_smoke_preserves_identity_and_releases_lock(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    terminate_at(tmp_path, "database.after_commit")
    recover_in_fresh_process(tmp_path)
    assert inventory(selected.database_file) == before


@pytest.mark.slow
@pytest.mark.parametrize("restore", [False, True])
def test_native_wal_upgrade_and_restore_crashes_retain_committed_records(
    tmp_path: Path, restore: bool
) -> None:
    selected = legacy(tmp_path)
    committed_wal(selected)
    before = inventory(selected.database_file)
    terminate_at(tmp_path, "database.after_replace" if restore else "database.after_checkpoint")
    if restore:
        terminate_at(tmp_path, "database.after_replace", "restore")
    recover_in_fresh_process(tmp_path, "restored" if restore else "ready")
    assert inventory(selected.database_file) == before


@pytest.mark.slow
@pytest.mark.parametrize("restore", [False, True])
@pytest.mark.parametrize(
    "boundary",
    [
        *(
            f"{StateCoordinator.file_key(path)}.{side}_replace"
            for path in (MOVES[0].moves[0].source, MOVES[-1].moves[0].target)
            for side in ("before", "after")
        ),
        "layout.before_replace",
        "layout.after_replace",
    ],
)
def test_native_filesystem_step_crashes_preserve_or_restore_originals(
    tmp_path: Path, boundary: str, restore: bool
) -> None:
    selected = legacy(tmp_path)
    workspace = tmp_path / "workspace"
    baseline = StateCoordinator(selected, workspace)
    assert baseline.apply(baseline.status.operation_id).state == "ready"
    marker = baseline.layout.read_bytes()
    baseline.close()
    original = workspace / MOVES[0].moves[0].source
    original.parent.mkdir()
    original.write_bytes(b"original saved UI view")
    before = inventory(selected.database_file)
    engine = (tmp_path / "immutable.yaml").read_bytes()
    terminate_at(tmp_path, boundary, "workspace-upgrade")
    recover_in_fresh_process(
        tmp_path,
        "restored" if restore else "ready",
        "workspace-restore" if restore else "workspace-recover",
    )
    target = workspace / MOVES[-1].moves[0].target
    if restore:
        assert original.read_bytes() == b"original saved UI view" and not target.exists()
        assert (workspace / ".eforge/studio/layout.json").read_bytes() == marker
    else:
        assert not original.exists() and target.read_bytes() == b"original saved UI view"
    assert inventory(selected.database_file) == before
    assert (tmp_path / "immutable.yaml").read_bytes() == engine


@pytest.mark.slow
@pytest.mark.parametrize("boundary", BOUNDARIES)
def test_native_upgrade_boundary_crashes_recover_without_record_loss(
    tmp_path: Path, boundary: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    engine = {path: path.read_bytes() for path in tmp_path.rglob("*.yaml")}
    terminate_at(tmp_path, boundary)
    recover_in_fresh_process(tmp_path)
    assert inventory(selected.database_file) == before
    assert all(path.read_bytes() == content for path, content in engine.items())


@pytest.mark.slow
@pytest.mark.parametrize(
    "boundary",
    [
        "database.before_replace",
        "database.after_replace",
        "settings.before_replace",
        "settings.after_replace",
        "layout.before_replace",
        "layout.after_replace",
        "journal.before_write",
        "journal.after_write",
        "completion.before",
        "completion.after",
    ],
)
def test_native_restore_boundary_crashes_resume_restoration(tmp_path: Path, boundary: str) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    coordinator.close()
    terminate_at(tmp_path, boundary, "restore")
    recover_in_fresh_process(
        tmp_path, "restored", "restore" if boundary == "journal.before_write" else "recover"
    )
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    assert not (selected.data / "studio-state.json").exists()


@pytest.mark.slow
def test_repeated_upgrade_and_restore_crashes_keep_original_backup(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    terminate_at(tmp_path, "settings.after_replace")
    terminate_at(tmp_path, "layout.after_replace")
    terminate_at(tmp_path, "database.after_replace")
    terminate_at(tmp_path, "settings.after_replace", "restore")
    terminate_at(tmp_path, "layout.after_replace", "restore")
    terminate_at(tmp_path, "database.after_replace", "restore")
    recover_in_fresh_process(tmp_path, "restored")
    assert inventory(selected.database_file) == before


@pytest.mark.slow
@pytest.mark.parametrize("boundary", UPGRADE_JOURNALS)
def test_every_upgrade_journal_publication_survives_native_termination(
    tmp_path: Path, boundary: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    terminate_at(tmp_path, boundary)
    recover_in_fresh_process(tmp_path)
    assert inventory(selected.database_file) == before


@pytest.mark.slow
@pytest.mark.parametrize("boundary", RESTORE_JOURNALS)
def test_every_restore_journal_publication_survives_native_termination(
    tmp_path: Path, boundary: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    coordinator.close()
    terminate_at(tmp_path, boundary, "restore")
    # Before the first durable restore intent, a fresh caller must request restore again.
    action = (
        "restore" if boundary == "journal.restore.running.0.package.before_write" else "recover"
    )
    recover_in_fresh_process(tmp_path, "restored", action)
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    assert not (selected.data / "studio-state.json").exists()


@pytest.mark.slow
@pytest.mark.parametrize(
    "boundary",
    [
        "database.before_commit",
        "database.after_commit",
        "settings.before_replace",
        "settings.after_replace",
        "layout.before_replace",
        "layout.after_replace",
        "completion.before",
        "completion.after",
    ],
)
def test_fresh_initialization_crashes_resume_without_a_recovery_backup(
    tmp_path: Path, boundary: str
) -> None:
    terminate_at(tmp_path, boundary, "fresh")
    recover_in_fresh_process(tmp_path)
    selected = paths(tmp_path / "private")
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "ready" and not coordinator.status.warning
    assert not list(coordinator.control_root.glob("*/manifest.json"))
    coordinator.close()
