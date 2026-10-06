"""Runtime expiry, uncertain safety warnings, and real detached-worker lease ownership."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import psutil
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from evidenceforge.desktop.jobs import _start_process
from evidenceforge.studio import runtime_cleanup as cleanup
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.runtime import RuntimeRelease
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.state_io import StateLock, atomic_write


def _runtime(data: Path, digit: str, *, legacy: bool = False) -> Path:
    root = data / "runtimes" / f"{digit * 64}-aarch64"
    root.mkdir(parents=True)
    (root / "release.json").write_text(
        RuntimeRelease(
            runtime_id=digit * 64,
            evidenceforge_version="2.1.2",
            python_version="3.12.12",
            architecture="aarch64",
        ).model_dump_json()
    )
    if not legacy:
        (root / ".cleanup-lease-v1").write_bytes(b"1\n")
    (root / "payload.txt").write_text("disposable installation")
    return root


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> cleanup.RuntimeCleanup:
    data = tmp_path / "data"
    selected = _runtime(data, "a")
    monkeypatch.setattr(cleanup, "_process_use", lambda root: (False, None))
    manager = cleanup.RuntimeCleanup(data, selected)
    manager.successful_launch()
    return manager


def _age(manager: cleanup.RuntimeCleanup, *roots: Path, days: int = 40) -> None:
    history = manager._history()
    history.first_seen.update({root.name: time.time() - days * 86400 for root in roots})
    manager._save(history)


def test_newly_discovered_runtime_has_full_grace_and_workspace_is_untouched(
    cache: cleanup.RuntimeCleanup, tmp_path: Path
) -> None:
    old = _runtime(cache.directory.parent, "b")
    workspace = tmp_path / "workspace/packs/industry"
    workspace.mkdir(parents=True)
    (workspace / "pack.yaml").write_text("authored pack")
    first = time.time()
    assert not cache.clean(now=first).removed
    assert not cache.clean(now=first + 86400 - 1).removed
    report = cache.clean(now=first + 86400)
    assert report.removed == [old.name] and not report.warnings
    assert not old.exists() and cache.selected is not None and cache.selected.is_dir()
    assert (workspace / "pack.yaml").read_text() == "authored pack"
    assert (cache.directory / "leases" / f"{old.name}.lock").exists()


def test_previous_successful_launch_expires_from_replacement_and_setting_is_persistent(
    cache: cleanup.RuntimeCleanup,
) -> None:
    previous = cache.selected
    assert previous is not None
    selected = _runtime(cache.directory.parent, "b")
    other = _runtime(cache.directory.parent, "c")
    updated = cleanup.RuntimeCleanup(cache.directory.parent, selected)
    replacement = time.time()
    updated.successful_launch(now=replacement)
    _age(updated, previous, other)
    # A repeated launch must not extend the rollback clock.
    updated.successful_launch(now=replacement + 100)
    assert updated._history().replaced_at == replacement
    report = updated.clean(now=replacement + 29 * 86400)
    assert report.removed == [other.name] and previous.is_dir()
    updated.save_settings(cleanup.RuntimeCleanupSettings(previous_runtime_days=45))
    reopened = cleanup.RuntimeCleanup(cache.directory.parent, selected)
    assert reopened.settings().previous_runtime_days == 45
    assert not reopened.clean(now=replacement + 30 * 86400).removed
    report = reopened.clean(now=replacement + 45 * 86400)
    assert report.removed == [previous.name] and selected.is_dir()


def test_zero_rollback_days_still_keeps_new_discovery_grace(cache: cleanup.RuntimeCleanup) -> None:
    previous = cache.selected
    selected = _runtime(cache.directory.parent, "b")
    updated = cleanup.RuntimeCleanup(cache.directory.parent, selected)
    timestamp = time.time()
    updated.successful_launch(now=timestamp)
    updated.save_settings(cleanup.RuntimeCleanupSettings(previous_runtime_days=0))
    assert not updated.clean(now=timestamp).removed
    assert updated.clean(now=timestamp + 86400).removed == [previous.name]


def test_superseded_helper_cannot_remove_latest_successful_runtime(
    cache: cleanup.RuntimeCleanup,
) -> None:
    latest = _runtime(cache.directory.parent, "b")
    updated = cleanup.RuntimeCleanup(cache.directory.parent, latest)
    updated.successful_launch()
    _age(updated, latest)
    assert not cache.clean(now=time.time() + 100 * 86400).removed
    assert latest.is_dir()


@pytest.mark.parametrize("days", [-1, 3651, 1.5, True])
def test_retention_configuration_rejects_invalid_values(days: object) -> None:
    with pytest.raises(ValidationError):
        cleanup.RuntimeCleanupSettings(previous_runtime_days=days)


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, 2])
def test_cache_contract_versions_are_exact_integers(version: object) -> None:
    for model in (cleanup.RuntimeCleanupSettings, cleanup.RuntimeHistory):
        with pytest.raises(ValidationError):
            model.model_validate({"schema_version": version})


def test_eligible_legacy_runtime_is_retained_with_specific_warning(
    cache: cleanup.RuntimeCleanup,
) -> None:
    old = _runtime(cache.directory.parent, "b", legacy=True)
    _age(cache, old)
    report = cache.clean()
    assert old.is_dir() and not report.removed
    assert len(report.warnings) == 1
    assert report.warnings[0].path == old
    assert "older Studio builds" in report.warnings[0].message


def test_uncertain_process_census_retains_runtime_and_warning_clears_after_retry(
    cache: cleanup.RuntimeCleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    monkeypatch.setattr(
        cleanup, "_process_use", lambda root: (False, "Cannot inspect process 123.")
    )
    report = cache.clean()
    assert old.is_dir() and "process 123" in report.warnings[0].message
    monkeypatch.setattr(cleanup, "_process_use", lambda root: (False, None))
    report = cache.clean()
    assert report.removed == [old.name] and not report.warnings


def test_verified_process_use_is_protected_without_uncertainty_warning(
    cache: cleanup.RuntimeCleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    monkeypatch.setattr(cleanup, "_process_use", lambda root: (True, None))
    report = cache.clean()
    assert old.is_dir() and not report.removed and not report.warnings


def test_warning_report_remains_coherent_during_a_cleanup_retry(
    cache: cleanup.RuntimeCleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _runtime(cache.directory.parent, "b", legacy=True)
    _age(cache, old)
    original = cache.clean()
    entered, release = Event(), Event()

    def paused(
        self: cleanup.RuntimeCleanup, *, now: float | None = None
    ) -> cleanup.RuntimeCleanupReport:
        self.report = cleanup.RuntimeCleanupReport()
        entered.set()
        assert release.wait(timeout=5)
        return original

    monkeypatch.setattr(cleanup.RuntimeCleanup, "_clean", paused)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cache.clean)
        try:
            assert entered.wait(timeout=5)
            assert cache.report is original and cache.report.warnings
        finally:
            release.set()
        assert future.result(timeout=5) is original


def test_real_detached_generation_worker_holds_lease_after_helper_releases_it(
    cache: cleanup.RuntimeCleanup, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    monkeypatch.setenv("EFORGE_STUDIO_RUNTIME_ROOT", str(old))
    ready = tmp_path / "ready"
    process: psutil.Process | None = None
    try:
        with cleanup.runtime_lease():
            pid, _ = _start_process(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); time.sleep(20)",
                    str(ready),
                ],
                cwd=tmp_path,
                log_file=tmp_path / "worker.log",
            )
            process = psutil.Process(pid)
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert ready.exists()
        assert not cleanup.runtime_worker_fds()
        report = cache.clean()
        assert old.is_dir() and not report.removed and not report.warnings
        process.terminate()
        process.wait(timeout=5)
        report = cache.clean()
        assert report.removed == [old.name]
    finally:
        if process is not None and process.is_running():
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("damage", ["receipt", "settings", "history", "symlink"])
def test_unknown_or_aliased_state_is_not_deleted_or_reset(
    cache: cleanup.RuntimeCleanup, tmp_path: Path, damage: str
) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    if damage == "receipt":
        (old / "release.json").write_text('{"schema_version":99}')
    elif damage == "settings":
        atomic_write(cache.settings_path, b'{"schema_version":99}')
    elif damage == "history":
        atomic_write(cache.directory / "usage.json", b'{"schema_version":99}')
    else:
        destination = tmp_path / "outside-runtime"
        old.rename(destination)
        old.symlink_to(destination, target_is_directory=True)
    report = cache.clean()
    assert old.exists() and not report.removed and report.warnings
    if damage == "settings":
        assert cache.settings_path.read_bytes() == b'{"schema_version":99}'
        with pytest.raises(ValidationError):
            cache.save_settings(cleanup.RuntimeCleanupSettings())


def test_removal_failure_warns_and_retry_finishes_atomic_retirement(
    cache: cleanup.RuntimeCleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    original = cleanup.shutil.rmtree

    def partial_failure(path: Path) -> None:
        (path / "release.json").unlink()
        (path / ".cleanup-lease-v1").unlink()
        raise PermissionError("removal unavailable")

    failure = Mock(side_effect=partial_failure)
    failure.avoids_symlink_attacks = True
    monkeypatch.setattr(cleanup.shutil, "rmtree", failure)
    report = cache.clean()
    retired = cache.directory / f".retired-{old.name}"
    assert retired.is_dir() and not old.exists() and report.warnings
    assert report.warnings[0].path == retired
    assert "removal unavailable" in report.warnings[0].message
    monkeypatch.setattr(cleanup.shutil, "rmtree", original)
    report = cleanup.RuntimeCleanup(cache.directory.parent, cache.selected).clean()
    assert report.removed == [old.name] and not retired.exists()


def test_payload_symlinks_are_unlinked_without_deleting_their_targets(
    cache: cleanup.RuntimeCleanup, tmp_path: Path
) -> None:
    old = _runtime(cache.directory.parent, "b")
    authored = tmp_path / "authored-pack"
    authored.mkdir()
    (authored / "pack.yaml").write_text("user data")
    (old / "linked-data").symlink_to(authored, target_is_directory=True)
    _age(cache, old)
    assert cache.clean().removed == [old.name]
    assert (authored / "pack.yaml").read_text() == "user data"


def test_process_list_failure_is_explicit_uncertainty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cleanup.psutil, "process_iter", Mock(side_effect=PermissionError("restricted census"))
    )
    assert cleanup._process_use(Path("/unused-runtime")) == (
        False,
        "Cannot inspect the process list to verify this runtime is unused.",
    )


def test_installer_ownership_blocks_cleanup_with_warning(cache: cleanup.RuntimeCleanup) -> None:
    old = _runtime(cache.directory.parent, "b")
    _age(cache, old)
    with StateLock(cache.directory / "install.lock"):
        report = cache.clean()
    assert old.is_dir() and report.warnings
    assert "owns this state" in report.warnings[0].message


def test_saved_retention_remains_visible_when_selected_runtime_cannot_be_verified(
    cache: cleanup.RuntimeCleanup,
) -> None:
    cache.save_settings(cleanup.RuntimeCleanupSettings(previous_runtime_days=7))
    assert cache.selected is not None
    (cache.selected / "release.json").write_text('{"schema_version":99}')
    report = cache.clean()
    assert report.settings.previous_runtime_days == 7 and report.warnings


def test_actual_census_protects_unleased_process_and_reports_access_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)", str(root)])
    try:
        assert cleanup._process_use(root) == (True, None)
    finally:
        process.terminate()
        process.wait(timeout=5)
    inaccessible = Mock(pid=123)
    inaccessible.uids.side_effect = psutil.AccessDenied(123)
    monkeypatch.setattr(cleanup.psutil, "process_iter", lambda: [inaccessible])
    assert cleanup._process_use(root) == (
        False,
        "Cannot inspect process 123 to verify this runtime is unused.",
    )


def test_cleanup_api_requires_auth_persists_setting_and_bootstrap_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StudioService, "start", quiet_start)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.delenv("EFORGE_STUDIO_RUNTIME_ROOT", raising=False)
    paths = StudioPaths(
        **{key: tmp_path / key for key in ("data", "config", "state", "cache", "logs")}
    )
    app = create_app(paths, "secret")
    studio = app.state.studio
    selected = _runtime(paths.data, "a")
    old = _runtime(paths.data, "b", legacy=True)
    studio.runtime_cleanup = cleanup.RuntimeCleanup(paths.data, selected)
    studio.runtime_cleanup.successful_launch()
    _age(studio.runtime_cleanup, old)
    settings_before = paths.settings_file.read_bytes() if paths.settings_file.exists() else None
    endpoint = "/v1/runtime/cleanup-settings"
    headers = {"X-EForge-Token": "secret"}
    with TestClient(app) as client:
        assert client.put(endpoint, json={"previous_runtime_days": 7}).status_code == 401
        assert (
            client.put(endpoint, json={"previous_runtime_days": -1}, headers=headers).status_code
            == 422
        )
        result = client.put(endpoint, json={"previous_runtime_days": 7}, headers=headers)
        assert result.status_code == 200
        assert result.json()["settings"]["previous_runtime_days"] == 7
        report = client.get("/v1/bootstrap", headers=headers).json()["runtime_cleanup"]
        assert report["warnings"][0]["path"] == str(old)
        assert (
            json.loads(studio.runtime_cleanup.settings_path.read_bytes())["previous_runtime_days"]
            == 7
        )
    assert (
        paths.settings_file.read_bytes() if paths.settings_file.exists() else None
    ) == settings_before
