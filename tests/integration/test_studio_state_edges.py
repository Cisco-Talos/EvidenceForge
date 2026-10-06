"""Storage, concurrency, workspace, compatibility and scale edge cases."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio import state_io
from evidenceforge.studio.service import create_app
from evidenceforge.studio.state_upgrade import LayoutDocument, StateCoordinator
from evidenceforge.studio.store import StudioStore
from tests.integration.test_studio_state_upgrade import fail_once
from tests.support.studio_state import committed_wal, inventory, legacy, paths
from tests.support.studio_state_boundaries import RESTORE_JOURNALS, UPGRADE_JOURNALS


@pytest.mark.parametrize("restore", [False, True])
def test_wal_resident_records_survive_failed_database_publication(
    tmp_path: Path, restore: bool
) -> None:
    selected = legacy(tmp_path)
    committed_wal(selected)
    before = inventory(selected.database_file)

    class FailingPublication(state_io.StateIO):
        def copy(
            self,
            path: Path,
            source: Path,
            mode: int = 0o600,
            *,
            precondition: Callable[[], None] | None = None,
        ) -> None:
            if path == selected.database_file:
                raise OSError("Failed replacement after checkpoint")
            super().copy(path, source, mode, precondition=precondition)

    coordinator = StateCoordinator(selected, io=FailingPublication())
    identity = coordinator.status.operation_id
    assert coordinator.apply(identity).state == "failed"
    assert inventory(selected.database_file) == before
    assert inventory(coordinator.package / "database.before") == before
    coordinator.close()
    resumed = StateCoordinator(selected)
    assert resumed.apply(identity, restore=restore).state == ("restored" if restore else "ready")
    assert inventory(selected.database_file) == before
    resumed.close()


@pytest.mark.parametrize("problem", [errno.ENOSPC, errno.EACCES, errno.EIO])
@pytest.mark.parametrize(
    "boundary",
    [
        "backup.before_create",
        "backup.before_publish",
        "database.before_commit",
        "settings.before_replace",
        "layout.after_replace",
        "completion.before",
    ],
)
def test_storage_errors_never_report_success_or_destroy_recovery(
    tmp_path: Path, problem: int, boundary: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    fired = False

    def observer(name: str) -> None:
        nonlocal fired
        if name == boundary and not fired:
            fired = True
            raise OSError(problem, "Injected native storage error")

    coordinator = StateCoordinator(selected, observer=observer)
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert inventory(selected.database_file) == before
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()


@pytest.mark.parametrize("operation", ["write", "flush", "replace"])
def test_failed_atomic_publication_retains_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    path = tmp_path / "settings.json"
    path.write_bytes(b"original")

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.ENOSPC, "Injected filesystem error")

    if os.name == "nt" and operation != "write":
        from evidenceforge.utils import windows_filesystem

        monkeypatch.setattr(
            windows_filesystem, "flush_file" if operation == "flush" else "replace_child", broken
        )
    else:
        monkeypatch.setattr(
            os, {"write": "write", "flush": "fsync", "replace": "replace"}[operation], broken
        )
    with pytest.raises(OSError):
        state_io.atomic_write(path, b"replacement")
    assert path.read_bytes() == b"original"


def test_duplicate_threads_apply_exactly_one_transition(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    entered, release = Event(), Event()

    def observer(name: str) -> None:
        if name == "database.before_commit":
            entered.set()
            assert release.wait(10)

    coordinator = StateCoordinator(selected, observer=observer)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(coordinator.apply, coordinator.status.operation_id)
        assert entered.wait(10)
        second = executor.submit(coordinator.apply, coordinator.status.operation_id)
        assert coordinator.status.state == "running"
        release.set()
        assert first.result(10).state == second.result(10).state == "ready"
    with closing(sqlite3.connect(selected.database_file)) as database, database:
        assert database.execute("SELECT COUNT(*) FROM studio_migrations").fetchone() == (3,)
    assert len(list((selected.data / "studio-upgrades").glob("*/manifest.json"))) == 1
    coordinator.close()


def test_backup_ignores_uncommitted_writer_then_retry_succeeds(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    writer = sqlite3.connect(selected.database_file)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO removed_job_history VALUES ('not-committed')")
    coordinator = StateCoordinator(selected)
    # Staging the backup does not acquire the writer transaction and cannot include its row.
    coordinator.create_backup()
    with closing(sqlite3.connect(coordinator.package / "database.before")) as backup, backup:
        assert not backup.execute(
            "SELECT 1 FROM removed_job_history WHERE job_id='not-committed'"
        ).fetchone()
    writer.rollback()
    writer.close()
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()


def test_independent_sqlite_writer_blocks_publication_and_allows_retry(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    writer = sqlite3.connect(selected.database_file)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO removed_job_history VALUES ('uncommitted')")
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected)
    try:
        assert coordinator.apply(coordinator.status.operation_id).state == "failed"
        assert "Database is in use" in coordinator.status.error
        assert inventory(selected.database_file) == before
        assert coordinator.verify_backup()
    finally:
        writer.rollback()
        writer.close()
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    assert inventory(selected.database_file) == before
    coordinator.close()


def test_retention_keeps_pending_and_latest_three_completed(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    package = coordinator.control_root
    pending = package / ("b" * 32)
    pending.mkdir()
    (pending / "unfinished").write_bytes(b"retained")
    finished: list[Path] = []
    for index in range(6):
        old = package / f"{index:032x}"
        old.mkdir()
        (old / "completed.json").write_text(
            coordinator.status.model_copy(update={"operation_id": old.name}).model_dump_json()
        )
        os.utime(old / "completed.json", ns=(index + 1, index + 1))
        finished.append(old)
    coordinator.prune()
    assert pending.exists()
    assert sum(path.exists() for path in finished) == 2  # Current package is the third newest.
    assert coordinator.package.exists()
    coordinator.close()


def test_pruning_failure_does_not_make_successful_upgrade_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)

    def failed() -> None:
        raise OSError("Retention directory is unavailable")

    monkeypatch.setattr(coordinator, "prune", failed)
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    assert not coordinator.status.can_restore
    coordinator.close()


@pytest.mark.parametrize("version", [True, 1.0, "1", 2, None])
def test_layout_headers_reject_malformed_or_future_versions(
    tmp_path: Path, version: object
) -> None:
    selected = paths(tmp_path / "private")
    selected.data.mkdir(parents=True)
    document = {
        "manifest_version": 1,
        "layout_version": version,
        "identity": "a" * 32,
        "app_version": "2.1.2",
        "runtime_id": "test",
    }
    (selected.data / "studio-state.json").write_text(json.dumps(document))
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    coordinator.close()


def test_missing_registered_workspace_is_not_recreated_and_another_can_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    coordinator.apply(coordinator.status.operation_id)
    coordinator.close()
    workspace = tmp_path / "workspace"
    unavailable = tmp_path / "unavailable"
    workspace.rename(unavailable)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(selected, "secret")) as client:
        status = client.get("/v1/state/status", headers=headers).json()
        assert status["state"] == "blocked" and status["scope"] == "workspace"
        assert not workspace.exists()
        assert (
            client.post(
                "/v1/workspaces/select", json={"path": str(tmp_path / "other")}, headers=headers
            ).status_code
            == 200
        )
        assert client.get("/v1/state/status", headers=headers).json()["state"] == "ready"
    assert not workspace.exists()


def test_unavailable_other_workspace_does_not_change_saved_selection(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    coordinator.apply(coordinator.status.operation_id)
    coordinator.close()
    saved = selected.settings_file.read_bytes()
    other = tmp_path / "other"
    other.rmdir()
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(selected, "secret")) as client:
        assert (
            client.post(
                "/v1/workspaces/select", json={"path": str(other)}, headers=headers
            ).status_code
            == 409
        )
        assert selected.settings_file.read_bytes() == saved
        assert not other.exists()


def test_workspace_scope_preserves_private_state_and_engine_files(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()
    engine = (tmp_path / "immutable.yaml").read_bytes()
    coordinator = StateCoordinator(selected, tmp_path / "workspace")
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    assert (tmp_path / "immutable.yaml").read_bytes() == engine
    LayoutDocument.model_validate_json(coordinator.layout.read_bytes())
    coordinator.close()


def test_corrupt_derived_records_and_missing_search_are_rebuilt_only(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    coordinator.apply(coordinator.status.operation_id)
    coordinator.close()
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        for table in ("validations", "dependency_health", "resource_predictions"):
            if table == "validations":
                connection.execute(
                    "INSERT OR REPLACE INTO validations VALUES ('scenario-a','source',1,'broken','')"
                )
            else:
                connection.execute(f"INSERT OR REPLACE INTO {table} VALUES ('scenario-a','broken')")
        connection.execute("DROP TABLE items_fts")
    before = inventory(selected.database_file)
    store = StudioStore(selected.database_file)
    store.close()
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        assert connection.execute("SELECT COUNT(*) FROM items_fts").fetchone() == (1,)
        for table in ("validations", "dependency_health", "resource_predictions"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
    after = inventory(selected.database_file)
    for table in before:
        if table not in {"validations", "dependency_health", "resource_predictions"}:
            assert before[table] == after[table]


@pytest.mark.slow
def test_large_history_preservation_and_responsive_progress(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        for index in range(10000):
            payload = {
                "id": f"chat-{index}",
                "workspace": str(tmp_path / "workspace"),
                "thread_id": f"thread-{index}",
                "title": "Recorded conversation",
                "updated_at": index,
            }
            connection.execute(
                "INSERT INTO conversations VALUES (?,?,?,?)",
                (payload["id"], payload["workspace"], None, json.dumps(payload)),
            )
    before = inventory(selected.database_file)
    observed: list[str] = []
    coordinator = StateCoordinator(selected, observer=observed.append)
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    assert inventory(selected.database_file) == before
    assert "backup.after_verify" in observed and "database.after_commit" in observed
    coordinator.close()


def test_losing_launch_cannot_overwrite_owner_journal(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    entered, release = Event(), Event()

    def observer(name: str) -> None:
        if name == "backup.after_publish":
            entered.set()
            assert release.wait(10)

    first = StateCoordinator(selected, observer=observer)
    second = StateCoordinator(selected)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(first.apply, first.status.operation_id)
        try:
            assert entered.wait(10)
            original = first.pointer.read_bytes()
            assert second.apply(second.status.operation_id).state == "failed"
            assert first.pointer.read_bytes() == original
            assert not second.package.exists()
        finally:
            release.set()
        assert pending.result(timeout=10).state == "ready"
    first.close()
    second.close()


def test_swapped_settings_parent_cannot_overwrite_external_file(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    protected = external / selected.settings_file.name
    protected.write_bytes(b"unrelated contents")
    held = tmp_path / "original-config"

    def observer(name: str) -> None:
        if name == "settings.before_replace":
            selected.config.rename(held)
            try:
                selected.config.symlink_to(external, target_is_directory=True)
            except OSError:
                held.rename(selected.config)
                pytest.skip("Native directory links require privileges on this runner")

    coordinator = StateCoordinator(selected, observer=observer)
    try:
        assert coordinator.apply(coordinator.status.operation_id).state == "failed"
        assert protected.read_bytes() == b"unrelated contents"
    finally:
        if selected.config.is_symlink():
            selected.config.unlink()
            held.rename(selected.config)
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()


def test_invalid_saved_values_are_not_copied_into_error_details(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    settings = json.loads(selected.settings_file.read_bytes())
    settings["unrecognized_field"] = "private-user-value"
    selected.settings_file.write_text(json.dumps(settings))
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    assert "private-user-value" not in (coordinator.status.error or "")
    assert "unrecognized_field" in (coordinator.status.error or "")


def test_current_startup_does_not_back_up_or_repeat_adoption_warning(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    assert coordinator.status.warning
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    packages = set(coordinator.control_root.iterdir())
    coordinator.close()
    current = StateCoordinator(selected)
    assert current.status.state == "ready" and current.status.warning is None
    assert current.apply(current.status.operation_id).state == "ready"
    assert set(current.control_root.iterdir()) == packages
    current.close()


def test_fresh_install_initializes_without_backup_or_warning(tmp_path: Path) -> None:
    selected = paths(tmp_path / "private")
    coordinator = StateCoordinator(selected)
    coordinator.initialize_if_fresh()
    assert coordinator.status.state == "ready"
    assert not coordinator.status.warning
    assert not list(coordinator.control_root.glob("*/manifest.json"))
    coordinator.close()


@pytest.mark.parametrize("table", ["jobs", "conversations", "projects", "removed_job_history"])
def test_missing_authoritative_table_is_not_silently_recreated(tmp_path: Path, table: str) -> None:
    selected = legacy(tmp_path)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        connection.execute(f'DROP TABLE "{table}"')
    original = selected.database_file.read_bytes()
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    assert selected.database_file.read_bytes() == original


def test_missing_derived_tables_are_rebuilt_without_changing_user_metadata(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()
    before = inventory(selected.database_file)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        connection.execute("DROP TABLE resource_predictions")
        connection.execute("DROP TABLE validations")
    store = StudioStore(selected.database_file)
    store.close()
    after = inventory(selected.database_file)
    for table in before.keys() - {"validations", "dependency_health", "resource_predictions"}:
        assert after[table] == before[table]


def test_retained_authoring_blocks_upgrade_without_clearing_associations(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        raw = connection.execute("SELECT payload FROM conversations LIMIT 1").fetchone()[0]
        payload = json.loads(raw)
        payload["active"] = True
        connection.execute(
            "UPDATE conversations SET payload=? WHERE id=?", (json.dumps(payload), payload["id"])
        )
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected)
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert "authoring ownership" in (coordinator.status.error or "")
    assert inventory(selected.database_file) == before
    assert not coordinator.package.exists()
    coordinator.close()


def test_running_job_without_worker_identity_blocks_preparation(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        raw = json.loads(connection.execute("SELECT payload FROM jobs").fetchone()[0])
        raw.update(status="running", pid=0)
        connection.execute("UPDATE jobs SET payload=? WHERE id=?", (json.dumps(raw), raw["id"]))
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected)
    coordinator.prepare()
    assert coordinator.status.state == "failed"
    assert "no verifiable worker identity" in coordinator.status.error
    assert coordinator.status.can_retry
    assert inventory(selected.database_file) == before
    assert not list(coordinator.control_root.glob("*/manifest.json"))
    coordinator.close()


@pytest.mark.slow
@pytest.mark.parametrize("boundary", UPGRADE_JOURNALS)
def test_each_upgrade_journal_io_error_preserves_recovery(tmp_path: Path, boundary: str) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected, observer=fail_once(boundary))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    if coordinator.status.can_restore:
        coordinator.verify_backup()
    coordinator.close()
    resumed = StateCoordinator(selected)
    assert resumed.apply(resumed.status.operation_id).state == "ready"
    assert inventory(selected.database_file) == before
    resumed.close()


@pytest.mark.slow
@pytest.mark.parametrize("boundary", RESTORE_JOURNALS)
def test_each_restore_journal_io_error_preserves_recovery(tmp_path: Path, boundary: str) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    coordinator.observer = fail_once(boundary)
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "failed"
    coordinator.verify_backup()
    coordinator.close()
    resumed = StateCoordinator(selected)
    assert resumed.apply(resumed.status.operation_id, restore=True).state == "restored"
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    resumed.close()


@pytest.mark.parametrize("fault", ["backup", "document"])
def test_injected_partial_io_never_accepts_an_incomplete_package(
    tmp_path: Path, fault: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()

    class PartialIO(state_io.StateIO):
        def write(self, path: Path, content: bytes, mode: int = 0o600) -> None:
            if fault == "document" and path.name == "settings.after":
                super().write(path, content[: len(content) // 2], mode)
                raise InterruptedError("Interrupted staged document write")
            super().write(path, content, mode)

        def backup(self, source: sqlite3.Connection, target: sqlite3.Connection) -> None:
            super().backup(source, target)
            if fault == "backup":
                path = Path(target.execute("PRAGMA database_list").fetchone()[2])
                target.close()
                path.write_bytes(b"incomplete database image")
                raise InterruptedError("Interrupted SQLite backup")

    coordinator = StateCoordinator(selected, io=PartialIO())
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert not coordinator.status.can_restore
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    package = coordinator.package
    coordinator.close()
    resumed = StateCoordinator(selected)
    assert package.exists()
    assert resumed.apply(resumed.status.operation_id).state == "ready"
    resumed.verify_backup()
    assert inventory(selected.database_file) == before
    resumed.close()


@pytest.mark.parametrize("absent", ["database", "settings"])
def test_restore_recovers_original_absence_of_each_private_file(
    tmp_path: Path, absent: str
) -> None:
    selected = legacy(tmp_path)
    missing = selected.database_file if absent == "database" else selected.settings_file
    missing.unlink()
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert missing.exists()
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "restored"
    assert not missing.exists()
    coordinator.close()


def test_private_permissions_survive_upgrade_and_restoration(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows ownership uses native ACLs rather than POSIX mode bits")
    selected = legacy(tmp_path)
    for path in (selected.settings_file, selected.database_file):
        path.chmod(0o600)
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    for path in coordinator.package.iterdir():
        if path.is_file():
            assert path.stat().st_mode & 0o077 == 0
    assert coordinator.package.stat().st_mode & 0o077 == 0
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "restored"
    assert all(
        path.stat().st_mode & 0o777 == 0o600
        for path in (selected.settings_file, selected.database_file)
    )
    coordinator.close()


def test_initialization_refuses_independently_populated_database(tmp_path: Path) -> None:
    selected = paths(tmp_path / "private")
    coordinator = StateCoordinator(selected, observer=fail_once("settings.before_replace"))
    coordinator.initialize_if_fresh()
    assert coordinator.status.state == "failed"
    coordinator.close()
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        connection.execute("INSERT INTO removed_job_history VALUES ('independently-added')")
    before = inventory(selected.database_file)
    resumed = StateCoordinator(selected)
    assert resumed.apply(resumed.status.operation_id).state == "failed"
    assert inventory(selected.database_file) == before
    resumed.close()


def test_missing_workspace_outside_recents_is_still_registered(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()
    settings = json.loads(selected.settings_file.read_bytes())
    settings["settings"]["recent_workspaces"] = []
    selected.settings_file.write_text(json.dumps(settings))
    other = tmp_path / "other"
    other.rmdir()
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(selected, "secret")) as client:
        response = client.post("/v1/workspaces/select", headers=headers, json={"path": str(other)})
        assert response.status_code == 409
        assert client.get("/v1/state/status", headers=headers).json()["scope"] == "workspace"
    assert not other.exists()


@pytest.mark.parametrize("table", ["items", "conversations", "jobs", "events"])
@pytest.mark.parametrize("payload", ["null", "[]", "123", '"text"'])
def test_non_object_authoritative_json_is_refused_before_writes(
    tmp_path: Path, table: str, payload: str
) -> None:
    selected = legacy(tmp_path)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        if table == "events":
            connection.execute(
                "INSERT INTO events(entity_id,kind,payload) VALUES ('entity','saved.event',?)",
                (payload,),
            )
        else:
            connection.execute(f'UPDATE "{table}" SET payload=?', (payload,))
    before = selected.database_file.read_bytes()
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    assert selected.database_file.read_bytes() == before


def test_regular_parent_substitution_is_refused_before_external_overwrite(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    external = tmp_path / "substituted"
    external.mkdir()
    (external / selected.settings_file.name).write_bytes(b"independent settings")
    held = tmp_path / "held-original"

    def observer(name: str) -> None:
        if name == "settings.before_replace":
            selected.config.rename(held)
            external.rename(selected.config)

    coordinator = StateCoordinator(selected, observer=observer)
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert (selected.config / selected.settings_file.name).read_bytes() == b"independent settings"
    selected.config.rename(external)
    held.rename(selected.config)
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()


def test_independent_leaf_edit_at_publication_is_not_overwritten(tmp_path: Path) -> None:
    selected = legacy(tmp_path)

    def observer(name: str) -> None:
        if name == "settings.before_replace":
            selected.settings_file.write_bytes(b"independent leaf edit")

    coordinator = StateCoordinator(selected, observer=observer)
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert selected.settings_file.read_bytes() == b"independent leaf edit"
    coordinator.close()


def test_upgrade_preserves_engine_qt_and_codex_history_bytes(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    sentinels = [
        tmp_path / "workspace/checkpoints/engine.bin",
        tmp_path / "workspace/runs/sample/GENERATED.log",
        tmp_path / "workspace/packs/sample/pack.yaml",
        selected.config / "retired-qt-state.json",
        tmp_path / "codex-owned/history.jsonl",
        tmp_path / "workspace/ENVIRONMENT.md",
    ]
    for path in sentinels:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original independent artifact\x00\xff\n")
    original = {path: path.read_bytes() for path in sentinels}
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "restored"
    assert all(path.read_bytes() == content for path, content in original.items())
    assert not any(
        path.name in {entry.name for entry in coordinator.package.iterdir()} for path in sentinels
    )
    coordinator.close()


def test_windows_backup_and_restoration_keep_owner_only_acls(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Native Windows ACL contract")
    from evidenceforge.utils import windows_filesystem as filesystem

    selected = legacy(tmp_path)
    for path in (selected.settings_file, selected.database_file):
        state_io.atomic_write(path, path.read_bytes())
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    directory = filesystem.open_directory(coordinator.package)
    try:
        filesystem.require_private(directory)
    finally:
        os.close(directory)
    for path in coordinator.package.iterdir():
        if path.is_file():
            descriptor = filesystem.open_file(path, os.O_RDONLY)
            try:
                filesystem.require_private(descriptor)
            finally:
                os.close(descriptor)
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "restored"
    for path in (selected.settings_file, selected.database_file):
        descriptor = filesystem.open_file(path, os.O_RDONLY)
        try:
            filesystem.require_private(descriptor)
        finally:
            os.close(descriptor)
    coordinator.close()
