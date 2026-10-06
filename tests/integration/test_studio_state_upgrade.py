"""Preservation, failures, path isolation and recovery of Studio-owned state."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from threading import Event

import psutil
import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio import service as service_module
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import create_app
from evidenceforge.studio.settings import SettingsStore, StudioSettings
from evidenceforge.studio.state_database import Migration, database_digest, migrate_database
from evidenceforge.studio.state_io import StateLock, StudioStateError, atomic_copy, atomic_write
from evidenceforge.studio.state_upgrade import StateCoordinator
from evidenceforge.studio.store import StudioStore
from tests.support.studio_state import inventory, legacy, paths

BOUNDARIES = [
    "backup.before_create",
    "backup.after_create",
    "backup.before_verify",
    "backup.after_verify",
    "backup.before_publish",
    "backup.after_publish",
    "database.before_replace",
    "database.before_checkpoint",
    "database.after_checkpoint",
    "database.before_commit",
    "database.after_commit",
    "database.after_replace",
    "settings.before_replace",
    "settings.after_replace",
    "layout.before_replace",
    "layout.after_replace",
    "journal.before_write",
    "journal.after_write",
    "validation.before",
    "validation.after",
    "completion.before",
    "completion.after",
]


def fail_once(boundary: str) -> Callable[[str], None]:
    fired = False

    def observer(name: str) -> None:
        nonlocal fired
        if name == boundary and not fired:
            fired = True
            raise OSError(f"Injected failure: {boundary}")

    return observer


@pytest.mark.parametrize(
    "shape", ["preview", "imports", "history", "original", "dependency", "current"]
)
def test_historical_upgrade_preserves_independent_inventory(tmp_path: Path, shape: str) -> None:
    selected = legacy(tmp_path, shape)
    before = inventory(selected.database_file)
    engine = {path: path.read_bytes() for path in tmp_path.rglob("*.yaml")}
    old_settings = json.loads(selected.settings_file.read_bytes())
    coordinator = StateCoordinator(selected)
    try:
        assert coordinator.status.state == "pending"
        assert coordinator.status.warning and coordinator.status.incompatible
        assert coordinator.apply(coordinator.status.operation_id).state == "ready"
        assert inventory(selected.database_file) == before
        assert json.loads(selected.settings_file.read_bytes())["settings"] == old_settings
        assert all(path.read_bytes() == content for path, content in engine.items())
        manifest = coordinator.verify_backup()
        assert len(manifest.files) == 3
        assert inventory(coordinator.package / "database.before") == before
        assert coordinator.status.can_restore is False
    finally:
        coordinator.close()
    reopened = StateCoordinator(selected)
    assert reopened.status.state == "ready"
    assert inventory(selected.database_file) == before
    assert len(list((selected.data / "studio-upgrades").glob("*/manifest.json"))) == 1
    reopened.close()


@pytest.mark.parametrize("boundary", BOUNDARIES)
def test_io_failure_has_safe_retry_and_preserves_records(tmp_path: Path, boundary: str) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected, observer=fail_once(boundary))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert inventory(selected.database_file) == before
    coordinator.close()
    recovered = StateCoordinator(selected)
    try:
        assert recovered.status.state != "ready"
        assert recovered.apply(recovered.status.operation_id).state == "ready"
        assert inventory(selected.database_file) == before
    finally:
        recovered.close()


@pytest.mark.parametrize(
    "boundary",
    [
        "database.after_commit",
        "settings.after_replace",
        "layout.after_replace",
        "completion.before",
    ],
)
def test_failed_upgrade_restores_original_contents_and_absence(
    tmp_path: Path, boundary: str
) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    settings = selected.settings_file.read_bytes()
    coordinator = StateCoordinator(selected, observer=fail_once(boundary))
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "restored"
    assert inventory(selected.database_file) == before
    assert selected.settings_file.read_bytes() == settings
    assert not coordinator.layout.exists()
    with closing(sqlite3.connect(selected.database_file)) as database, database:
        assert database.execute("PRAGMA user_version").fetchone() == (0,)
    coordinator.close()
    recovered = StateCoordinator(selected)
    assert recovered.status.state == "restored"
    assert recovered.apply(recovered.status.operation_id).state == "ready"
    recovered.close()


@pytest.mark.parametrize(
    "boundary",
    [
        "database.after_replace",
        "settings.after_replace",
        "layout.after_replace",
        "journal.after_write",
        "completion.before",
    ],
)
def test_restore_can_itself_fail_and_resume(tmp_path: Path, boundary: str) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    coordinator.apply(coordinator.status.operation_id)
    coordinator.observer = fail_once(boundary)
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "failed"
    coordinator.close()
    recovered = StateCoordinator(selected)
    assert recovered.apply(recovered.status.operation_id).state == "restored"
    assert inventory(selected.database_file) == before
    assert not recovered.layout.exists()
    recovered.close()


@pytest.mark.parametrize("key", ["database", "settings", "layout"])
def test_independent_changes_block_restore_without_overwrite(tmp_path: Path, key: str) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected, observer=fail_once("completion.before"))
    coordinator.apply(coordinator.status.operation_id)
    path = coordinator.destinations()[key]
    if key == "database":
        with closing(sqlite3.connect(path)) as database, database:
            database.execute("INSERT INTO removed_job_history VALUES ('independent')")
    else:
        path.write_bytes(b"independent edit")
    before = path.read_bytes()
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "failed"
    assert "changed independently" in coordinator.status.error
    assert path.read_bytes() == before
    coordinator.close()


@pytest.mark.parametrize(
    "defect", ["missing", "truncated", "manifest", "scope", "root", "duplicate"]
)
def test_bad_package_cannot_authorize_restoration(tmp_path: Path, defect: str) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected, observer=fail_once("settings.before_replace"))
    coordinator.apply(coordinator.status.operation_id)
    before = inventory(selected.database_file)
    if defect == "missing":
        (coordinator.package / "database.before").unlink()
    elif defect == "truncated":
        (coordinator.package / "settings.before").write_bytes(b"truncated")
    else:
        path = coordinator.package / "manifest.json"
        if defect == "manifest":
            path.write_bytes(b"{}")
        else:
            manifest = json.loads(path.read_bytes())
            if defect == "scope":
                manifest["scope"] = "workspace"
            if defect == "root":
                manifest["root"] = str(tmp_path / "external")
            if defect == "duplicate":
                manifest["files"].append(manifest["files"][0])
            from evidenceforge.studio.state_upgrade import sha

            path.write_text(json.dumps(manifest))
            coordinator.journal.manifest_sha256 = sha(path.read_bytes())
    coordinator.observer = lambda _name: None
    assert coordinator.apply(coordinator.status.operation_id, restore=True).state == "failed"
    assert inventory(selected.database_file) == before
    coordinator.close()


def test_committed_wal_and_uncommitted_rows_are_handled_by_backup(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    writer = sqlite3.connect(selected.database_file)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO removed_job_history VALUES ('committed-wal')")
    writer.commit()
    reader = sqlite3.connect(selected.database_file)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM items").fetchall()
    coordinator = StateCoordinator(selected)
    coordinator.create_backup()
    with closing(sqlite3.connect(coordinator.package / "database.before")) as backup, backup:
        assert backup.execute(
            "SELECT job_id FROM removed_job_history WHERE job_id='committed-wal'"
        ).fetchone()
    reader.close()
    writer.close()
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()


@pytest.mark.parametrize(
    "defect",
    [
        "db-version",
        "settings-version",
        "settings-bool",
        "settings-json",
        "record-json",
        "identity",
        "unknown-table",
        "damaged-db",
    ],
)
def test_unsupported_or_corrupt_state_is_not_rewritten(tmp_path: Path, defect: str) -> None:
    selected = legacy(tmp_path)
    if defect.startswith("settings"):
        selected.settings_file.write_text(
            {
                "settings-version": '{"schema_version": 9}',
                "settings-bool": '{"schema_version": true}',
                "settings-json": '{"workspace":',
            }[defect]
        )
    elif defect == "damaged-db":
        selected.database_file.write_bytes(b"not sqlite")
    else:
        with closing(sqlite3.connect(selected.database_file)) as connection, connection:
            if defect == "db-version":
                connection.execute("PRAGMA user_version=99")
            if defect == "record-json":
                connection.execute("UPDATE projects SET payload='broken'")
            if defect == "identity":
                connection.execute("UPDATE projects SET payload=json_set(payload, '$.id', 'other')")
            if defect == "unknown-table":
                connection.execute("CREATE TABLE unexpected (value TEXT)")
    before = (selected.database_file.read_bytes(), selected.settings_file.read_bytes())
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    assert (selected.database_file.read_bytes(), selected.settings_file.read_bytes()) == before
    coordinator.close()


def test_stores_refuse_unversioned_state_without_reset(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    with pytest.raises(StudioStateError):
        StudioStore(selected.database_file)
    with pytest.raises(StudioStateError):
        SettingsStore(selected).load()
    with pytest.raises(StudioStateError):
        SettingsStore(selected).save(StudioSettings())


@pytest.mark.parametrize("identity", ["live", "reuse", "unknown", "denied"])
def test_worker_ownership_never_stops_a_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: str
) -> None:
    selected = legacy(tmp_path)
    real = psutil.Process()
    created = real.create_time()
    with closing(sqlite3.connect(selected.database_file)) as database, database:
        raw = json.loads(database.execute("SELECT payload FROM jobs").fetchone()[0])
        raw.update(pid=os.getpid(), process_created_at=created + (20 if identity == "reuse" else 0))
        if identity == "unknown":
            raw["process_created_at"] = 0
        database.execute("UPDATE jobs SET payload=? WHERE id=?", (json.dumps(raw), raw["id"]))
    if identity == "denied":

        def denied(_self: psutil.Process) -> float:
            raise psutil.AccessDenied(os.getpid())

        monkeypatch.setattr(psutil.Process, "create_time", denied)
    coordinator = StateCoordinator(selected)
    result = coordinator.apply(coordinator.status.operation_id)
    assert result.state == ("ready" if identity == "reuse" else "failed")
    assert psutil.pid_exists(os.getpid())
    coordinator.close()


def test_lock_and_obsolete_requests_refuse_conflicting_operations(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    with pytest.raises(StudioStateError):
        coordinator.apply("0" * 32)
    with StateLock(selected.state / "studio-data.lock"):
        assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    with pytest.raises(StudioStateError):
        coordinator.apply(coordinator.status.operation_id, restore=True)
    coordinator.close()


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_aliased_state_is_rejected_without_external_writes(tmp_path: Path, alias: str) -> None:
    selected = legacy(tmp_path)
    external = tmp_path / "external-settings"
    original = selected.settings_file.read_bytes()
    selected.settings_file.rename(external)
    if alias == "symlink":
        try:
            selected.settings_file.symlink_to(external)
        except OSError:
            pytest.skip("Native symlink creation is unavailable")
    else:
        os.link(external, selected.settings_file)
    coordinator = StateCoordinator(selected)
    assert coordinator.status.state == "blocked"
    assert external.read_bytes() == original
    coordinator.close()


def test_atomic_publication_handles_short_writes_and_copy_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio import state_io

    write = os.write
    monkeypatch.setattr(state_io.os, "write", lambda descriptor, data: write(descriptor, data[:7]))
    destination = tmp_path / "file"
    content = b"large verified image" * 100000
    atomic_write(destination, content)
    assert destination.read_bytes() == content
    copied = tmp_path / "copy"
    atomic_copy(copied, destination, 0o640)
    assert copied.read_bytes() == content
    if os.name != "nt":
        assert copied.stat().st_mode & 0o777 == 0o640


def test_consecutive_migrations_and_failure_rollback_are_transactional(tmp_path: Path) -> None:
    path = tmp_path / "database"
    chain = (
        Migration(
            id="one",
            source=0,
            target=1,
            description="first",
            sql="CREATE TABLE test (value TEXT); INSERT INTO test VALUES ('old');",
        ),
        Migration(
            id="two", source=1, target=2, description="second", sql="UPDATE test SET value='new';"
        ),
    )
    from evidenceforge.studio import state_database

    first = chain[0]
    second = chain[1]
    migrate_database(path, "test", migrations=(first, second))
    with closing(sqlite3.connect(path)) as connection, connection:
        assert connection.execute("SELECT value FROM test").fetchone() == ("new",)
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
    before = state_database.database_digest(path)
    third = Migration(
        id="three", source=2, target=3, description="third", sql="UPDATE test SET value='changed';"
    )
    with pytest.raises(OSError):
        migrate_database(path, "test", fail_once("database.before_commit"), (third,))
    assert database_digest(path) == before


def test_api_warns_and_gates_before_upgrade_and_rejects_stale_restore(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    headers = {"X-EForge-Token": "secret"}
    app = create_app(selected, "secret")
    with TestClient(app) as client:
        assert client.get("/v1/state/status").status_code == 401
        status = client.get("/v1/state/status", headers=headers).json()
        assert status["warning"] and status["state"] == "pending"
        assert inventory(selected.database_file) == before
        assert client.get("/v1/bootstrap", headers=headers).status_code == 503
        assert client.get("/v1/health", headers=headers).json()["ready"] == "false"
        assert (
            client.post(
                "/v1/state/upgrade", headers=headers, json={"operation_id": "0" * 32}
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/v1/state/upgrade", headers=headers, json={"operation_id": status["operation_id"]}
            ).status_code
            == 200
        )
        # Lifespan joins the operation task; no timing-dependent polling assertion here.
    reopened = StateCoordinator(selected)
    assert reopened.status.state == "ready"
    reopened.close()


def test_schema_generation_has_no_state_side_effects(tmp_path: Path) -> None:
    selected = paths(tmp_path / "private")
    assert create_app(selected, "schema", schema_only=True).openapi()["paths"]["/v1/state/status"]
    assert not selected.data.exists()


def test_inspection_change_refuses_obsolete_preparation_without_backup(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    coordinator = StateCoordinator(selected)
    settings = json.loads(selected.settings_file.read_bytes())
    settings["checkpoint_hours"] = 9
    content = json.dumps(settings).encode()
    selected.settings_file.write_bytes(content)
    assert coordinator.apply(coordinator.status.operation_id).state == "failed"
    assert "Prepared state changed" in coordinator.status.error
    assert selected.settings_file.read_bytes() == content
    assert not list(coordinator.control_root.glob("*/manifest.json"))
    coordinator.close()


def test_http_preparation_holds_ownership_before_warning_and_backup(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    app = create_app(selected, "secret")
    with TestClient(app) as client:
        status = client.get("/v1/state/status", headers={"X-EForge-Token": "secret"}).json()
        assert status["state"] == "pending" and status["warning"]
        competitor = StateLock(selected.state / "studio-data.lock")
        with pytest.raises(StudioStateError, match="Another Studio process"):
            competitor.acquire()
        assert not list((selected.data / "studio-upgrades").glob("*/manifest.json"))


def test_http_duplicate_restore_observes_existing_operation_and_conflicts_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = legacy(tmp_path)
    entered, released, finished = Event(), Event(), Event()
    failure = fail_once("database.after_replace")
    restoring = False

    def observer(name: str) -> None:
        if restoring and name == "settings.before_replace":
            entered.set()
            assert released.wait(10), "Restore barrier timed out"
        failure(name)

    class ObservedCoordinator(StateCoordinator):
        def __init__(self, paths: StudioPaths, workspace: Path | None = None) -> None:
            super().__init__(paths, workspace, observer=observer)

        def apply(self, identity: str, restore: bool = False) -> service_module.UpgradeStatus:
            result = super().apply(identity, restore)
            finished.set()
            return result

    monkeypatch.setattr(service_module, "StateCoordinator", ObservedCoordinator)
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(selected, "secret")) as client:
        identity = client.get("/v1/state/status", headers=headers).json()["operation_id"]
        body = {"operation_id": identity}
        assert client.post("/v1/state/upgrade", headers=headers, json=body).status_code == 200
        assert finished.wait(10)
        restoring = True
        finished.clear()
        assert client.post("/v1/state/restore", headers=headers, json=body).status_code == 200
        try:
            assert entered.wait(10)
            duplicate = client.post("/v1/state/restore", headers=headers, json=body)
            assert duplicate.status_code == 200 and duplicate.json()["state"] == "running"
            assert client.post("/v1/state/upgrade", headers=headers, json=body).status_code == 409
            assert client.get("/v1/bootstrap", headers=headers).status_code == 503
        finally:
            released.set()
        assert finished.wait(10)
        duplicate = client.post("/v1/state/restore", headers=headers, json=body)
        assert duplicate.status_code == 200 and duplicate.json()["state"] == "restored"
