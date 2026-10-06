"""Simulated OS identities test refusal without needing additional system accounts."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import psutil
import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio import bootstrap, ownership, state_io
from evidenceforge.studio.paths import studio_paths
from evidenceforge.studio.service import create_app
from evidenceforge.studio.settings import SettingsStore, StudioSettings
from evidenceforge.studio.state_io import StateLock, StudioStateError, atomic_write
from evidenceforge.studio.state_upgrade import StateCoordinator
from evidenceforge.studio.store import StudioStore
from tests.support.studio_state import paths


def descriptor(**values: object) -> bootstrap.ServiceDescriptor:
    return bootstrap.ServiceDescriptor.model_validate(
        {
            "schema_version": 1,
            "owner": ownership.current_account(),
            "pid": 42,
            "created_at": 100,
            "port": 1234,
            "token": "do-not-disclose-this-secret",
            "executable": sys.executable,
            "runtime_id": "selected",
            **values,
        }
    )


def process(monkeypatch: pytest.MonkeyPatch) -> Mock:
    selected = Mock(spec=psutil.Process)
    selected.pid = 42
    selected.create_time.return_value = 100
    selected.exe.return_value = sys.executable
    selected.cmdline.return_value = [
        sys.executable,
        "-m",
        "evidenceforge.studio.bootstrap",
        "--serve",
    ]
    selected.is_running.return_value = True
    monkeypatch.setattr(bootstrap.psutil, "Process", lambda pid: selected)
    monkeypatch.setattr(bootstrap, "process_account", lambda proc: ownership.current_account())
    return selected


@pytest.mark.parametrize("kind,value", [("uid", "9999997"), ("sid", "S-1-5-21-9999997")])
def test_foreign_claimed_owner_never_sends_token_or_starts_or_signals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, value: str
) -> None:
    selected = process(monkeypatch)
    foreign = descriptor(owner={"kind": kind, "value": value})
    request = Mock()
    start = Mock()
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", request)
    monkeypatch.setattr(bootstrap, "start_background_service", start)
    monkeypatch.setattr(bootstrap, "_read_descriptor", lambda path: foreign)
    with pytest.raises(StudioStateError, match="another OS account"):
        bootstrap.connect_or_start(paths(tmp_path))
    with pytest.raises(StudioStateError, match="another OS account"):
        bootstrap._replace_idle(foreign)
    request.assert_not_called()
    start.assert_not_called()
    selected.terminate.assert_not_called()


@pytest.mark.parametrize("failure", ["foreign", "denied", "executable", "command"])
def test_actual_process_checked_before_any_authenticated_request(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    selected = process(monkeypatch)
    if failure == "foreign":
        monkeypatch.setattr(
            bootstrap,
            "process_account",
            lambda proc: ownership.AccountIdentity(kind="uid", value="999999"),
        )
    elif failure == "denied":
        selected.create_time.side_effect = psutil.AccessDenied(42)
    elif failure == "executable":
        selected.exe.return_value = "/unrelated/executable"
    else:
        selected.cmdline.return_value = [sys.executable, "-m", "unrelated", "--serve"]
    request = Mock()
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", request)
    with pytest.raises(StudioStateError):
        bootstrap._is_live(descriptor())
    with pytest.raises(StudioStateError):
        bootstrap._replace_idle(descriptor())
    request.assert_not_called()
    selected.terminate.assert_not_called()


@pytest.mark.parametrize("change", ["owner", "pid", "command"])
def test_replacement_rechecks_identity_after_authenticated_handoff(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    selected = process(monkeypatch)

    def reply(*args: object, **kwargs: object) -> io.BytesIO:
        if change == "owner":
            monkeypatch.setattr(
                bootstrap,
                "process_account",
                lambda proc: ownership.AccountIdentity(kind="uid", value="999999"),
            )
        elif change == "pid":
            selected.create_time.return_value = 200
        else:
            selected.cmdline.return_value = ["unrelated"]
        return io.BytesIO(b'{"ready":true,"runtime_id":"selected"}')

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", reply)
    with pytest.raises((StudioStateError, RuntimeError)):
        bootstrap._replace_idle(descriptor())
    selected.terminate.assert_not_called()


def test_verified_idle_helper_is_replaced_without_force_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = process(monkeypatch)
    monkeypatch.setattr(
        bootstrap.urllib.request,
        "urlopen",
        lambda *args, **kwargs: io.BytesIO(b'{"ready":true,"runtime_id":"selected"}'),
    )
    bootstrap._replace_idle(descriptor())
    selected.terminate.assert_called_once()
    selected.wait.assert_called_once_with(timeout=8)
    selected.kill.assert_not_called()


def test_verified_starting_helper_never_starts_second_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process(monkeypatch)
    selected = descriptor()
    monkeypatch.setattr(bootstrap, "_read_descriptor", lambda path: selected)
    healthy = Mock(side_effect=[False, True])
    monkeypatch.setattr(bootstrap, "_is_live", healthy)
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "selected")
    start = Mock()
    monkeypatch.setattr(bootstrap, "start_background_service", start)
    assert bootstrap.connect_or_start(paths(tmp_path)) == selected
    start.assert_not_called()


@pytest.mark.parametrize("failure", ["future", "malformed", "missing-owner", "oversize"])
def test_discovery_refusals_do_not_disclose_credentials(tmp_path: Path, failure: str) -> None:
    selected = descriptor().model_dump(mode="json")
    if failure == "future":
        selected["schema_version"] = 2
    elif failure == "missing-owner":
        selected["owner"] = None
    elif failure == "malformed":
        selected["port"] = "invalid"
    else:
        selected["token"] = "x" * 17000
    path = tmp_path / "state/service.json"
    atomic_write(path, json.dumps(selected).encode())
    before = path.read_bytes()
    with pytest.raises(StudioStateError) as error:
        bootstrap._read_descriptor(path)
    assert "do-not-disclose" not in str(error.value)
    assert path.read_bytes() == before


def test_legacy_discovery_is_accepted_only_after_live_process_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = process(monkeypatch)
    path = tmp_path / "state/service.json"
    legacy = descriptor().model_dump(mode="json", exclude={"owner", "schema_version", "executable"})
    atomic_write(path, json.dumps(legacy).encode())
    old = bootstrap._read_descriptor(path)
    assert old is not None and old.schema_version == 0
    assert bootstrap._verified_process(old) is selected
    selected.cmdline.return_value = ["unrelated"]
    with pytest.raises(StudioStateError):
        bootstrap._verified_process(old)


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX UID and mode contracts; Windows uses native ACL tests"
)
@pytest.mark.parametrize("entry", ["broad-credentials", "symlink", "hardlink", "directory", "fifo"])
def test_unsafe_discovery_entry_cannot_be_read(tmp_path: Path, entry: str) -> None:
    path = tmp_path / "state/service.json"
    atomic_write(path, descriptor().model_dump_json().encode())
    original = path.read_bytes()
    external = tmp_path / "external"
    external.write_bytes(original)
    if entry == "broad-credentials":
        path.chmod(0o644)
    else:
        path.unlink()
        if entry == "symlink":
            path.symlink_to(external)
        elif entry == "hardlink":
            os.link(external, path)
        elif entry == "fifo":
            os.mkfifo(path)
        else:
            path.mkdir()
    with pytest.raises((StudioStateError, OSError)):
        bootstrap._read_descriptor(path)
    assert external.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership simulation")
def test_foreign_root_refuses_before_other_roots_are_modified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = paths(tmp_path / "private")
    selected.config.mkdir(parents=True)
    selected.data.mkdir()
    before = selected.config.stat().st_mode
    original = Path.lstat

    def metadata(path: Path) -> os.stat_result:
        result = original(path)
        if path == selected.data:
            values = list(result)
            values[4] = 999999
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(StudioStateError, match="another OS account"):
        ownership.validate_private_paths(selected)
    assert selected.config.stat().st_mode == before
    assert not selected.state.exists()
    with closing(StateCoordinator(selected)) as coordinator:
        assert coordinator.status.state == "blocked"
        assert not coordinator.paths.database_file.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contracts")
def test_owned_default_roots_are_tightened_without_modifying_contents(tmp_path: Path) -> None:
    selected = paths(tmp_path)
    selected.data.mkdir(mode=0o755)
    reference = selected.data / "reference"
    reference.write_bytes(b"preserve exactly")
    ownership.validate_private_paths(selected)
    assert reference.read_bytes() == b"preserve exactly"
    assert stat.S_IMODE(selected.data.stat().st_mode) == 0o700
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contracts")
def test_custom_insecure_root_is_refused_without_repair_or_store_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "custom"
    root.mkdir(mode=0o755)
    marker = root / "existing"
    marker.write_bytes(b"unchanged")
    monkeypatch.setenv("EFORGE_STUDIO_HOME", str(root))
    selected = studio_paths()
    with pytest.raises(StudioStateError, match="mode 700"):
        bootstrap.connect_or_start(selected)
    with pytest.raises(StudioStateError, match="mode 700"):
        SettingsStore(selected)
    assert stat.S_IMODE(root.stat().st_mode) == 0o755
    assert list(root.iterdir()) == [marker]
    assert marker.read_bytes() == b"unchanged"


def test_custom_link_is_not_resolved_away(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    external = tmp_path / "external"
    external.mkdir()
    link = tmp_path / "custom"
    try:
        link.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("Native symbolic links unavailable")
    monkeypatch.setenv("EFORGE_STUDIO_HOME", str(link))
    selected = studio_paths()
    assert selected.data.parent == link
    with pytest.raises(StudioStateError, match="link or reparse"):
        bootstrap.connect_or_start(selected)
    assert list(external.iterdir()) == []


def test_current_and_process_identity_use_os_values_not_usernames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ownership.os, "name", "posix")
    monkeypatch.setattr(ownership.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(ownership.os, "geteuid", lambda: 1001, raising=False)
    assert ownership.current_account() == ownership.AccountIdentity(kind="uid", value="1001")
    selected = Mock(spec=psutil.Process)
    from collections import namedtuple

    ids = namedtuple("Ids", "real effective saved")
    selected.uids = Mock(return_value=ids(1002, 1002, 1002))
    assert ownership.process_account(selected).value == "1002"
    selected.uids.return_value = ids(1002, 1001, 1002)
    with pytest.raises(StudioStateError, match="mixed"):
        ownership.process_account(selected)
    monkeypatch.setattr(ownership.os, "geteuid", lambda: 0)
    with pytest.raises(StudioStateError, match="normal account"):
        ownership.current_account()


def test_windows_account_adapter_uses_token_sid_on_every_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = SimpleNamespace(
        current_user_sid=lambda: "S-1-5-21-1001", process_user_sid=lambda pid: "S-1-5-21-1002"
    )
    monkeypatch.setitem(sys.modules, "evidenceforge.utils.windows_filesystem", adapter)
    monkeypatch.setattr(ownership.os, "name", "nt")
    assert ownership.current_account().value == "S-1-5-21-1001"
    assert ownership.process_account(SimpleNamespace(pid=42)).value == "S-1-5-21-1002"


def test_separate_account_roots_preserve_independent_settings_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulated identities do not claim to reproduce kernel access controls.
    roots = [paths(tmp_path / name) for name in ("account-one", "account-two")]
    for selected, cap, name in zip(roots, (1, 3), ("one", "two"), strict=True):
        monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / name))
        with closing(StateCoordinator(selected)) as coordinator:
            coordinator.initialize_if_fresh()
        settings = StudioSettings()
        settings.max_concurrent_generations = cap
        SettingsStore(selected).save(settings)
        with closing(StudioStore(selected.database_file)) as store:
            store._db.execute("INSERT INTO removed_job_history VALUES (?)", (name,))
            store._db.commit()
    assert [SettingsStore(selected).load().max_concurrent_generations for selected in roots] == [
        1,
        3,
    ]
    for selected, name in zip(roots, ("one", "two"), strict=True):
        with closing(StudioStore(selected.database_file)) as store:
            assert (
                store._db.execute("SELECT job_id FROM removed_job_history").fetchall()[0][0] == name
            )


def test_spoofed_account_and_session_headers_do_not_authorize_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(paths(tmp_path), "secret")
    with TestClient(app) as client:
        headers = {"X-EForge-Session": "known-window", "X-EForge-User": "same-account"}
        assert client.get("/v1/health", headers=headers).status_code == 401
        headers["X-EForge-Token"] = "wrong"
        assert client.post("/v1/session/open", headers=headers).status_code == 401


def test_schema_generation_does_not_prepare_or_repair_private_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = paths(tmp_path / "untouched")
    prepare = Mock(side_effect=AssertionError("schema generation accessed private state"))
    monkeypatch.setattr(ownership, "validate_private_paths", prepare)
    assert create_app(selected, "schema-only", schema_only=True).openapi()["paths"]
    assert not selected.data.parent.exists()
    prepare.assert_not_called()


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership simulation")
@pytest.mark.parametrize("entry", ["settings_file", "database_file"])
def test_foreign_authoritative_file_is_not_adopted_or_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    selected = paths(tmp_path)
    protected = getattr(selected, entry)
    protected.parent.mkdir()
    protected.write_bytes(b"foreign authoritative bytes")
    original = Path.lstat

    def metadata(path: Path) -> os.stat_result:
        result = original(path)
        if path == protected:
            values = list(result)
            values[4] = 999999
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "lstat", metadata)
    with closing(StateCoordinator(selected)) as coordinator:
        assert coordinator.status.state == "blocked"
        assert "another OS account" in coordinator.status.error
        assert protected.read_bytes() == b"foreign authoritative bytes"
        assert not (selected.data / "studio-upgrades").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow directory handles")
def test_directory_substitution_after_open_never_changes_external_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "guarded-studio-root"
    root.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o755)
    original_mode = external.stat().st_mode
    original = ownership.os.open

    def opened(path: object, flags: int, *args: object, **kwargs: object) -> int:
        result = original(path, flags, *args, **kwargs)
        if path == root.name and flags & os.O_DIRECTORY:
            root.rename(tmp_path / "retained")
            root.symlink_to(external, target_is_directory=True)
        return result

    monkeypatch.setattr(ownership.os, "open", opened)
    with pytest.raises(StudioStateError, match="changed|link or reparse"):
        ownership.secure_directory(root)
    assert external.stat().st_mode == original_mode
    assert list(external.iterdir()) == []


def test_standard_xdg_paths_retain_default_permission_repair_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EFORGE_STUDIO_HOME", raising=False)
    monkeypatch.setattr("evidenceforge.studio.paths.sys.platform", "linux")
    for variable, suffix in (
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_STATE_HOME", ".local/state"),
        ("XDG_CACHE_HOME", ".cache"),
    ):
        monkeypatch.setenv(variable, str(Path.home() / suffix))
    assert studio_paths().custom_roots == ()


def test_concurrent_creation_and_ownership_of_launch_lock(tmp_path: Path) -> None:
    for number in range(20):
        root = tmp_path / f"round-{number}"
        root.mkdir(mode=0o700)
        start = Barrier(4, timeout=8)
        finished = Barrier(4, timeout=8)

        def attempt(
            root: Path = root, start: Barrier = start, finished: Barrier = finished
        ) -> bool:
            lock = StateLock(root / "service-start.lock")
            owned = False
            try:
                start.wait()
                try:
                    lock.acquire()
                    owned = True
                except StudioStateError as error:
                    assert "Another Studio process" in str(error)
                finally:
                    finished.wait()
                return owned
            finally:
                lock.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert sum(pool.map(lambda _: attempt(), range(4))) == 1


def test_failed_discovery_publication_releases_listener_and_instance_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = paths(tmp_path)
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ("127.0.0.1", 1234)
    monkeypatch.setattr(bootstrap.socket, "socket", lambda *args: listener)
    publication = Mock(side_effect=OSError("injected publication failure"))
    monkeypatch.setattr(bootstrap, "atomic_write", publication)
    actual = Mock()
    actual.create_time.return_value = 100
    actual.exe.return_value = "/actual/interpreter"
    monkeypatch.setattr(bootstrap.psutil, "Process", lambda: actual)
    with pytest.raises(OSError, match="injected"):
        bootstrap.serve(selected)
    listener.__exit__.assert_called_once()
    with StateLock(selected.state / "service-instance.lock"):
        pass
    published = bootstrap.ServiceDescriptor.model_validate_json(publication.call_args.args[1])
    assert published.executable == str(Path("/actual/interpreter").resolve())
    assert not selected.database_file.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative substitution adapter")
def test_file_substitution_between_inspection_and_open_refuses_changed_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = tmp_path / "protected-record"
    replacement = tmp_path / "independent-edit"
    atomic_write(protected, b"original")
    atomic_write(replacement, b"independently changed")
    original = os.open

    def opened(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == protected.name:
            os.replace(replacement, protected)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(state_io.os, "open", opened)
    with pytest.raises(StudioStateError, match="changed while opening"):
        state_io.read_bytes(protected)
    assert protected.read_bytes() == b"independently changed"
