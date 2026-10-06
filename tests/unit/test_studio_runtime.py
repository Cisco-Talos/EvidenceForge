"""Standalone interpreter, CLI discovery, and safe helper handoff contracts."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from evidenceforge.desktop.jobs import _eforge_command
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio import bootstrap, runtime
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.store import Conversation


def _paths(root: Path) -> StudioPaths:
    return StudioPaths(
        config=root / "config",
        data=root / "data",
        state=root / "state",
        cache=root / "cache",
        logs=root / "logs",
    )


def test_private_runtime_is_relocation_safe_and_isolates_python_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Retained runtime ü"
    executable = root / "bin/python3.12"
    executable.parent.mkdir(parents=True)
    executable.touch()
    (root / "release.json").write_text(
        runtime.RuntimeRelease(
            runtime_id="a" * 64,
            evidenceforge_version="2.1.2",
            python_version="3.12.12",
            architecture="aarch64",
        ).model_dump_json()
    )
    monkeypatch.setenv("EFORGE_STUDIO_RUNTIME_ROOT", str(root))
    monkeypatch.setenv("PYTHONHOME", "/unrelated/python")
    monkeypatch.setenv("PYTHONPATH", "/unrelated/packages")
    monkeypatch.delenv("EFORGE_DESKTOP_EFORGE_BIN", raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    assert runtime.runtime_id() == "a" * 64
    environment = runtime.command_environment()
    assert environment["PATH"].split(":")[0] == str(root / "bin")
    assert "PYTHONHOME" not in environment and "PYTHONPATH" not in environment
    assert _eforge_command() == [str(executable), "-I", "-B", "-m", "evidenceforge"]
    monkeypatch.setattr(sys, "executable", "/unrelated/python")
    with pytest.raises(RuntimeError, match="outside its selected private runtime"):
        runtime.runtime_id()


def test_finder_codex_discovery_and_explicit_setting_precedence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: None)
    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.delenv("EFORGE_DESKTOP_CODEX_BIN", raising=False)
    candidate = Path("/Applications/Codex.app/Contents/Resources/codex")
    monkeypatch.setattr(Path, "is_file", lambda path: path == candidate)
    monkeypatch.setattr(runtime.os, "access", lambda path, mode: path == candidate)
    assert runtime.discover_codex() == str(candidate)
    explicit = tmp_path / "codex"
    assert runtime.discover_codex(explicit) == str(explicit)
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", "/chosen/codex")
    assert runtime.discover_codex(explicit) == "/chosen/codex"


def test_source_identity_changes_between_launches_but_running_helper_keeps_its_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "src/evidenceforge"
    service = package / "studio/service.py"
    service.parent.mkdir(parents=True)
    service.write_text("asset_routes = False\n")
    monkeypatch.delenv("EFORGE_STUDIO_RUNTIME_ROOT", raising=False)
    monkeypatch.setattr(runtime, "_source_identity", None)
    monkeypatch.setattr(runtime, "__file__", str(package / "studio/runtime.py"))
    first = runtime._source_runtime_id(package)
    assert runtime.runtime_id() == first
    service.write_text("asset_routes = True\n")
    assert runtime.runtime_id() == first
    updated = runtime._source_runtime_id(package)
    assert updated.startswith("source-") and updated != first
    (tmp_path / "uv.lock").write_text("version = 1\n")
    assert runtime._source_runtime_id(package) != updated


@pytest.mark.parametrize("old_identity", ["source", "source-previous", "source-current"])
def test_source_launch_replaces_changed_helpers_and_only_accepts_selected_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old_identity: str
) -> None:
    paths = _paths(tmp_path)
    old = bootstrap.ServiceDescriptor(
        pid=42, created_at=100, port=1234, token="secret", runtime_id=old_identity
    )
    current = old.model_copy(update={"pid": 43, "runtime_id": "source-current"})
    # An old descriptor briefly remaining after startup must never be returned.
    read = Mock(side_effect=[old, old, current])
    replace = Mock()
    start = Mock()
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "source-current")
    monkeypatch.setattr(bootstrap, "_read_descriptor", read)
    monkeypatch.setattr(bootstrap, "_is_live", lambda descriptor: True)
    monkeypatch.setattr(bootstrap, "_replace_idle", replace)
    monkeypatch.setattr(bootstrap, "start_background_service", start)
    monkeypatch.setattr(bootstrap.time, "sleep", lambda seconds: None)
    result = bootstrap.connect_or_start(paths)
    if old_identity == "source-current":
        assert result is old
        replace.assert_not_called()
        start.assert_not_called()
    else:
        assert result is current
        replace.assert_called_once_with(old)
        start.assert_called_once_with(paths)
        assert read.call_count == 3


def test_handoff_requires_auth_and_idle_work_across_all_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StudioService, "start", quiet_start)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.delenv("EFORGE_STUDIO_RUNTIME_ROOT", raising=False)
    app = create_app(_paths(tmp_path / "state"), "secret")
    headers = {"X-EForge-Token": "secret"}
    service = app.state.studio
    job = GenerationJob(
        id="other-workspace-job",
        scenario=tmp_path / "other/scenario.yaml",
        workspace=tmp_path / "other",
        output_root=tmp_path / "other/run",
        progress_file=tmp_path / "other/progress.jsonl",
        log_file=tmp_path / "other/job.log",
        started_at=1,
        status="queued",
    )
    service.jobs.save_generation(job)
    with TestClient(app) as client:
        endpoint = "/v1/runtime/prepare-replacement"
        assert client.post(endpoint).status_code == 401
        assert client.post(endpoint, headers=headers).status_code == 409
        assert not service.replacement_ready
        job.status = "paused"
        service.jobs.save_generation(job)
        chat = Conversation(id="active-chat", workspace=tmp_path / "other", active=True)
        service.store.save_conversation(chat)
        assert client.post(endpoint, headers=headers).status_code == 409
        chat.active = False
        service.store.save_conversation(chat)
        assert client.post(endpoint, headers=headers).json() == {
            "ready": True,
            "runtime_id": runtime.runtime_id(),
        }
        assert client.get("/v1/bootstrap", headers=headers).status_code == 409
        assert client.get("/v1/health", headers=headers).status_code == 200


def test_replacement_never_terminates_a_reused_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    descriptor = bootstrap.ServiceDescriptor(
        pid=42,
        created_at=100,
        port=1234,
        token="secret",
        runtime_id="old",
        executable="/private/runtime/bin/python3.12",
    )
    result = io.BytesIO(json.dumps({"ready": True, "runtime_id": "old"}).encode())
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", lambda *args, **kwargs: result)
    process = Mock()
    process.create_time.return_value = 200
    process.cmdline.return_value = ["python", "-m", "evidenceforge.studio.bootstrap", "--serve"]
    monkeypatch.setattr(bootstrap.psutil, "Process", lambda pid: process)
    with pytest.raises(RuntimeError, match="identity changed"):
        bootstrap._replace_idle(descriptor)
    process.terminate.assert_not_called()
