"""Background helper launch contracts without registering real system services."""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.studio import background
from evidenceforge.studio.paths import StudioPaths


def _paths(root: Path) -> StudioPaths:
    paths = StudioPaths(
        config=root / "config",
        data=root / "data",
        state=root / "state",
        cache=root / "cache",
        logs=root / "logs",
    )
    paths.state.mkdir(parents=True)
    paths.logs.mkdir()
    return paths


@pytest.mark.parametrize("registered", [False, True])
def test_macos_helper_launch_is_independent_and_scoped_to_data_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registered: bool
) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        background.os,
        "getuid",
        lambda: os.geteuid() if hasattr(os, "geteuid") else 1000,
        raising=False,
    )
    monkeypatch.setenv("EFORGE_STUDIO_HOME", str(tmp_path))
    monkeypatch.setenv("UNRELATED_API_SECRET", "must-not-be-persisted")
    run = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 0 if registered else 1, stdout="state = exited\n"),
            subprocess.CompletedProcess([], 0),
            *([subprocess.CompletedProcess([], 0)] if registered else []),
        ]
    )
    monkeypatch.setattr(background.subprocess, "run", run)
    popen = Mock()
    monkeypatch.setattr(background.subprocess, "Popen", popen)

    background.start_background_service(paths)

    label = background.macos_service_label(paths)
    other_paths = paths.model_copy(update={"state": tmp_path / "other-state"})
    assert background.macos_service_label(other_paths) != label
    agent = paths.state / "service-agent.plist"
    config = plistlib.loads(agent.read_bytes())
    assert config["Label"] == label
    assert config["ProgramArguments"] == [
        sys.executable,
        "-m",
        "evidenceforge.studio.bootstrap",
        "--serve",
    ]
    assert config["EnvironmentVariables"]["EFORGE_STUDIO_HOME"] == str(tmp_path)
    assert config["EnvironmentVariables"]["EFORGE_STUDIO_DAEMON"] == "1"
    assert "UNRELATED_API_SECRET" not in config["EnvironmentVariables"]
    assert config["StandardOutPath"] == str(paths.logs / "service.log")
    assert config["RunAtLoad"] is True
    assert "KeepAlive" not in config
    if os.name == "posix":
        assert agent.stat().st_mode & 0o777 == 0o600
    assert run.call_args_list[0].args[0][1] == "print"
    assert run.call_args_list[0].kwargs["text"] is True
    assert run.call_args_list[1].args[0][1] == ("bootout" if registered else "bootstrap")
    assert run.call_args_list[-1].args[0][1] == "bootstrap"
    popen.assert_not_called()


def test_macos_does_not_replace_running_registration_without_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="\tpid = 1234\n"))
    monkeypatch.setattr(background.subprocess, "run", run)
    monkeypatch.setattr(background.psutil, "pid_exists", lambda pid: pid == 1234)
    with pytest.raises(RuntimeError, match="still running without a usable descriptor"):
        background.start_background_service(paths)
    assert run.call_count == 1


def test_macos_launch_failure_does_not_fall_back_to_app_owned_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        background.os,
        "getuid",
        lambda: os.geteuid() if hasattr(os, "geteuid") else 1000,
        raising=False,
    )
    monkeypatch.setattr(
        background.subprocess,
        "run",
        Mock(side_effect=[subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 5)]),
    )
    popen = Mock()
    monkeypatch.setattr(background.subprocess, "Popen", popen)
    with pytest.raises(RuntimeError, match="launchd helper .*exit 5"):
        background.start_background_service(paths)
    popen.assert_not_called()


def test_linux_helper_keeps_detached_process_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(sys, "platform", "linux")
    popen = Mock()
    monkeypatch.setattr(background.subprocess, "Popen", popen)
    run = Mock()
    monkeypatch.setattr(background.subprocess, "run", run)
    background.start_background_service(paths)
    assert popen.call_args.kwargs["start_new_session"] is True
    assert popen.call_args.kwargs["env"]["EFORGE_STUDIO_DAEMON"] == "1"
    assert popen.call_args.kwargs["stdin"] == subprocess.DEVNULL
    run.assert_not_called()
