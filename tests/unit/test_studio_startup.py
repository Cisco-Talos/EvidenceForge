"""Slow startup remains bounded, owned and observable without false early failure."""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.studio import bootstrap
from evidenceforge.studio.state_io import StudioStateError
from tests.unit.test_studio_runtime import _paths


def _clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    clock = {"now": 0.0}

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    monkeypatch.setattr(
        bootstrap, "time", SimpleNamespace(monotonic=lambda: clock["now"], sleep=sleep)
    )
    return clock


@pytest.mark.parametrize(
    "platform,delay,succeeds",
    [("win32", 20, True), ("darwin", 20, False), ("linux", 20, False), ("win32", 80, False)],
)
def test_delayed_readiness_has_a_windows_budget_and_preserves_posix_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    delay: int,
    succeeds: bool,
) -> None:
    clock = _clock(monkeypatch)
    selected = bootstrap.ServiceDescriptor(
        pid=42, created_at=100, port=1234, token="never-log-this", runtime_id="selected"
    )
    monkeypatch.setattr(bootstrap, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "selected")
    monkeypatch.setattr(
        bootstrap, "_read_descriptor", lambda path: selected if clock["now"] >= delay else None
    )
    monkeypatch.setattr(bootstrap, "_is_live", lambda descriptor: True)
    child = Mock()
    child.poll.return_value = None
    launch = Mock(return_value=child)
    monkeypatch.setattr(bootstrap, "start_background_service", launch)
    paths = _paths(tmp_path)
    if succeeds:
        assert bootstrap.connect_or_start(paths) == selected
    else:
        with pytest.raises(RuntimeError, match="did not become ready"):
            bootstrap.connect_or_start(paths)
        budget = 60 if platform == "win32" else 12
        assert budget <= clock["now"] < budget + 0.2
    launch.assert_called_once_with(paths)
    child.terminate.assert_not_called()
    log = (paths.logs / "service.log").read_text()
    assert "runtime=selected" in log and "elapsed_s=" in log and "role=launcher" in log
    assert "never-log-this" not in log
    assert ("phase=ready" in log) == succeeds


def test_second_windows_launch_waits_for_the_same_slow_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _clock(monkeypatch)
    original_acquire = bootstrap.StateLock.acquire

    def acquire(lock: bootstrap.StateLock) -> None:
        if clock["now"] < 20:
            raise StudioStateError("The first window is preparing the helper")
        original_acquire(lock)

    selected = bootstrap.ServiceDescriptor(
        pid=42, created_at=100, port=1234, token="private", runtime_id="selected"
    )
    monkeypatch.setattr(bootstrap, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "selected")
    monkeypatch.setattr(bootstrap.StateLock, "acquire", acquire)
    monkeypatch.setattr(
        bootstrap, "_read_descriptor", lambda path: selected if clock["now"] >= 20 else None
    )
    monkeypatch.setattr(bootstrap, "_is_live", lambda descriptor: True)
    launch = Mock(return_value=None)
    monkeypatch.setattr(bootstrap, "start_background_service", launch)
    assert bootstrap.connect_or_start(_paths(tmp_path)) == selected
    launch.assert_not_called()


def test_exited_new_helper_fails_promptly_without_waiting_or_relaunching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _clock(monkeypatch)
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "selected")
    monkeypatch.setattr(bootstrap, "_read_descriptor", lambda path: None)
    child = Mock()
    child.poll.return_value = 17
    launch = Mock(return_value=child)
    monkeypatch.setattr(bootstrap, "start_background_service", launch)
    with pytest.raises(RuntimeError, match="exited before becoming ready.*17"):
        bootstrap.connect_or_start(_paths(tmp_path))
    assert clock["now"] == 0
    launch.assert_called_once()
    child.terminate.assert_not_called()


def test_attachment_launcher_does_not_import_the_application() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys; import evidenceforge.studio.bootstrap; "
            "assert 'evidenceforge.studio.service' not in sys.modules; print('lightweight launcher')",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert result.stdout.strip() == "lightweight launcher"


def test_verified_starting_helper_exit_is_detected_without_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _clock(monkeypatch)
    selected = bootstrap.ServiceDescriptor(
        pid=42, created_at=100, port=1234, token="private", runtime_id="selected"
    )
    monkeypatch.setattr(bootstrap, "runtime_id", lambda: "selected")
    monkeypatch.setattr(bootstrap, "_read_descriptor", lambda path: selected)
    monkeypatch.setattr(bootstrap, "_is_live", lambda descriptor: False)
    verify = Mock(side_effect=[object(), None, None])
    monkeypatch.setattr(bootstrap, "_verified_process", verify)
    launch = Mock(return_value=None)
    monkeypatch.setattr(bootstrap, "start_background_service", launch)
    with pytest.raises(RuntimeError, match="exited while becoming ready"):
        bootstrap.connect_or_start(_paths(tmp_path))
    assert clock["now"] == 0
    launch.assert_not_called()
