"""Native cleanup controls and cancellation, confined to disposable test account paths."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from ctypes import wintypes as wt
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows dialog ABI")


@pytest.mark.parametrize("action", ["cancel", "preserve", "private"])
def test_native_cleanup_review_defaults_and_actions(tmp_path: Path, action: str) -> None:
    root = tmp_path / "cleanup test ü 汉"
    from evidenceforge.studio.state_io import private_directory

    private_directory(root)
    private = root / "AppData/Local/EvidenceForge"
    private.mkdir(parents=True)
    sentinel = private / "sentinel.txt"
    sentinel.write_text("private test data")
    unrelated = root / "Documents/EvidenceForge/unrelated.txt"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("preserve")
    script = """
import sys
from pathlib import Path
from evidenceforge.studio.windows_uninstall import UserLocations, build_plan
from evidenceforge.studio import windows_uninstall_ui as ui
from evidenceforge.utils.windows_filesystem import current_user_sid
root=Path(sys.argv[1])
ui.message=lambda *args: 6
plan=build_plan(UserLocations(profile=root,local=root/'AppData/Local',documents=root/'Documents',account=current_user_sid()))
raise SystemExit(ui.choose(plan))
"""
    with subprocess.Popen(
        [sys.executable, "-c", script, str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as child:
        try:
            from evidenceforge.studio.windows_uninstall_native import _function

            find = _function("user32", "FindWindowW", wt.HWND, [wt.LPCWSTR, wt.LPCWSTR])
            pid_for = _function(
                "user32", "GetWindowThreadProcessId", wt.DWORD, [wt.HWND, ctypes.POINTER(wt.DWORD)]
            )
            deadline = time.monotonic() + 20
            window = None
            while time.monotonic() < deadline:
                candidate = find("EvidenceForge.Uninstall.Review", None)
                pid = wt.DWORD()
                if candidate and pid_for(candidate, ctypes.byref(pid)) and pid.value == child.pid:
                    ready = _function("user32", "GetDlgItem", wt.HWND, [wt.HWND, ctypes.c_int])
                    if ready(candidate, 301):
                        window = candidate
                        break
                if child.poll() is not None:
                    break
                time.sleep(0.05)
            assert window, child.communicate(timeout=1)
            control = _function("user32", "GetDlgItem", wt.HWND, [wt.HWND, ctypes.c_int])
            send = _function(
                "user32", "SendMessageW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
            )
            for identifier in (101, 102, 103):
                assert send(control(window, identifier), 0xF0, 0, 0) == 0
            if action == "private":
                send(control(window, 101), 0xF1, 1, 0)
                send(window, 0x111, 101, control(window, 101))
            text = ctypes.create_unicode_buffer(32768)
            _function("user32", "GetWindowTextW", ctypes.c_int, [wt.HWND, wt.LPWSTR, ctypes.c_int])(
                control(window, 301), text, len(text)
            )
            assert str(root) in text.value
            if action == "private":
                assert str(private) in text.value and "DELETE:" in text.value
            button = 202 if action == "cancel" else 201
            send(control(window, button), 0xF5, 0, 0)
            stdout, stderr = child.communicate(timeout=20)
            assert child.returncode == (1 if action == "cancel" else 0), (stdout, stderr)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    assert sentinel.exists() is (action != "private")
    assert unrelated.read_text() == "preserve"


def test_broker_handoff_uses_original_token_and_fresh_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.studio import windows_uninstall_native as native
    from evidenceforge.utils import windows_filesystem as fs

    tokens = iter((201, 200))  # elevated broker, original non-elevated Explorer
    recorded: dict[str, object] = {}

    def function(library: str, name: str, result: object, arguments: list[object]) -> object:
        def call(*args: object) -> int:
            if name == "GetShellWindow":
                return 55
            if name == "GetWindowThreadProcessId":
                ctypes.cast(args[1], ctypes.POINTER(wt.DWORD))[0] = 9
            elif name == "ProcessIdToSessionId":
                ctypes.cast(args[1], ctypes.POINTER(wt.DWORD))[0] = 3
            elif name == "QueryFullProcessImageNameW":
                args[2].value = r"C:\Windows\explorer.exe"
            elif name == "GetWindowsDirectoryW":
                args[0].value = r"C:\Windows"
            elif name == "OpenProcessToken":
                ctypes.cast(args[2], ctypes.POINTER(wt.HANDLE))[0] = next(tokens)
            elif name == "DuplicateTokenEx":
                ctypes.cast(args[5], ctypes.POINTER(wt.HANDLE))[0] = 300
            elif name == "CreateEnvironmentBlock":
                assert args[1].value == 300 and args[2] is False
                ctypes.cast(args[0], ctypes.POINTER(wt.LPVOID))[0] = 88
            elif name == "CreateProcessWithTokenW":
                recorded["token"] = args[0].value
                recorded["command"] = args[3].value
                recorded["flags"] = args[4]
                info = ctypes.cast(args[8], ctypes.POINTER(native._ProcessInfo)).contents
                info.process, info.thread = 400, 401
            elif name == "WaitForSingleObject":
                return 0
            elif name == "GetExitCodeProcess":
                ctypes.cast(args[1], ctypes.POINTER(wt.DWORD))[0] = 0
            return 1

        return call

    monkeypatch.setattr(native, "_function", function)
    monkeypatch.setattr(native, "_elevated", lambda token: token.value == 201)
    monkeypatch.setattr(fs, "process_user_sid", lambda pid: "S-1-5-21-original-user")
    monkeypatch.setattr(native, "message", lambda *args: pytest.fail("Unexpected fallback"))
    assert native.broker() == 0
    assert recorded["token"] == 300
    assert "--expected-account S-1-5-21-original-user" in recorded["command"]
    assert recorded["flags"] == 0x08000400


def test_interactive_rejects_mismatched_account_before_inventory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from evidenceforge.studio import windows_uninstall_native as native
    from evidenceforge.studio.windows_uninstall import UserLocations

    monkeypatch.setattr(
        native,
        "user_locations",
        lambda: UserLocations(
            profile=tmp_path, local=tmp_path, documents=tmp_path, account="actual-account"
        ),
    )
    monkeypatch.setattr(
        native, "build_plan", lambda *args: pytest.fail("Must not inventory the wrong account")
    )
    monkeypatch.setattr(native, "message", lambda *args: 0)
    assert native.interactive("other-account") == 2
