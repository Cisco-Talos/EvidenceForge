"""Compile the real NSIS page and exercise its real checkbox/Cancel controls."""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from ctypes import wintypes as wt
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native NSIS wizard")


def _wait(predicate: Callable[[], bool], failure: str | Callable[[], str]) -> None:
    deadline = time.monotonic() + 25
    while not predicate():
        assert time.monotonic() < deadline, failure() if callable(failure) else failure
        time.sleep(0.03)


def _maker() -> Path:
    found = shutil.which("makensis")
    if found:
        return Path(found)
    candidates = [
        Path(os.environ["LOCALAPPDATA"]) / "tauri/NSIS/makensis.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "NSIS/makensis.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    pytest.fail("NSIS must be available after the preview packaging step")


@pytest.mark.parametrize("mode", ["cancel-review", "preserve", "private-and-work"])
def test_real_nsis_choices_and_cancel_remain_independent(tmp_path: Path, mode: str) -> None:
    from evidenceforge.studio.windows_uninstall_native import _function

    root = Path(__file__).resolve().parents[2]
    folder = tmp_path / "native wizard ü 汉"
    folder.mkdir()
    controller = folder / "controller.py"
    controller.write_text(
        f"import sys; sys.path.insert(0, {str(root)!r})\n"
        + """
import sys,time
from pathlib import Path
sys.stderr=open(Path(__file__).with_suffix('.log'),'w',buffering=1)
sys.stdout=sys.stderr
from evidenceforge.studio import windows_uninstall_session as session
from evidenceforge.studio.state_io import private_directory
from evidenceforge.studio.windows_uninstall import UserLocations
from evidenceforge.studio.windows_uninstall_wizard import WizardControls,run_wizard
from evidenceforge.utils.windows_filesystem import current_user_sid
from tests.unit.test_studio_uninstall_wizard import LocalChannel
root=Path(__file__).parent/'account'
private_directory(root)
locations=UserLocations(profile=root,local=root/'AppData/Local',documents=root/'Documents',account=current_user_sid())
private_directory(locations.private)
(locations.private/'sentinel.txt').write_text('private')
workspace=root/'EvidenceForge'
(workspace/'scenarios').mkdir(parents=True)
(workspace/'scenarios/test.yaml').write_text('name: test\\nschema_version: "3.0"\\n')
(workspace/'unrelated.txt').write_text('preserve')
(root/'.eforge').mkdir()
(root/'.eforge/publisher.yaml').write_text('publisher: test\\npublisher_display_name: Test\\n')
original=session.build_plan
def inspect(*args,check_cancelled,**kwargs):
    while not (Path(__file__).parent/'allow-review').exists():
        check_cancelled()
        time.sleep(.02)
    return original(*args,check_cancelled=check_cancelled,**kwargs)
session.build_plan=inspect
run_wizard(WizardControls(int(sys.argv[1]),int(sys.argv[2]),[int(x) for x in sys.argv[4:8]],int(sys.argv[3])),lambda:LocalChannel(locations))
""",
        encoding="utf-8",
    )
    if mode != "cancel-review":
        (folder / "allow-review").touch()
    template = (root / "desktop-ui/packaging/windows-installer.nsi").read_text()
    page = template.split("; EFORGE_CLEANUP_PAGE_BEGIN", 1)[1].split(
        "; EFORGE_CLEANUP_PAGE_END", 1
    )[0]
    # Only replace process launch: the NSIS page, styles, notifications, review and
    # navigation callbacks remain exactly the production template's bytes.
    launch = next(line for line in page.splitlines() if line.strip().startswith("Exec "))
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    assert pythonw.is_file(), "The native Python test environment must include pythonw.exe"
    command = f"""  Exec '\"{pythonw}\" \"{controller}\" $HWNDPARENT $EForgeCleanupPage $0 $EForgeCleanupPrivate $EForgeCleanupSkills $EForgeCleanupWork $EForgeCleanupReview' """
    page = page.replace(launch, command)
    installer = folder / "harness.exe"
    script = folder / "harness.nsi"
    script.write_text(
        f'''
Unicode true
!include MUI2.nsh
!include nsDialogs.nsh
!include LogicLib.nsh
!include WinMessages.nsh
Name "EvidenceForge Cleanup Harness"
OutFile "{installer}"
InstallDir "{folder}"
RequestExecutionLevel user
Var PassiveMode
Var UpdateMode
!define MAINBINARYNAME Studio
!define PRODUCTNAME "EvidenceForge Studio"
!macro CheckIfAppIsRunning binary name
!macroend
{page}
!insertmacro MUI_LANGUAGE English
Section
  WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd
Section Uninstall
  FileOpen $0 "$INSTDIR\\uninstalled.txt" w
  FileWrite $0 "application-only test marker"
  FileClose $0
  SetAutoClose true
SectionEnd
''',
        encoding="utf-8-sig",
    )
    compiled = subprocess.run([str(_maker()), "/V2", str(script)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    subprocess.run([str(installer), "/S", f"/D={folder}"], check=True, timeout=20)
    with subprocess.Popen([str(folder / "uninstall.exe"), f"_?={folder}"]) as child:
        try:
            callback_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
            enum = _function("user32", "EnumWindows", wt.BOOL, [callback_type, wt.LPARAM])
            pid_for = _function(
                "user32", "GetWindowThreadProcessId", wt.DWORD, [wt.HWND, ctypes.POINTER(wt.DWORD)]
            )
            window = 0

            @callback_type
            def find(handle: int, parameter: int) -> bool:
                nonlocal window
                pid = wt.DWORD()
                pid_for(handle, ctypes.byref(pid))
                name = ctypes.create_unicode_buffer(64)
                _function(
                    "user32", "GetClassNameW", ctypes.c_int, [wt.HWND, wt.LPWSTR, ctypes.c_int]
                )(handle, name, len(name))
                if pid.value == child.pid and name.value == "#32770":
                    window = handle
                return True

            def attached() -> bool:
                enum(find, 0)
                return bool(window)

            _wait(attached, "Native uninstaller window not found")
            controls: dict[str, int] = {}

            @callback_type
            def collect(handle: int, parameter: int) -> bool:
                text = ctypes.create_unicode_buffer(1024)
                _function(
                    "user32", "GetWindowTextW", ctypes.c_int, [wt.HWND, wt.LPWSTR, ctypes.c_int]
                )(handle, text, len(text))
                for label in ("Studio settings", "EvidenceForge skills", "Authored scenarios"):
                    if text.value.startswith(label):
                        controls[label] = handle
                return True

            def found() -> bool:
                _function(
                    "user32", "EnumChildWindows", wt.BOOL, [wt.HWND, callback_type, wt.LPARAM]
                )(window, collect, 0)
                return len(controls) == 3

            _wait(found, "Native cleanup checkboxes were not created")
            _function("user32", "SetForegroundWindow", wt.BOOL, [wt.HWND])(window)
            send = _function(
                "user32", "SendMessageW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
            )
            get = _function("user32", "GetDlgItem", wt.HWND, [wt.HWND, ctypes.c_int])
            enabled = _function("user32", "IsWindowEnabled", wt.BOOL, [wt.HWND])
            next_button = get(window, 1)

            def failure() -> str:
                log = controller.with_suffix(".log")
                return log.read_text() if log.exists() else "Controller did not start"

            _wait(lambda: bool(enabled(next_button)), failure)
            assert all(send(handle, 0xF0, 0, 0) == 0 for handle in controls.values())
            if mode == "cancel-review":
                for handle in controls.values():
                    send(handle, 0xF5, 0, 0)  # BM_CLICK, not BM_SETCHECK.
                assert all(send(handle, 0xF0, 0, 0) == 1 for handle in controls.values())
                for handle in controls.values():
                    send(handle, 0xF5, 0, 0)
                assert all(send(handle, 0xF0, 0, 0) == 0 for handle in controls.values())
                send(controls["Studio settings"], 0xF5, 0, 0)
                start = time.monotonic()
                send(get(window, 2), 0xF5, 0, 0)
                assert child.wait(timeout=5) != 0
                assert time.monotonic() - start < 5
            else:
                if mode == "private-and-work":
                    send(controls["Studio settings"], 0xF5, 0, 0)
                    send(controls["Authored scenarios"], 0xF5, 0, 0)
                    _wait(lambda: bool(enabled(next_button)), failure)
                send(next_button, 0xF5, 0, 0)
                assert child.wait(timeout=20) == 0, failure()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    account = folder / "account"
    assert (account / "AppData/Local/EvidenceForge/sentinel.txt").exists() is (
        mode != "private-and-work"
    )
    assert (account / "EvidenceForge/scenarios/test.yaml").exists() is (mode != "private-and-work")
    assert (account / ".eforge/publisher.yaml").exists()
    assert (account / "EvidenceForge/unrelated.txt").read_text() == "preserve"
    assert (folder / "uninstalled.txt").exists() is (mode != "cancel-review")
