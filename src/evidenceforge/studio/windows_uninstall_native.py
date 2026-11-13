"""Native account handoff and review for the Windows uninstaller; never elevate cleanup."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes as wt
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_uninstall import UserLocations, build_plan


def _function(library: str, name: str, result: Any, arguments: list[Any]) -> Any:
    function = getattr(ctypes.WinDLL(library, use_last_error=True), name)
    function.restype = result
    function.argtypes = arguments
    return function


def _require(value: Any) -> None:
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())


def message(text: str, flags: int = 0, owner: int | None = None) -> int:
    """Show a native, console-free account/data message."""
    return _function(
        "user32", "MessageBoxW", ctypes.c_int, [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT]
    )(owner, text, "Uninstall EvidenceForge Studio", flags)


def _elevated(token: Any) -> bool:
    value = wt.DWORD()
    size = wt.DWORD()
    _require(
        _function(
            "advapi32",
            "GetTokenInformation",
            wt.BOOL,
            [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD)],
        )(token, 20, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size))
    )
    return value.value != 0


def user_locations() -> UserLocations:
    """Resolve profile folders from this unelevated token, not administrator environment."""
    from evidenceforge.utils.windows_filesystem import current_user_sid

    token = wt.HANDLE()
    current = _function("kernel32", "GetCurrentProcess", wt.HANDLE, [])()
    _require(
        _function(
            "advapi32",
            "OpenProcessToken",
            wt.BOOL,
            [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)],
        )(current, 8, ctypes.byref(token))
    )
    close = _function("kernel32", "CloseHandle", wt.BOOL, [wt.HANDLE])
    try:
        if _elevated(token):
            raise StudioStateError(
                "User-data cleanup must run without elevation; no files were removed"
            )
    finally:
        close(token)

    def folder(identifier: str) -> Path:
        guid = (ctypes.c_ubyte * 16).from_buffer_copy(UUID(identifier).bytes_le)
        result = wt.LPWSTR()
        status = _function(
            "shell32",
            "SHGetKnownFolderPath",
            ctypes.c_long,
            [wt.LPVOID, wt.DWORD, wt.HANDLE, ctypes.POINTER(wt.LPWSTR)],
        )(ctypes.byref(guid), 0, None, ctypes.byref(result))
        if status < 0:
            raise OSError(f"Could not identify the current account's folder: {identifier}")
        try:
            return Path(result.value)
        finally:
            _function("ole32", "CoTaskMemFree", None, [wt.LPVOID])(ctypes.cast(result, wt.LPVOID))

    return UserLocations(
        profile=folder("5E6C858F-0E22-4760-9AFE-EA3317B67173"),
        local=folder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091"),
        documents=folder("FDD39AD0-238F-46AF-ADB4-6C85480369C7"),
        account=current_user_sid(),
    )


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("reserved", wt.LPWSTR),
        ("desktop", wt.LPWSTR),
        ("title", wt.LPWSTR),
        ("x", wt.DWORD),
        ("y", wt.DWORD),
        ("width", wt.DWORD),
        ("height", wt.DWORD),
        ("chars_x", wt.DWORD),
        ("chars_y", wt.DWORD),
        ("fill", wt.DWORD),
        ("flags", wt.DWORD),
        ("show", wt.WORD),
        ("reserved_size", wt.WORD),
        ("reserved_data", wt.LPVOID),
        ("stdin", wt.HANDLE),
        ("stdout", wt.HANDLE),
        ("stderr", wt.HANDLE),
    ]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("process", wt.HANDLE), ("thread", wt.HANDLE), ("pid", wt.DWORD), ("tid", wt.DWORD)]


def broker() -> int:
    """Run the cleanup dialog using the authenticated, same-session Explorer token."""
    from evidenceforge.utils.windows_filesystem import current_user_sid, process_user_sid

    close = _function("kernel32", "CloseHandle", wt.BOOL, [wt.HANDLE])
    handles: list[Any] = []
    environment = wt.LPVOID()
    child_started = False
    try:
        shell = _function("user32", "GetShellWindow", wt.HWND, [])()
        if not shell:
            raise StudioStateError("The original desktop account could not be identified")
        pid = wt.DWORD()
        _require(
            _function(
                "user32", "GetWindowThreadProcessId", wt.DWORD, [wt.HWND, ctypes.POINTER(wt.DWORD)]
            )(shell, ctypes.byref(pid))
        )
        session = _function(
            "kernel32", "ProcessIdToSessionId", wt.BOOL, [wt.DWORD, ctypes.POINTER(wt.DWORD)]
        )
        source_session, current_session = wt.DWORD(), wt.DWORD()
        _require(session(pid, ctypes.byref(source_session)))
        _require(session(os.getpid(), ctypes.byref(current_session)))
        if source_session.value != current_session.value:
            raise StudioStateError("Cleanup refuses another desktop session")
        process = _function("kernel32", "OpenProcess", wt.HANDLE, [wt.DWORD, wt.BOOL, wt.DWORD])(
            0x1000, False, pid
        )
        _require(process)
        handles.append(process)
        image = ctypes.create_unicode_buffer(32768)
        length = wt.DWORD(len(image))
        _require(
            _function(
                "kernel32",
                "QueryFullProcessImageNameW",
                wt.BOOL,
                [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)],
            )(process, 0, image, ctypes.byref(length))
        )
        windows = ctypes.create_unicode_buffer(32768)
        _require(
            _function("kernel32", "GetWindowsDirectoryW", wt.UINT, [wt.LPWSTR, wt.UINT])(
                windows, len(windows)
            )
        )
        if Path(image.value) != Path(windows.value) / "explorer.exe":
            raise StudioStateError("The desktop owner is not the Windows shell")
        account = process_user_sid(pid.value)
        own_token = wt.HANDLE()
        current = _function("kernel32", "GetCurrentProcess", wt.HANDLE, [])()
        _require(
            _function(
                "advapi32",
                "OpenProcessToken",
                wt.BOOL,
                [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)],
            )(current, 8, ctypes.byref(own_token))
        )
        handles.append(own_token)
        if not _elevated(own_token):
            if current_user_sid() != account:
                raise StudioStateError("The uninstaller is not running as the desktop account")
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    "utf8",
                    "-m",
                    "evidenceforge.studio.windows_uninstall",
                    "--interactive",
                    "--expected-account",
                    account,
                ],
                check=False,
                creationflags=0x08000000,
            ).returncode
        token = wt.HANDLE()
        _require(
            _function(
                "advapi32",
                "OpenProcessToken",
                wt.BOOL,
                [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)],
            )(process, 0xB, ctypes.byref(token))
        )
        handles.append(token)
        if _elevated(token):
            raise StudioStateError("The desktop is elevated; cleanup needs a normal user desktop")
        primary = wt.HANDLE()
        _require(
            _function(
                "advapi32",
                "DuplicateTokenEx",
                wt.BOOL,
                [
                    wt.HANDLE,
                    wt.DWORD,
                    wt.LPVOID,
                    ctypes.c_int,
                    ctypes.c_int,
                    ctypes.POINTER(wt.HANDLE),
                ],
            )(token, 0x02000000, None, 2, 1, ctypes.byref(primary))
        )
        handles.append(primary)
        _require(
            _function(
                "userenv",
                "CreateEnvironmentBlock",
                wt.BOOL,
                [ctypes.POINTER(wt.LPVOID), wt.HANDLE, wt.BOOL],
            )(ctypes.byref(environment), primary, False)
        )
        account = process_user_sid(pid.value)
        command = ctypes.create_unicode_buffer(
            subprocess.list2cmdline(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    "utf8",
                    "-m",
                    "evidenceforge.studio.windows_uninstall",
                    "--interactive",
                    "--expected-account",
                    account,
                ]
            )
        )
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.desktop = "winsta0\\default"
        child = _ProcessInfo()
        _require(
            _function(
                "advapi32",
                "CreateProcessWithTokenW",
                wt.BOOL,
                [
                    wt.HANDLE,
                    wt.DWORD,
                    wt.LPCWSTR,
                    wt.LPWSTR,
                    wt.DWORD,
                    wt.LPVOID,
                    wt.LPCWSTR,
                    ctypes.POINTER(_StartupInfo),
                    ctypes.POINTER(_ProcessInfo),
                ],
            )(
                primary,
                1,
                sys.executable,
                command,
                0x08000400,
                environment,
                str(Path(sys.executable).parent),
                ctypes.byref(startup),
                ctypes.byref(child),
            )
        )
        child_started = True
        handles.extend((child.process, child.thread))
        wait = _function("kernel32", "WaitForSingleObject", wt.DWORD, [wt.HANDLE, wt.DWORD])
        if wait(child.process, 0xFFFFFFFF) != 0:
            raise StudioStateError("Could not wait for the account's uninstall choices")
        result = wt.DWORD()
        _require(
            _function(
                "kernel32", "GetExitCodeProcess", wt.BOOL, [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
            )(child.process, ctypes.byref(result))
        )
        return result.value
    except (OSError, EvidenceForgeError) as error:
        if child_started:
            message(
                f"Uninstall could not confirm that cleanup has finished: {error}. Close its review window and retry.",
                0x10,
            )
            return 2
        # App-only uninstall remains available, but uncertain identity never authorizes deletion.
        return (
            0
            if message(
                f"User-data cleanup is unavailable: {error}\n\n"
                "Continue uninstalling the application and preserve all user data and skills?",
                0x134,
            )
            == 6
            else 1
        )
    finally:
        if environment:
            _function("userenv", "DestroyEnvironmentBlock", wt.BOOL, [wt.LPVOID])(environment)
        for handle in reversed(handles):
            close(handle)


def interactive(expected_account: str | None) -> int:
    """Review and execute choices only after confirming the unelevated account handoff."""
    try:
        locations = user_locations()
        if not expected_account or locations.account != expected_account:
            raise StudioStateError("Uninstall's original account could not be authenticated")
        from evidenceforge.studio.windows_uninstall_ui import choose

        return choose(build_plan(locations))
    except (OSError, EvidenceForgeError, ValidationError, ValueError) as error:
        return (
            0
            if message(
                f"No cleanup was started. {error}\n\n"
                "Continue uninstalling only the application and preserve all user data and skills?",
                0x134,
            )
            == 6
            else 2
        )
