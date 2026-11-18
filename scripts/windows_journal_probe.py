# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Probe why SQLite cannot reopen a private native journal in the current sandbox.

Diagnostic only. Run with the installed Studio runtime's python.exe, once inside the
Codex authoring sandbox (ask the agent to run it) and once from ordinary PowerShell,
passing a writable directory such as a draft folder:

    & '<runtime>\\python.exe' -I -B -X utf8 windows_journal_probe.py '<writable folder>'

It prints the process token's sandbox identity, then creates directories and files with
private (protected) and inherited ACLs and reports whether SQLite and a plain path-based
CreateFileW can reopen each one. Every created entry is removed afterwards.
"""

from __future__ import annotations

import ctypes
import os
import sqlite3
import sys
import uuid
from ctypes import wintypes
from pathlib import Path

from evidenceforge.utils import windows_filesystem as fs

_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel.GetCurrentProcess.restype = wintypes.HANDLE
_kernel.LocalFree.argtypes = [wintypes.LPVOID]
_advapi.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
_advapi.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_advapi.IsTokenRestricted.argtypes = [wintypes.HANDLE]
_advapi.GetSidSubAuthorityCount.restype = ctypes.c_void_p
_advapi.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
_advapi.GetSidSubAuthority.restype = ctypes.c_void_p
_advapi.GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
_advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.c_int,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.LPVOID),
]
_advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPWSTR),
    wintypes.LPVOID,
]


def _token_dword(information_class: int) -> int | None:
    token = wintypes.HANDLE()
    if not _advapi.OpenProcessToken(_kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        return None
    try:
        value, size = wintypes.DWORD(), wintypes.DWORD()
        if not _advapi.GetTokenInformation(
            token, information_class, ctypes.byref(value), 4, ctypes.byref(size)
        ):
            return None
        return value.value
    finally:
        _kernel.CloseHandle(token)


def _sddl(path: Path) -> str:
    descriptor = wintypes.LPVOID()
    result = _advapi.GetNamedSecurityInfoW(
        str(path), 1, 0x4 | 0x1, None, None, None, None, ctypes.byref(descriptor)
    )
    if result != 0:
        return f"<GetNamedSecurityInfoW error {result}>"
    text = wintypes.LPWSTR()
    try:
        if not _advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 0x4 | 0x1, ctypes.byref(text), None
        ):
            return f"<convert error {ctypes.get_last_error()}>"
        return text.value
    finally:
        _kernel.LocalFree(descriptor)
        if text:
            _kernel.LocalFree(text)


def _create_file_w(path: Path) -> str:
    create = _kernel.CreateFileW
    create.restype = wintypes.HANDLE
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    handle = create(str(path), 0xC0000000, 0x3, None, 3, 0x80, None)  # RW, share RW, OPEN_EXISTING
    if handle in (None, wintypes.HANDLE(-1).value):
        return f"FAIL error {ctypes.get_last_error()}"
    _kernel.CloseHandle(handle)
    return "OK"


def _sqlite(path: Path) -> str:
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True)
        connection.execute("CREATE TABLE IF NOT EXISTS probe (value INTEGER)")
        connection.execute("INSERT INTO probe VALUES (1)")
        connection.commit()
        connection.close()
        return "OK"
    except sqlite3.Error as error:
        return f"FAIL {error}"


def main() -> int:
    base = Path(os.path.abspath(sys.argv[1]))
    print(f"base={base}")
    print(
        "token: app_container="
        f"{_token_dword(29)} is_restricted={bool(_advapi.IsTokenRestricted(_token_handle()))} "
        f"integrity_rid={_integrity_rid()} user={fs.current_user_sid()}"
    )
    print(f"base DACL: {_sddl(base)}")
    parent = fs.open_directory(base)
    created: list[tuple[Path, bool]] = []
    try:
        for directory_private in (True, False):
            for file_private in (True, False):
                label = (
                    f"dir={'private' if directory_private else 'inherited'} "
                    f"file={'private' if file_private else 'inherited'}"
                )
                name = f"journal-probe-{uuid.uuid4().hex[:8]}"
                fs.mkdir_child(parent, name, 0o700 if directory_private else 0o777)
                directory = base / name
                created.append((directory, True))
                child = fs.open_directory(directory)
                try:
                    file_name = "journal.sqlite3"
                    descriptor = fs.open_child(
                        child,
                        file_name,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL,
                        0o600 if file_private else 0o666,
                    )
                    os.close(descriptor)
                finally:
                    os.close(child)
                path = directory / file_name
                created.append((path, False))
                print(f"{label}: CreateFileW={_create_file_w(path)} sqlite={_sqlite(path)}")
                print(f"    dir DACL:  {_sddl(directory)}")
                print(f"    file DACL: {_sddl(path)}")
        _long_path_variants(base, parent, created)
    finally:
        os.close(parent)
        for path, directory in reversed(created):
            physical = "\\\\?\\" + str(path)
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    os.unlink(f"{physical}{suffix}")
                except OSError:
                    pass
            try:
                os.rmdir(physical) if directory else os.unlink(physical)
            except OSError as error:
                print(f"cleanup left {path}: {error}")
    return 0


def _sqlite_open(target: str, *, uri: bool) -> str:
    try:
        connection = sqlite3.connect(target, uri=uri)
        connection.execute("CREATE TABLE IF NOT EXISTS probe (value INTEGER)")
        connection.execute("INSERT INTO probe VALUES (1)")
        connection.commit()
        connection.close()
        return "OK"
    except sqlite3.Error as error:
        return f"FAIL {error}"


def _long_path_variants(base: Path, parent: int, created: list[tuple[Path, bool]]) -> None:
    """Build a journal beyond MAX_PATH natively, then try each SQLite path spelling."""
    from urllib.parse import quote

    print(f"sqlite_version={sqlite3.sqlite_version}")
    directory, handle = base, parent
    while len(str(directory)) < 240:
        name = f"deep-{uuid.uuid4().hex}"
        fs.mkdir_child(handle, name, 0o700)
        directory = directory / name
        created.append((directory, True))
        if handle != parent:
            os.close(handle)
        handle = fs.open_directory(directory)
    try:
        descriptor = fs.open_child(handle, "journal.sqlite3", os.O_RDWR | os.O_CREAT | os.O_EXCL)
        os.close(descriptor)
    finally:
        if handle != parent:
            os.close(handle)
    path = directory / "journal.sqlite3"
    created.append((path, False))
    extended = "\\\\?\\" + str(path)
    print(f"long journal length={len(str(path))}")
    print(f"L1 URI, ordinary path:        {_sqlite_open(f'{path.as_uri()}?mode=rw', uri=True)}")
    print(f"L2 plain extended path:       {_sqlite_open(extended, uri=False)}")
    print(
        f"L3 URI, quoted extended path: {_sqlite_open(f'file:{quote(extended)}?mode=rw', uri=True)}"
    )
    print(f"L4 CreateFileW extended path: {_create_file_w(Path(extended))}")


def _token_handle() -> wintypes.HANDLE:
    token = wintypes.HANDLE()
    _advapi.OpenProcessToken(_kernel.GetCurrentProcess(), 0x8, ctypes.byref(token))
    return token


def _integrity_rid() -> int | None:
    token = _token_handle()
    try:
        size = wintypes.DWORD()
        _advapi.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not _advapi.GetTokenInformation(token, 25, buffer, size, ctypes.byref(size)):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID))[0]
        count = ctypes.cast(_advapi.GetSidSubAuthorityCount(sid), ctypes.POINTER(ctypes.c_ubyte))[0]
        return ctypes.cast(
            _advapi.GetSidSubAuthority(sid, count - 1), ctypes.POINTER(wintypes.DWORD)
        )[0]
    finally:
        _kernel.CloseHandle(token)


if __name__ == "__main__":
    raise SystemExit(main())
