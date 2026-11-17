# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Probe which Windows directory/file publication forms work in the current sandbox.

Diagnostic only. Run with the installed Studio runtime's python.exe, once inside the
Codex authoring sandbox (ask the agent to run it) and once from an ordinary PowerShell
window, passing a writable directory such as a draft folder:

    & '<runtime>\\python.exe' -I -B -X utf8 windows_rename_probe.py '<writable folder>'

Each variant creates and removes its own uniquely named entries and prints one line.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
import traceback
import uuid
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO
from evidenceforge.utils import windows_filesystem as fs

_FILE_ADD_FILE = 0x2
_FILE_ADD_SUBDIRECTORY = 0x4


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _temp_directory(parent: int, name: str, *, write_through: bool = True) -> None:
    descriptor = fs.open_child(
        parent, name, os.O_CREAT | os.O_EXCL, 0o777, directory=True, write_through=write_through
    )
    os.close(descriptor)


def _rename_full_path(source: Path, target: Path, *, directory: bool) -> None:
    """FileRenameInformation with no RootDirectory and an absolute NT target path."""
    source_parent = fs.open_directory(source.parent)
    try:
        descriptor = fs._open_native(
            source.name,
            root=fs._handle(source_parent),
            flags=os.O_RDONLY,
            directory=directory,
            extra_access=fs._DELETE,
        )
    finally:
        os.close(source_parent)
    try:
        encoded = ("\\??\\" + str(target)).encode("utf-16-le")
        buffer = ctypes.create_string_buffer(ctypes.sizeof(fs._RenameInformation) + len(encoded))
        information = fs._RenameInformation.from_buffer(buffer)
        information.Flags = 0
        information.RootDirectory = None
        information.FileNameLength = len(encoded)
        ctypes.memmove(
            ctypes.addressof(buffer) + fs._RenameInformation.FileName.offset, encoded, len(encoded)
        )
        status = fs._IoStatusBlock()
        result = fs._nt_set_information(
            fs._handle(descriptor), ctypes.byref(status), buffer, len(buffer), 10
        )
        if result < 0:
            raise ctypes.WinError(fs._nt_error(result))
    finally:
        os.close(descriptor)


def main() -> int:
    base = Path(os.path.abspath(sys.argv[1]))
    print(f"python={sys.version.split()[0]} windows={platform.version()} base={base}")
    print(f"user={os.environ.get('USERNAME')} sandbox_env={os.environ.get('CODEX_SANDBOX', '')}")
    parent = fs.open_directory(base)
    cleanup: list[tuple[Path, bool]] = []

    def relative_directory_rename(write_through: bool) -> Callable[[], None]:
        def run() -> None:
            temporary, final = _unique("tmp-dir"), _unique("final-dir")
            _temp_directory(parent, temporary)
            cleanup.append((base / temporary, True))
            fs.replace_child(
                parent,
                temporary,
                parent,
                final,
                replace=False,
                directory=True,
                write_through=write_through,
            )
            cleanup.append((base / final, True))

        return run

    def relative_rename_with_add_access() -> None:
        grandparent = fs.open_directory(base.parent)
        try:
            target_parent = fs._open_native(
                base.name,
                root=fs._handle(grandparent),
                flags=os.O_RDONLY,
                directory=True,
                extra_access=_FILE_ADD_FILE | _FILE_ADD_SUBDIRECTORY,
            )
        finally:
            os.close(grandparent)
        try:
            temporary, final = _unique("tmp-dir"), _unique("final-dir")
            _temp_directory(parent, temporary)
            cleanup.append((base / temporary, True))
            fs.replace_child(
                parent,
                temporary,
                target_parent,
                final,
                replace=False,
                directory=True,
                write_through=True,
            )
            cleanup.append((base / final, True))
        finally:
            os.close(target_parent)

    def full_path_directory_rename() -> None:
        temporary, final = _unique("tmp-dir"), _unique("final-dir")
        _temp_directory(parent, temporary)
        cleanup.append((base / temporary, True))
        _rename_full_path(base / temporary, base / final, directory=True)
        cleanup.append((base / final, True))

    def move_file_ex_directory() -> None:
        temporary, final = _unique("tmp-dir"), _unique("final-dir")
        _temp_directory(parent, temporary)
        cleanup.append((base / temporary, True))
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        if not move(str(base / temporary), str(base / final), 0x8):  # MOVEFILE_WRITE_THROUGH
            raise ctypes.WinError(ctypes.get_last_error())
        cleanup.append((base / final, True))

    def direct_directory_create() -> None:
        final = _unique("direct-dir")
        _temp_directory(parent, final)
        cleanup.append((base / final, True))

    def relative_file_replace() -> None:
        temporary, final = _unique("tmp-file"), _unique("final-file")
        descriptor = fs.open_child(parent, temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.write(descriptor, b"probe\n")
            fs.flush_file(descriptor)
        finally:
            os.close(descriptor)
        cleanup.append((base / temporary, False))
        fs.replace_child(
            parent, temporary, parent, final, replace=True, directory=False, write_through=True
        )
        cleanup.append((base / final, False))

    final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    final_path.restype = wintypes.DWORD
    final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]

    def handle_path(descriptor: int, volume_flag: int) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        if not final_path(fs._handle(descriptor), buffer, 32768, volume_flag):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def handle_derived_rename(volume_flag: int, *, directory: bool) -> Callable[[], None]:
        """The fix's fallback: rename by the pinned parent's own path, then verify."""

        def run() -> None:
            temporary, final = _unique("tmp"), _unique("final")
            if directory:
                _temp_directory(parent, temporary)
            else:
                os.close(fs.open_child(parent, temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR))
            cleanup.append((base / temporary, directory))
            descriptor = fs._open_native(
                temporary,
                root=fs._handle(parent),
                flags=os.O_RDONLY,
                directory=directory,
                extra_access=fs._DELETE,
            )
            try:
                parent_path = handle_path(parent, volume_flag)
                if volume_flag == 0 and parent_path.startswith("\\\\?\\"):
                    parent_path = "\\??\\" + parent_path[4:]
                expected = parent_path.rstrip("\\") + "\\" + final
                encoded = expected.encode("utf-16-le")
                size = ctypes.sizeof(fs._RenameInformation) + len(encoded)
                buffer = ctypes.create_string_buffer(size)
                information = fs._RenameInformation.from_buffer(buffer)
                information.Flags = 0
                information.RootDirectory = None
                information.FileNameLength = len(encoded)
                ctypes.memmove(
                    ctypes.addressof(buffer) + fs._RenameInformation.FileName.offset,
                    encoded,
                    len(encoded),
                )
                status = fs._IoStatusBlock()
                result = fs._nt_set_information(
                    fs._handle(descriptor), ctypes.byref(status), buffer, len(buffer), 10
                )
                if result < 0:
                    raise ctypes.WinError(fs._nt_error(result))
                cleanup.append((base / final, directory))
                moved = handle_path(descriptor, 0x2).casefold()
                beneath = (handle_path(parent, 0x2).rstrip("\\") + "\\" + final).casefold()
                if moved != beneath:
                    raise OSError(f"verification mismatch: {moved} != {beneath}")
            finally:
                os.close(descriptor)

        return run

    def checkpoint_mkdir() -> None:
        target = base / _unique("checkpoint") / "nested"
        WindowsCheckpointIO().mkdir(target, parents=True, exist_ok=True)
        cleanup.append((target, True))
        cleanup.append((target.parent, True))

    variants: list[tuple[str, Callable[[], None]]] = [
        ("A checkpoint mkdir (current product path)", checkpoint_mkdir),
        ("B relative directory rename, write-through", relative_directory_rename(True)),
        ("C relative directory rename, no write-through", relative_directory_rename(False)),
        ("D relative rename, target parent with ADD access", relative_rename_with_add_access),
        ("E full-path directory rename (no RootDirectory)", full_path_directory_rename),
        ("F MoveFileExW directory, write-through", move_file_ex_directory),
        ("G direct directory create, write-through", direct_directory_create),
        ("H relative file replace, write-through", relative_file_replace),
        ("I fix: NT-path directory rename + verify", handle_derived_rename(0x2, directory=True)),
        ("J fix: NT-path file rename + verify", handle_derived_rename(0x2, directory=False)),
        ("K DOS-path directory rename + verify", handle_derived_rename(0x0, directory=True)),
    ]
    try:
        for label, variant in variants:
            try:
                variant()
                print(f"OK    {label}")
            except OSError as error:
                print(f"FAIL  {label}: {error!r}")
            except Exception:  # noqa: BLE001 - diagnostic output must report every failure
                print(f"FAIL  {label}: {traceback.format_exc(limit=1).strip()}")
    finally:
        for path, directory in reversed(cleanup):
            try:
                os.rmdir(path) if directory else os.unlink(path)
            except OSError:
                pass
        os.close(parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
