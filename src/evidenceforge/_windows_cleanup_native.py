# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""No-follow attribute repair for removal of caller-owned Windows scratch."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

from evidenceforge._windows_paths import filesystem_path


class _BasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", wintypes.DWORD),
    ]


class _StandardInfo(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_int64),
        ("EndOfFile", ctypes.c_int64),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", wintypes.BYTE),
        ("Directory", wintypes.BYTE),
    ]


def _eligible_attributes(attributes: int, tag: int) -> bool:
    """Allow ordinary entries and Cloud Files placeholders, never redirections."""
    return bool(attributes & 0x1) and (not attributes & 0x400 or tag & ~0xF000 == 0x9000001A)


def clear_readonly_for_removal(path: Path) -> bool:
    """Clear only ReadOnly on a pinned owned entry; preserve ACLs and other bits.

    OPEN_REPARSE_POINT inspects the entry itself. Cloud Files tags are storage
    placeholders rather than name surrogates; all other reparse tags are refused.
    An ordinary multiply-linked file is also refused. The caller establishes
    scratch ownership and must still perform and confirm the actual removal.
    """
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    get_info = kernel.GetFileInformationByHandleEx
    get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    get_info.restype = wintypes.BOOL
    set_info = kernel.SetFileInformationByHandle
    set_info.argtypes = get_info.argtypes
    set_info.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    # READ_ATTRIBUTES | WRITE_ATTRIBUTES; share read/write/delete so our own
    # inspection does not block removal. OPEN_EXISTING, BACKUP_SEMANTICS and
    # OPEN_REPARSE_POINT avoid traversing the final entry.
    handle = create(str(filesystem_path(path)), 0x180, 0x7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        tags = (wintypes.DWORD * 2)()
        if not get_info(handle, 9, tags, ctypes.sizeof(tags)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not _eligible_attributes(tags[0], tags[1]):
            return False
        standard = _StandardInfo()
        if not get_info(handle, 1, ctypes.byref(standard), ctypes.sizeof(standard)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not standard.Directory and standard.NumberOfLinks != 1:
            return False
        basic = _BasicInfo()
        if not get_info(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            raise ctypes.WinError(ctypes.get_last_error())
        basic.FileAttributes = (basic.FileAttributes & ~0x1) or 0x80
        if not set_info(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    finally:
        close(handle)
