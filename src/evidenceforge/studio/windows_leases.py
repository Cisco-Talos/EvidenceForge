"""Windows kernel-held shared runtime leases, interoperable with Rust File locks."""

from __future__ import annotations

import ctypes
import msvcrt
from ctypes import wintypes


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def lock_runtime(descriptor: int, *, exclusive: bool) -> None:
    """Lock the full file range until its descriptor closes, without polling."""
    lock = ctypes.WinDLL("kernel32", use_last_error=True).LockFileEx
    lock.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    lock.restype = wintypes.BOOL
    overlapped = _Overlapped()
    if not lock(
        msvcrt.get_osfhandle(descriptor),
        1 | (2 if exclusive else 0),
        0,
        0xFFFFFFFF,
        0xFFFFFFFF,
        ctypes.byref(overlapped),
    ):
        error = ctypes.get_last_error()
        if error == 33:  # ERROR_LOCK_VIOLATION
            raise BlockingIOError("A running Studio process holds this runtime lease")
        raise ctypes.WinError(error)
