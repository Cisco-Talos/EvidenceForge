"""Local, account-restricted cleanup pipe with OS-authenticated process endpoints."""

from __future__ import annotations

import ctypes
import json
import struct
import threading
from ctypes import wintypes as wt
from typing import Any
from uuid import UUID

from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_uninstall_native import _function, _require

_LIMIT = 4 * 1024 * 1024


def pipe_name(identity: str) -> str:
    """Accept only our random local endpoint namespace, never arbitrary pipe paths."""
    return rf"\\.\pipe\EvidenceForge.Uninstall.{UUID(identity).hex}"


class CleanupPipe:
    """Bounded JSON frames on a synchronous local pipe, used off the UI thread."""

    def __init__(self, handle: int) -> None:
        self.handle = handle
        self.lock = threading.Lock()

    @classmethod
    def server(cls, identity: str, account: str) -> CleanupPipe:
        """Grant this ephemeral channel only to the account, admins and SYSTEM."""
        from evidenceforge.utils.windows_filesystem import current_user_sid

        class Security(ctypes.Structure):
            _fields_ = [("length", wt.DWORD), ("descriptor", wt.LPVOID), ("inherit", wt.BOOL)]

        # SIDs come from process tokens, not a username or environment override.
        sids = {account, current_user_sid(), "S-1-5-18", "S-1-5-32-544"}
        descriptor = wt.LPVOID()
        _require(
            _function(
                "advapi32",
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                wt.BOOL,
                [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(wt.LPVOID), wt.LPVOID],
            )(
                "D:P" + "".join(f"(A;;GA;;;{sid})" for sid in sorted(sids)),
                1,
                ctypes.byref(descriptor),
                None,
            )
        )
        try:
            security = Security(ctypes.sizeof(Security), descriptor, False)
            handle = _function(
                "kernel32",
                "CreateNamedPipeW",
                wt.HANDLE,
                [
                    wt.LPCWSTR,
                    wt.DWORD,
                    wt.DWORD,
                    wt.DWORD,
                    wt.DWORD,
                    wt.DWORD,
                    wt.DWORD,
                    ctypes.POINTER(Security),
                ],
            )(pipe_name(identity), 0x80003, 0x8, 1, 65536, 65536, 0, ctypes.byref(security))
            if handle == wt.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            return cls(handle)
        finally:
            _function("kernel32", "LocalFree", wt.LPVOID, [wt.LPVOID])(descriptor)

    @classmethod
    def client(cls, identity: str, server_pid: int) -> CleanupPipe:
        """Connect to the exact controller process, without file-based rendezvous."""
        name = pipe_name(identity)
        _require(
            _function("kernel32", "WaitNamedPipeW", wt.BOOL, [wt.LPCWSTR, wt.DWORD])(name, 10000)
        )
        handle = _function(
            "kernel32",
            "CreateFileW",
            wt.HANDLE,
            [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE],
        )(name, 0xC0000000, 0, None, 3, 0, None)
        if handle == wt.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        result = cls(handle)
        try:
            if result.peer_pid(server=True) != server_pid:
                raise StudioStateError("Uninstall controller process changed")
            return result
        except BaseException:
            result.close()
            raise

    def accept(self) -> None:
        """Accept one local connection; the caller must authenticate its PID."""
        connected = _function("kernel32", "ConnectNamedPipe", wt.BOOL, [wt.HANDLE, wt.LPVOID])(
            self.handle, None
        )
        if not connected and ctypes.get_last_error() != 535:  # ERROR_PIPE_CONNECTED
            raise ctypes.WinError(ctypes.get_last_error())

    def peer_pid(self, *, server: bool = False) -> int:
        """Read endpoint identity from the kernel, not from an incoming JSON claim."""
        pid = wt.ULONG()
        _require(
            _function(
                "kernel32",
                "GetNamedPipeServerProcessId" if server else "GetNamedPipeClientProcessId",
                wt.BOOL,
                [wt.HANDLE, ctypes.POINTER(wt.ULONG)],
            )(self.handle, ctypes.byref(pid))
        )
        return pid.value

    def send(self, value: dict[str, Any]) -> None:
        """Serialize a bounded complete frame under one writer lock."""
        payload = json.dumps(value, ensure_ascii=False).encode()
        if len(payload) > _LIMIT:
            raise StudioStateError("Uninstall review exceeds the channel limit; no cleanup started")
        frame = struct.pack("<I", len(payload)) + payload
        write = _function(
            "kernel32",
            "WriteFile",
            wt.BOOL,
            [wt.HANDLE, wt.LPCVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID],
        )
        with self.lock:
            while frame:
                written = wt.DWORD()
                _require(write(self.handle, frame, len(frame), ctypes.byref(written), None))
                if not written.value:
                    raise BrokenPipeError("Uninstall channel closed")
                frame = frame[written.value :]

    def _read(self, size: int) -> bytes:
        content = bytearray()
        read = _function(
            "kernel32",
            "ReadFile",
            wt.BOOL,
            [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID],
        )
        while len(content) < size:
            buffer = ctypes.create_string_buffer(min(size - len(content), 65536))
            count = wt.DWORD()
            _require(read(self.handle, buffer, len(buffer), ctypes.byref(count), None))
            if not count.value:
                raise BrokenPipeError("Uninstall channel closed")
            content.extend(buffer.raw[: count.value])
        return bytes(content)

    def receive(self) -> dict[str, Any]:
        """Reject oversized/non-object frames before processing a cleanup request."""
        size = struct.unpack("<I", self._read(4))[0]
        if not 0 < size <= _LIMIT:
            raise StudioStateError("Invalid uninstall channel frame")
        value = json.loads(self._read(size))
        if not isinstance(value, dict):
            raise StudioStateError("Invalid uninstall channel document")
        return value

    def close(self) -> None:
        """Release the one owned channel handle."""
        if self.handle:
            _function("kernel32", "CloseHandle", wt.BOOL, [wt.HANDLE])(self.handle)
            self.handle = 0
