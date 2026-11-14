"""Local, account-restricted cleanup pipe with OS-authenticated process endpoints."""

from __future__ import annotations

import ctypes
import json
import struct
import threading
from collections.abc import Callable
from ctypes import wintypes as wt
from typing import Any
from uuid import UUID

from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_uninstall_native import _function, _require

_LIMIT = 4 * 1024 * 1024


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", wt.DWORD),
        ("offset_high", wt.DWORD),
        ("event", wt.HANDLE),
    ]


def pipe_name(identity: str) -> str:
    """Accept only our random local endpoint namespace, never arbitrary pipe paths."""
    return rf"\\.\pipe\EvidenceForge.Uninstall.{UUID(identity).hex}"


class CleanupPipe:
    """Bounded frames with independent overlapped operations in each direction."""

    def __init__(self, handle: int) -> None:
        self.handle = handle
        self.lock = threading.Lock()
        self.condition = threading.Condition()
        self.active = 0
        self.closing = False

    def _io(
        self,
        start: Callable[[int, _Overlapped, wt.DWORD], int],
        *,
        timeout_ms: int = 0xFFFFFFFF,
        accept_connected: bool = False,
    ) -> int:
        """Keep each event/buffer alive until completion, including cancellation."""
        event = _function(
            "kernel32", "CreateEventW", wt.HANDLE, [wt.LPVOID, wt.BOOL, wt.BOOL, wt.LPCWSTR]
        )(None, True, False, None)
        _require(event)
        operation = _Overlapped(event=event)
        transferred = wt.DWORD()
        registered = False
        try:
            with self.condition:
                if self.closing or not self.handle:
                    raise BrokenPipeError("Uninstall channel closed")
                handle = self.handle
                self.active += 1
                registered = True
                # Close cannot cancel before this operation has been submitted.
                success = start(handle, operation, transferred)
                error = ctypes.get_last_error() if not success else 0
            if accept_connected and error == 535:  # ERROR_PIPE_CONNECTED
                return 0
            if not success:
                if error != 997:  # ERROR_IO_PENDING
                    raise ctypes.WinError(error)
                wait = _function("kernel32", "WaitForSingleObject", wt.DWORD, [wt.HANDLE, wt.DWORD])
                result = wait(event, timeout_ms)
                if result != 0:
                    _function(
                        "kernel32", "CancelIoEx", wt.BOOL, [wt.HANDLE, ctypes.POINTER(_Overlapped)]
                    )(handle, ctypes.byref(operation))
                    # CancelIoEx requests cancellation; it does not complete it.
                    wait(event, 0xFFFFFFFF)
                    raise TimeoutError("Uninstall channel operation did not finish")
            _require(
                _function(
                    "kernel32",
                    "GetOverlappedResult",
                    wt.BOOL,
                    [wt.HANDLE, ctypes.POINTER(_Overlapped), ctypes.POINTER(wt.DWORD), wt.BOOL],
                )(handle, ctypes.byref(operation), ctypes.byref(transferred), False)
            )
            return transferred.value
        finally:
            _function("kernel32", "CloseHandle", wt.BOOL, [wt.HANDLE])(event)
            if registered:
                with self.condition:
                    self.active -= 1
                    self.condition.notify_all()

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
            )(pipe_name(identity), 0x40080003, 0x8, 1, 65536, 65536, 0, ctypes.byref(security))
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
        )(name, 0xC0000000, 0, None, 3, 0x40000000, None)
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
        connect = _function(
            "kernel32", "ConnectNamedPipe", wt.BOOL, [wt.HANDLE, ctypes.POINTER(_Overlapped)]
        )
        self._io(
            lambda handle, operation, count: connect(handle, ctypes.byref(operation)),
            timeout_ms=15000,
            accept_connected=True,
        )

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
                written = self._io(
                    lambda handle, operation, count, frame=frame: write(
                        handle, frame, len(frame), ctypes.byref(count), ctypes.byref(operation)
                    ),
                    timeout_ms=10000,
                )
                if not written:
                    raise BrokenPipeError("Uninstall channel closed")
                frame = frame[written:]

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
            count = self._io(
                lambda handle, operation, count, buffer=buffer: read(
                    handle, buffer, len(buffer), ctypes.byref(count), ctypes.byref(operation)
                )
            )
            if not count:
                raise BrokenPipeError("Uninstall channel closed")
            content.extend(buffer.raw[:count])
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
        """Cancel pending I/O and drain it before releasing the owned handle."""
        with self.condition:
            if self.closing:
                while self.handle:
                    self.condition.wait()
                return
            self.closing = True
            if self.handle:
                _function("kernel32", "CancelIoEx", wt.BOOL, [wt.HANDLE, wt.LPVOID])(
                    self.handle, None
                )
                while self.active:
                    self.condition.wait()
                _function("kernel32", "CloseHandle", wt.BOOL, [wt.HANDLE])(self.handle)
                self.handle = 0
            self.condition.notify_all()
