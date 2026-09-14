"""Native Windows operations for protected local NTFS storage.

This module is imported only by Windows branches. POSIX callers continue using
their existing descriptor-relative implementation. Returned descriptors own their
native handles and must be closed with os.close, just like ordinary binary files.
"""

from __future__ import annotations

import ctypes
import msvcrt
import os
import secrets
import stat
import tempfile
from ctypes import wintypes
from pathlib import Path, PureWindowsPath
from threading import RLock
from typing import Any

_READ_CONTROL = 0x00020000
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_FILE_READ_ATTRIBUTES = 0x80
_FILE_DIRECTORY_FILE = 0x1
_FILE_NON_DIRECTORY_FILE = 0x40
_FILE_SYNCHRONOUS_IO_NONALERT = 0x20
_FILE_DELETE_ON_CLOSE = 0x1000
_FILE_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_SHARE_READ_WRITE = 0x3
_FILE_SHARE_DELETE = 0x4
_FILE_OPEN = 1
_FILE_CREATE = 2
_FILE_OPEN_IF = 3
_FILE_OVERWRITE = 4
_FILE_OVERWRITE_IF = 5
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_SE_FILE_OBJECT = 1
_ERROR_NO_MORE_FILES = 18
_FILE_ATTRIBUTE_TAG_INFO = 9
_FILE_ID_BOTH_DIRECTORY_INFO = 10
_FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 11
_FILE_RENAME_INFO = 3
_FILE_DISPOSITION_INFO = 4
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


class _StandardInformation(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_int64),
        ("EndOfFile", ctypes.c_int64),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", wintypes.BYTE),
        ("Directory", wintypes.BYTE),
    ]


class _RenameInformation(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _Acl(ctypes.Structure):
    _fields_ = [
        ("AclRevision", wintypes.BYTE),
        ("Sbz1", wintypes.BYTE),
        ("AclSize", wintypes.WORD),
        ("AceCount", wintypes.WORD),
        ("Sbz2", wintypes.WORD),
    ]


class _AllowedAce(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


class _DirectoryInformation(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.DWORD),
        ("FileIndex", wintypes.DWORD),
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("EndOfFile", ctypes.c_int64),
        ("AllocationSize", ctypes.c_int64),
        ("FileAttributes", wintypes.DWORD),
        ("FileNameLength", wintypes.DWORD),
        ("EaSize", wintypes.DWORD),
        ("ShortNameLength", ctypes.c_byte),
        ("ShortName", wintypes.WCHAR * 12),
        ("FileId", ctypes.c_int64),
        ("FileName", wintypes.WCHAR * 1),
    ]


def _bind(library: Any, name: str, result: Any, arguments: list[Any]) -> Any:
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


_kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
_base = ctypes.WinDLL("kernelbase.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
_advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
_ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
_nt_create_file = _bind(
    _ntdll,
    "NtCreateFile",
    ctypes.c_int32,
    [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ],
)
_nt_error = _bind(_ntdll, "RtlNtStatusToDosError", wintypes.ULONG, [ctypes.c_int32])
_nt_set_information = _bind(
    _ntdll,
    "NtSetInformationFile",
    ctypes.c_int32,
    [
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    ],
)
_close_handle = _bind(_kernel, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
_get_info = _bind(
    _kernel,
    "GetFileInformationByHandleEx",
    wintypes.BOOL,
    [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD],
)
_set_info = _bind(
    _kernel,
    "SetFileInformationByHandle",
    wintypes.BOOL,
    [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD],
)
_flush = _bind(_kernel, "FlushFileBuffers", wintypes.BOOL, [wintypes.HANDLE])
_compare_handles = _bind(
    _base, "CompareObjectHandles", wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]
)
_local_free = _bind(_kernel, "LocalFree", wintypes.HLOCAL, [wintypes.HLOCAL])
_current_process = _bind(_kernel, "GetCurrentProcess", wintypes.HANDLE, [])
_open_token = _bind(
    _advapi,
    "OpenProcessToken",
    wintypes.BOOL,
    [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
)
_token_info = _bind(
    _advapi,
    "GetTokenInformation",
    wintypes.BOOL,
    [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ],
)
_sid_string = _bind(
    _advapi,
    "ConvertSidToStringSidW",
    wintypes.BOOL,
    [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)],
)
_convert_sd = _bind(
    _advapi,
    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
    wintypes.BOOL,
    [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ],
)
_get_security = _bind(
    _advapi,
    "GetSecurityInfo",
    wintypes.DWORD,
    [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ],
)
_get_ace = _bind(
    _advapi,
    "GetAce",
    wintypes.BOOL,
    [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)],
)
_drive_type = _bind(_kernel, "GetDriveTypeW", wintypes.UINT, [wintypes.LPCWSTR])
_volume_info = _bind(
    _kernel,
    "GetVolumeInformationByHandleW",
    wintypes.BOOL,
    [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ],
)


def _require(success: int) -> None:
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())


def _handle(descriptor: int) -> int:
    return msvcrt.get_osfhandle(descriptor)


def _sid(pointer: int | None) -> str:
    if pointer is None:
        raise PermissionError("Windows object has no owner SID")
    value = wintypes.LPWSTR()
    _require(_sid_string(pointer, ctypes.byref(value)))
    try:
        return str(value.value)
    finally:
        _local_free(ctypes.cast(value, wintypes.LPVOID))


def current_user_sid() -> str:
    """Read the real owner SID from the process token."""
    token = wintypes.HANDLE()
    _require(_open_token(_current_process(), 0x8, ctypes.byref(token)))
    try:
        size = wintypes.DWORD()
        _token_info(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        _require(_token_info(token, 1, buffer, size, ctypes.byref(size)))
        return _sid(ctypes.c_void_p.from_buffer(buffer).value)
    finally:
        _close_handle(token)


def _private_security_descriptor() -> wintypes.LPVOID:
    owner = current_user_sid()
    descriptor = wintypes.LPVOID()
    sddl = f"O:{owner}D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    _require(_convert_sd(sddl, 1, ctypes.byref(descriptor), None))
    return descriptor


def require_private(descriptor: int, *, ancestry: bool = False) -> None:
    """Validate native ownership and DACL mutation rights on an opened object."""
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    security = wintypes.LPVOID()
    result = _get_security(
        _handle(descriptor),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security),
    )
    if result:
        raise ctypes.WinError(result)
    try:
        user = current_user_sid()
        trusted = {
            user,
            "S-1-5-18",
            "S-1-5-32-544",
            # Windows Modules Installer owns protected OS directories, including
            # the system volume root on supported Windows installations.
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        }
        if _sid(owner.value) not in (trusted if ancestry else {user}):
            raise PermissionError(
                f"Windows protected storage has an unexpected owner: {_sid(owner.value)}"
            )
        if not dacl.value:
            raise PermissionError("Windows protected storage has no restrictive DACL")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        # An ancestor may allow creating new children, but not replacing existing
        # children or changing its security. Private leaves permit no outside access.
        mutation = 0x500D0040 if ancestry else 0xFFFFFFFF
        for index in range(acl.AceCount):
            pointer = wintypes.LPVOID()
            _require(_get_ace(dacl, index, ctypes.byref(pointer)))
            ace = ctypes.cast(pointer, ctypes.POINTER(_AllowedAce)).contents
            if ace.AceFlags & 0x8:  # INHERIT_ONLY_ACE does not apply to this object.
                continue
            if ace.AceType == 1:  # Deny ACEs cannot grant additional access.
                continue
            if ace.AceType != 0:
                raise PermissionError("Windows protected storage has an unsupported ACL entry")
            principal = _sid(pointer.value + _AllowedAce.SidStart.offset)
            if principal not in trusted | {"S-1-3-4"} and ace.Mask & mutation:
                raise PermissionError(
                    "Windows protected storage allows another principal to access it: "
                    f"SID={principal}, mask=0x{ace.Mask:08x}, ancestry={ancestry}"
                )
    finally:
        _local_free(security)


def _component(name: str) -> None:
    if not name or name in {".", ".."} or any(character in name for character in "\\/:\x00"):
        raise ValueError("Windows protected storage requires one relative path component")
    if (
        name.endswith((".", " "))
        or PureWindowsPath(name).is_reserved()
        or any(character in name for character in '<>"|?*')
        or any(ord(character) < 32 for character in name)
    ):
        raise ValueError("Windows protected storage rejects ambiguous or reserved names")


def _open_native(
    name: str,
    *,
    root: int | None,
    flags: int,
    directory: bool | None,
    private: bool = False,
    extra_access: int = 0,
    temporary: bool = False,
) -> int:
    supported_flags = (
        os.O_RDONLY
        | os.O_WRONLY
        | os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_TRUNC
        | os.O_BINARY
        | os.O_NOINHERIT
    )
    if flags & ~supported_flags:
        raise ValueError("Unsupported native Windows protected-file flags")
    if root is not None:
        _component(name)
    buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UnicodeString(
        encoded_length, encoded_length + 2, ctypes.cast(buffer, wintypes.LPWSTR)
    )
    security = _private_security_descriptor() if private else None
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), root, ctypes.pointer(unicode_name), 0x40, security, None
    )
    access = _READ_CONTROL | _SYNCHRONIZE | _FILE_READ_ATTRIBUTES | extra_access
    if temporary:
        access |= _DELETE
    if directory:
        access |= 0x21  # FILE_LIST_DIRECTORY | FILE_TRAVERSE
    else:
        access |= 0x2 if flags & os.O_WRONLY else 0x1
        if flags & os.O_RDWR:
            access |= 0x3
    disposition = _FILE_OPEN
    if flags & os.O_CREAT:
        disposition = _FILE_CREATE if flags & os.O_EXCL else _FILE_OPEN_IF
    if flags & os.O_TRUNC:
        disposition = _FILE_OVERWRITE_IF if flags & os.O_CREAT else _FILE_OVERWRITE
    options = _FILE_OPEN_REPARSE_POINT | _FILE_SYNCHRONOUS_IO_NONALERT
    if temporary:
        options |= _FILE_DELETE_ON_CLOSE
    if directory is not None:
        options |= _FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE
    handle = wintypes.HANDLE()
    status = _IoStatusBlock()
    try:
        result = _nt_create_file(
            ctypes.byref(handle),
            access,
            ctypes.byref(attributes),
            ctypes.byref(status),
            None,
            0x80,
            _FILE_SHARE_READ_WRITE | (0 if directory else _FILE_SHARE_DELETE),
            disposition,
            options,
            None,
            0,
        )
    finally:
        if security is not None:
            _local_free(security)
    if result < 0:
        raise ctypes.WinError(_nt_error(result))
    try:
        tags = (wintypes.DWORD * 2)()
        _require(_get_info(handle, _FILE_ATTRIBUTE_TAG_INFO, tags, ctypes.sizeof(tags)))
        if tags[0] & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError("Windows protected storage cannot traverse a reparse point")
        descriptor = msvcrt.open_osfhandle(
            handle.value, (flags & (os.O_RDWR | os.O_WRONLY)) | os.O_BINARY | os.O_NOINHERIT
        )
    except BaseException:
        _close_handle(handle)
        raise
    return descriptor


def open_directory(path: Path, *, create: bool = False) -> int:
    """Pin a local absolute directory through no-follow handle-relative opens."""
    absolute = Path(os.path.abspath(path))
    if len(absolute.drive) != 2 or absolute.drive[1] != ":":
        raise OSError("Native Windows protected storage requires a local NTFS drive")
    if _drive_type(absolute.anchor) != 3:  # DRIVE_FIXED; mapped shares are DRIVE_REMOTE.
        raise OSError("Native Windows protected storage requires a fixed local NTFS drive")
    descriptor = _open_native(
        "\\??\\" + absolute.anchor, root=None, flags=os.O_RDONLY, directory=True
    )
    try:
        filesystem = ctypes.create_unicode_buffer(32)
        _require(
            _volume_info(
                _handle(descriptor), None, 0, None, None, None, filesystem, len(filesystem)
            )
        )
        if filesystem.value.upper() != "NTFS":
            raise OSError("Native Windows protected storage requires an NTFS volume")
        for component in absolute.parts[1:]:
            next_descriptor = _open_native(
                component,
                root=_handle(descriptor),
                flags=os.O_CREAT if create else os.O_RDONLY,
                directory=True,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_child(
    parent: int, name: str, flags: int, mode: int = 0o600, *, directory: bool = False
) -> int:
    """Open or exclusively create a child while retaining its parent identity."""
    return _open_native(
        name,
        root=_handle(parent),
        flags=flags,
        directory=directory,
        private=bool(flags & os.O_CREAT and mode in {0o600, 0o700}),
    )


def mkdir_child(parent: int, name: str, mode: int = 0o700) -> None:
    """Exclusively create a directory with a private native ACL when requested."""
    descriptor = open_child(parent, name, os.O_CREAT | os.O_EXCL, mode, directory=True)
    os.close(descriptor)


def child_stat(parent: int, name: str, *, directory: bool | None = False) -> os.stat_result:
    """Inspect an opened child rather than a pathname susceptible to substitution."""
    descriptor = _open_native(name, root=_handle(parent), flags=os.O_RDONLY, directory=directory)
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def flush_file(descriptor: int) -> None:
    """Flush file data; Windows has no POSIX directory-sync durability contract."""
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        _require(_flush(_handle(descriptor)))


def same_open_file(first: int, second: int) -> bool:
    """Compare kernel file objects, distinguishing duplicate from reopened handles."""
    return bool(_compare_handles(_handle(first), _handle(second)))


def list_directory(descriptor: int) -> list[str]:
    """Enumerate a pinned directory through its native handle."""
    buffer = ctypes.create_string_buffer(65536)
    names: list[str] = []
    information = _FILE_ID_BOTH_DIRECTORY_RESTART_INFO
    while True:
        if not _get_info(_handle(descriptor), information, buffer, len(buffer)):
            error = ctypes.get_last_error()
            if error == _ERROR_NO_MORE_FILES:
                return names
            raise ctypes.WinError(error)
        information = _FILE_ID_BOTH_DIRECTORY_INFO
        offset = 0
        while True:
            entry = _DirectoryInformation.from_buffer(buffer, offset)
            start = offset + _DirectoryInformation.FileName.offset
            name = bytes(buffer[start : start + entry.FileNameLength]).decode("utf-16-le")
            if name not in {".", ".."}:
                names.append(name)
            if not entry.NextEntryOffset:
                break
            offset += entry.NextEntryOffset


def remove_child(
    parent: int,
    name: str,
    *,
    directory: bool = False,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Delete the opened child through its handle, rejecting reparse points."""
    descriptor = _open_native(
        name, root=_handle(parent), flags=os.O_RDONLY, directory=directory, extra_access=_DELETE
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            expected_identity is not None
            and (int(metadata.st_dev), int(metadata.st_ino)) != expected_identity
        ):
            raise OSError("Windows file identity changed before deletion")
        delete = wintypes.BYTE(1)
        _require(
            _set_info(
                _handle(descriptor),
                _FILE_DISPOSITION_INFO,
                ctypes.byref(delete),
                ctypes.sizeof(delete),
            )
        )
    finally:
        os.close(descriptor)


def replace_child(
    source_parent: int,
    source: str,
    target_parent: int,
    target: str,
    *,
    replace: bool = True,
    directory: bool = False,
) -> None:
    """Atomically publish a file using retained source and destination directory handles."""
    _component(target)
    descriptor = _open_native(
        source,
        root=_handle(source_parent),
        flags=os.O_RDONLY,
        directory=directory,
        extra_access=_DELETE,
    )
    try:
        encoded = target.encode("utf-16-le")
        buffer = ctypes.create_string_buffer(ctypes.sizeof(_RenameInformation) + len(encoded))
        information = _RenameInformation.from_buffer(buffer)
        information.Flags = int(replace)
        information.RootDirectory = _handle(target_parent)
        information.FileNameLength = len(encoded)
        ctypes.memmove(
            ctypes.addressof(buffer) + _RenameInformation.FileName.offset, encoded, len(encoded)
        )
        # Use the native information class for RootDirectory-relative renames;
        # the Win32 wrapper rejects this form on the hosted Windows runner.
        status = _IoStatusBlock()
        result = _nt_set_information(
            _handle(descriptor), ctypes.byref(status), buffer, len(buffer), 10
        )
        if result < 0:
            raise ctypes.WinError(_nt_error(result))
    finally:
        os.close(descriptor)


def open_file(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open a regular binary file through a pinned, no-follow absolute parent."""
    absolute = Path(os.path.abspath(path))
    parent = open_directory(absolute.parent)
    try:
        return open_child(parent, absolute.name, flags, mode)
    finally:
        os.close(parent)


def directory_entries(path: Path) -> list[tuple[str, os.stat_result]]:
    """Inventory children through one pinned directory without following reparse points."""
    parent = open_directory(path)
    try:
        return [
            (name, child_stat(parent, name, directory=None))
            for name in sorted(list_directory(parent))
        ]
    finally:
        os.close(parent)


def publish_new_directory(source: Path, target: Path) -> None:
    """Atomically rename a staged directory only if its sibling target is absent."""
    source = Path(os.path.abspath(source))
    target = Path(os.path.abspath(target))
    if source.parent != target.parent:
        raise ValueError("Windows staged directory publication requires sibling paths")
    parent = open_directory(source.parent)
    try:
        replace_child(parent, source.name, parent, target.name, replace=False, directory=True)
    finally:
        os.close(parent)


def temporary_descriptor() -> int:
    """Create private delete-on-close storage, retained by all duplicated handles.

    Windows keeps a private directory entry until the final handle closes. The
    kernel owns cleanup even after a process crash; callers never reopen its path.
    """
    parent = open_directory(Path(tempfile.gettempdir()))
    try:
        for _attempt in range(128):
            try:
                descriptor = _open_native(
                    f".eforge-private-{secrets.token_hex(16)}",
                    root=_handle(parent),
                    flags=os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    directory=False,
                    private=True,
                    temporary=True,
                )
                try:
                    delete = wintypes.BYTE(1)
                    _require(
                        _set_info(
                            _handle(descriptor),
                            _FILE_DISPOSITION_INFO,
                            ctypes.byref(delete),
                            ctypes.sizeof(delete),
                        )
                    )
                    return descriptor
                except BaseException:
                    os.close(descriptor)
                    raise
            except FileExistsError:
                continue
        raise FileExistsError("Unable to allocate private Windows temporary storage")
    finally:
        os.close(parent)


def require_temporary(descriptor: int) -> None:
    """Verify native delete-pending ownership, zero links, and the private ACL."""
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 0:
        raise PermissionError("Windows temporary storage is not one private regular file")
    information = _StandardInformation()
    _require(
        _get_info(_handle(descriptor), 1, ctypes.byref(information), ctypes.sizeof(information))
    )
    if not information.DeletePending or os.get_inheritable(descriptor):
        raise PermissionError("Windows temporary storage lost its delete-pending ownership")
    require_private(descriptor)


# These operations are used together for opaque Syslog-owned descriptors. Holding
# the same lock across save/read/restore preserves a shared file pointer even
# when another owner operation uses a duplicated handle. No pathname is reopened.
_position_lock = RLock()


def read(descriptor: int, count: int) -> bytes:
    """Read a native journal under the positioned-I/O coordination lock."""
    with _position_lock:
        return os.read(descriptor, count)


def write(descriptor: int, payload: bytes | memoryview) -> int:
    """Write a native journal under the positioned-I/O coordination lock."""
    with _position_lock:
        return os.write(descriptor, payload)


def lseek(descriptor: int, offset: int, whence: int = os.SEEK_SET) -> int:
    """Move the native journal pointer without racing a positioned read."""
    with _position_lock:
        return os.lseek(descriptor, offset, whence)


def pread(descriptor: int, count: int, offset: int) -> bytes:
    """Read an opaque journal without changing its shared owner file position.

    Callers must use this module's read/write/lseek operations for the same
    descriptor and its duplicates. Syslog's Windows boundary enforces that rule.
    """
    if count < 0 or offset < 0:
        raise ValueError("Windows positioned read requires nonnegative count and offset")
    with _position_lock:
        original = os.lseek(descriptor, 0, os.SEEK_CUR)
        try:
            os.lseek(descriptor, offset, os.SEEK_SET)
            return os.read(descriptor, count)
        finally:
            os.lseek(descriptor, original, os.SEEK_SET)


def mkdir_private(path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
    """Create a private directory with an explicit ACL, or validate an existing one."""
    absolute = Path(os.path.abspath(path))
    parent = open_directory(absolute.parent, create=parents)
    try:
        try:
            mkdir_child(parent, absolute.name)
        except FileExistsError:
            if not exist_ok:
                raise
        descriptor = open_child(parent, absolute.name, os.O_RDONLY, directory=True)
        try:
            require_private(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def read_private_file(path: Path) -> bytes:
    """Read protected recovery bytes from a no-follow, ACL-validated native handle."""
    descriptor = open_file(path, os.O_RDONLY)
    try:
        require_private(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def validate_future_file(path: Path) -> None:
    """Validate existing ancestry and a regular leaf without creating missing paths."""
    path = Path(os.path.abspath(path))
    ancestor = path.parent
    while True:
        try:
            descriptor = open_directory(ancestor)
            break
        except FileNotFoundError:
            ancestor = ancestor.parent
    try:
        if ancestor == path.parent:
            try:
                child_stat(descriptor, path.name)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)


def write_private_atomic(path: Path, content: bytes) -> None:
    """Publish fully flushed private bytes through one retained parent handle."""
    absolute = Path(os.path.abspath(path))
    parent = open_directory(absolute.parent, create=True)
    descriptor = None
    name = None
    identity = None
    try:
        for _attempt in range(128):
            candidate = f".{absolute.name}.{secrets.token_hex(16)}"
            try:
                descriptor = open_child(parent, candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                continue
            name = candidate
            metadata = os.fstat(descriptor)
            identity = (int(metadata.st_dev), int(metadata.st_ino))
            break
        else:
            raise FileExistsError("Unable to allocate private Windows publication storage")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Windows private publication made no progress")
            view = view[written:]
        flush_file(descriptor)
        os.close(descriptor)
        descriptor = None
        replace_child(parent, name, parent, absolute.name)
        name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if name is not None:
                try:
                    remove_child(parent, name, expected_identity=identity)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent)
