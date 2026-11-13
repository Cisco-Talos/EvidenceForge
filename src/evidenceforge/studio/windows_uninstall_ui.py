"""Small native Windows cleanup dialog, independent of WebView, helpers or saved state."""

from __future__ import annotations

import ctypes
from ctypes import wintypes as wt

from pydantic import ValidationError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.windows_uninstall import LABELS, Category, CleanupPlan, describe, execute
from evidenceforge.studio.windows_uninstall_native import _function, _require, message


def choose(plan: CleanupPlan) -> int:
    """Offer three unchecked choices, exact paths, cancellation and final confirmation."""
    window_proc = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

    class WindowClass(ctypes.Structure):
        _fields_ = [
            ("style", wt.UINT),
            ("procedure", window_proc),
            ("class_extra", ctypes.c_int),
            ("window_extra", ctypes.c_int),
            ("instance", wt.HINSTANCE),
            ("icon", wt.HICON),
            ("cursor", wt.HANDLE),
            ("background", wt.HBRUSH),
            ("menu", wt.LPCWSTR),
            ("name", wt.LPCWSTR),
        ]

    send = _function(
        "user32", "SendMessageW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    )
    destroy = _function("user32", "DestroyWindow", wt.BOOL, [wt.HWND])
    quit_message = _function("user32", "PostQuitMessage", None, [ctypes.c_int])
    default = _function(
        "user32", "DefWindowProcW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    )
    set_text = _function("user32", "SetWindowTextW", wt.BOOL, [wt.HWND, wt.LPCWSTR])
    result = 1
    checks: dict[Category, int] = {}
    inventory = 0

    def selected() -> set[Category]:
        return {category for category, handle in checks.items() if send(handle, 0xF0, 0, 0) == 1}

    @window_proc
    def procedure(window: int, event: int, word: int, parameter: int) -> int:
        nonlocal result
        try:
            if event == 0x111:  # WM_COMMAND
                control = word & 0xFFFF
                if control in (101, 102, 103):
                    set_text(inventory, describe(plan, selected()))
                    return 0
                if control == 201:
                    choices = selected()
                    if (
                        choices
                        and message(
                            "Permanently delete the selected data now? This cannot be undone.\n\n"
                            "The full list is in the review window. Only the checked categories "
                            "for the displayed account will be removed.",
                            0x134,
                            window,
                        )
                        != 6
                    ):
                        return 0
                    execute(plan, choices)
                    result = 0
                    destroy(window)
                    return 0
                if control == 202:
                    destroy(window)
                    return 0
            if event == 0x10:  # WM_CLOSE is always cancellation, never approval.
                destroy(window)
                return 0
            if event == 2:  # WM_DESTROY
                quit_message(result)
                return 0
        except (OSError, EvidenceForgeError, ValidationError, ValueError) as error:
            message(
                f"Cleanup stopped: {error}\n\n"
                "The application has not been uninstalled. Close any Studio/background jobs "
                "and reopen uninstall. If deletion had already started, some selected files "
                "may be gone; do not remove unlisted files manually.",
                0x10,
                window,
            )
        return default(window, event, word, parameter)

    # Native controls follow system DPI/font, and require no Python GUI dependencies.
    _function("user32", "SetProcessDpiAwarenessContext", wt.BOOL, [wt.HANDLE])(wt.HANDLE(-4))
    dpi = _function("user32", "GetDpiForSystem", wt.UINT, [])() / 96

    def scale(value: int) -> int:
        return round(value * dpi)

    instance = _function("kernel32", "GetModuleHandleW", wt.HMODULE, [wt.LPCWSTR])(None)
    name = "EvidenceForge.Uninstall.Review"
    registration = WindowClass()
    registration.procedure = procedure
    registration.instance = instance
    registration.background = 6  # COLOR_WINDOW + 1
    registration.name = name
    _require(
        _function("user32", "RegisterClassW", wt.ATOM, [ctypes.POINTER(WindowClass)])(
            ctypes.byref(registration)
        )
    )
    create = _function(
        "user32",
        "CreateWindowExW",
        wt.HWND,
        [
            wt.DWORD,
            wt.LPCWSTR,
            wt.LPCWSTR,
            wt.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wt.HWND,
            wt.HMENU,
            wt.HINSTANCE,
            wt.LPVOID,
        ],
    )
    window = create(
        0,
        name,
        "Uninstall EvidenceForge Studio — optional data removal",
        0x10CA0000,
        60,
        60,
        scale(850),
        scale(640),
        None,
        None,
        instance,
        None,
    )
    _require(window)
    font = _function("gdi32", "GetStockObject", wt.HANDLE, [ctypes.c_int])(17)

    def control(
        kind: str,
        text: str,
        style: int,
        x: int,
        y: int,
        width: int,
        height: int,
        identifier: int = 0,
    ) -> int:
        handle = create(
            0,
            kind,
            text,
            0x50000000 | style,
            scale(x),
            scale(y),
            scale(width),
            scale(height),
            window,
            wt.HMENU(identifier),
            instance,
            None,
        )
        _require(handle)
        send(handle, 0x30, font, 1)  # WM_SETFONT
        return handle

    control(
        "STATIC",
        "Choose what else to remove. Leave everything unchecked to keep your data.",
        0,
        18,
        16,
        795,
        25,
    )
    for index, (category, label) in enumerate(LABELS.items()):
        checks[category] = control(
            "BUTTON", label, 0x10003, 18, 47 + index * 29, 795, 25, 101 + index
        )
    inventory = control("EDIT", describe(plan, set()), 0xB018C4, 18, 145, 795, 380, 301)
    send(inventory, 0xC5, 0x7FFFFFFE, 0)  # EM_SETLIMITTEXT; the review must not truncate paths.
    set_text(inventory, describe(plan, set()))
    control("BUTTON", "Uninstall", 0x10001, 575, 548, 112, 32, 201)
    control("BUTTON", "Cancel", 0x10000, 701, 548, 112, 32, 202)
    get_message = _function(
        "user32", "GetMessageW", wt.BOOL, [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
    )
    translate = _function("user32", "TranslateMessage", wt.BOOL, [ctypes.POINTER(wt.MSG)])
    dispatch = _function("user32", "DispatchMessageW", ctypes.c_ssize_t, [ctypes.POINTER(wt.MSG)])
    dialog_message = _function(
        "user32", "IsDialogMessageW", wt.BOOL, [wt.HWND, ctypes.POINTER(wt.MSG)]
    )
    event = wt.MSG()
    while True:
        status = get_message(ctypes.byref(event), None, 0, 0)
        if status == -1:
            raise ctypes.WinError(ctypes.get_last_error())
        if status == 0:
            break
        if not dialog_message(window, ctypes.byref(event)):
            translate(ctypes.byref(event))
            dispatch(ctypes.byref(event))
    return result
