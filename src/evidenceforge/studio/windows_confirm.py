"""An icon-free native Yes/Cancel confirmation, with Cancel as the default."""

from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
from pathlib import Path

from evidenceforge.studio.windows_uninstall_native import _function, _require


class _ActivationContext(ctypes.Structure):
    _fields_ = [
        ("size", wt.ULONG),
        ("flags", wt.DWORD),
        ("source", wt.LPCWSTR),
        ("architecture", wt.USHORT),
        ("language", wt.WORD),
        ("directory", wt.LPCWSTR),
        ("resource", wt.LPCWSTR),
        ("application", wt.LPCWSTR),
        ("module", wt.HMODULE),
    ]


class _TaskDialog(ctypes.Structure):
    # commctrl.h puts the task-dialog declarations inside pshpack1.h.
    _pack_ = 1
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("owner", wt.HWND),
        ("instance", wt.HINSTANCE),
        ("flags", ctypes.c_uint32),
        ("buttons", ctypes.c_uint32),
        ("title", wt.LPCWSTR),
        ("icon", wt.HICON),
        ("instruction", wt.LPCWSTR),
        ("content", wt.LPCWSTR),
        ("button_count", ctypes.c_uint32),
        ("custom_buttons", ctypes.c_void_p),
        ("default_button", ctypes.c_int32),
        ("radio_count", ctypes.c_uint32),
        ("radios", ctypes.c_void_p),
        ("default_radio", ctypes.c_int32),
        ("verification", wt.LPCWSTR),
        ("expanded", wt.LPCWSTR),
        ("expanded_control", wt.LPCWSTR),
        ("collapsed_control", wt.LPCWSTR),
        ("footer_icon", wt.HICON),
        ("footer", wt.LPCWSTR),
        ("callback", ctypes.c_void_p),
        ("callback_data", ctypes.c_ssize_t),
        ("width", ctypes.c_uint32),
    ]


def confirm_content(text: str, owner: int) -> bool:
    """Show the selected categories without an error icon; Escape/close cancel."""
    context = _ActivationContext()
    context.size = ctypes.sizeof(context)
    context.source = str(Path(__file__).with_name("windows-controls.manifest"))
    handle = _function(
        "kernel32", "CreateActCtxW", wt.HANDLE, [ctypes.POINTER(_ActivationContext)]
    )(ctypes.byref(context))
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    cookie = ctypes.c_size_t()
    activated = False
    try:
        _require(
            _function(
                "kernel32", "ActivateActCtx", wt.BOOL, [wt.HANDLE, ctypes.POINTER(ctypes.c_size_t)]
            )(handle, ctypes.byref(cookie))
        )
        activated = True
        question, _separator, content = text.partition("\n\n")
        config = _TaskDialog()
        config.size = ctypes.sizeof(config)
        config.owner = owner
        config.flags = 0x1000  # TDF_POSITION_RELATIVE_TO_WINDOW
        config.buttons = 0xA  # TDCBF_YES_BUTTON | TDCBF_CANCEL_BUTTON
        config.default_button = 2  # IDCANCEL
        config.title = "Uninstall EvidenceForge Studio"
        config.instruction = question
        config.content = content
        answer = ctypes.c_int()
        result = _function(
            "comctl32",
            "TaskDialogIndirect",
            ctypes.c_int32,
            [
                ctypes.POINTER(_TaskDialog),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
        )(ctypes.byref(config), ctypes.byref(answer), None, None)
        if result < 0:
            raise OSError(
                f"Windows could not display the cleanup confirmation (HRESULT {result:#x})"
            )
        return answer.value == 6  # IDYES
    finally:
        if activated:
            _require(
                _function("kernel32", "DeactivateActCtx", wt.BOOL, [wt.DWORD, ctypes.c_size_t])(
                    0, cookie.value
                )
            )
        _function("kernel32", "ReleaseActCtx", None, [wt.HANDLE])(handle)
