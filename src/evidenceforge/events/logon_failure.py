# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Windows failed-logon condition, before source projection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WindowsLogonFailure:
    """One generic logon failure with its specific account-state substatus."""

    status: str
    substatus: str
    resource_reason: str

    @classmethod
    def for_account_state(cls, *, known: bool, disabled: bool) -> WindowsLogonFailure:
        """Keep the resource reason attached to Status, rather than SubStatus."""
        if disabled:
            substatus = "0xc0000072"
        elif not known:
            substatus = "0xc0000064"
        else:
            substatus = "0xc000006a"
        # STATUS_LOGON_FAILURE uses the generic unknown-user/bad-password text;
        # SubStatus supplies the more specific failure, including disabled state.
        return cls(status="0xc000006d", substatus=substatus, resource_reason="%%2313")
