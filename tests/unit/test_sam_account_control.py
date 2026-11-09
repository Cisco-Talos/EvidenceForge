# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SAM mask transitions own their native Windows resource messages."""

from datetime import UTC, datetime

import pytest

from evidenceforge.generation.actions.windows_audit import (
    AccountChangedRequest,
    sam_account_control_change_tokens,
)
from evidenceforge.models import System, User


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("0x15", "0x10", ("%%2048", "%%2050")),
        ("0x15", "0x211", ("%%2050", "%%2089")),
        ("0x0", "0x15", ("%%2080", "%%2082", "%%2084")),
        ("0x10", "0x11", ("%%2080",)),
        ("0x10", "0x10", ()),
        ("0X00000010", "0x0010", ()),
    ],
)
def test_sam_transition_uses_resource_messages_for_changed_bits(
    old: str, new: str, expected: tuple[str, ...]
) -> None:
    assert sam_account_control_change_tokens(old, new) == expected


@pytest.mark.parametrize(
    "value", ["-", "", "-1", "0x-1", "0x", "0xg", "0x100000000", "0x10 ", "16"]
)
def test_sam_transition_rejects_invalid_masks(value: str) -> None:
    with pytest.raises(ValueError, match="SAM account-control"):
        sam_account_control_change_tokens(value, "0x10")
    with pytest.raises(ValueError, match="SAM account-control"):
        sam_account_control_change_tokens("0x10", value)


def _request(**kwargs: str | None) -> AccountChangedRequest:
    return AccountChangedRequest(
        actor=User(
            username="admin",
            full_name="Admin",
            email="admin@example.test",
            department="IT",
            title="Admin",
            groups=[],
        ),
        system=System(hostname="dc", ip="10.0.0.1", os="Windows Server 2022", type="server"),
        time=datetime(2026, 11, 2, tzinfo=UTC),
        target_username="newuser",
        target_sid="S-1-5-21-1-2-3-1001",
        **kwargs,
    )


def test_account_change_derives_one_shared_control_text() -> None:
    request = _request(old_uac_value="0x15", new_uac_value="0x10")
    assert request.user_account_control == "\n\t\t\t%%2048\n\t\t\t%%2050"
    assert _request(old_uac_value="0x10", new_uac_value="0x10").user_account_control == "-"
    assert _request().old_uac_value is None
    assert _request().new_uac_value is None
    assert _request().user_account_control is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"old_uac_value": "0x15"},
        {"new_uac_value": "0x10"},
        {"old_uac_value": "0x15", "new_uac_value": "0x10", "user_account_control": "%%2081"},
    ],
)
def test_account_change_rejects_partial_or_contradictory_transition(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="SAM account-control"):
        _request(**kwargs)
