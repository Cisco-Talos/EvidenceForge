# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native failure reason describes main status; substatus preserves account state."""

from types import SimpleNamespace

import pytest

from evidenceforge.events.logon_failure import WindowsLogonFailure
from evidenceforge.generation.emitters.ecar import _ecar_failed_logon_reason


@pytest.mark.parametrize(
    "known,disabled,substatus,normalized",
    [
        (True, False, "0xc000006a", "bad_password"),
        (False, False, "0xc0000064", "unknown_user"),
        (True, True, "0xc0000072", "account_disabled"),
    ],
)
def test_failure_condition_preserves_native_and_normalized_semantics(
    known: bool, disabled: bool, substatus: str, normalized: str
) -> None:
    condition = WindowsLogonFailure.for_account_state(known=known, disabled=disabled)
    assert condition.status == "0xc000006d"
    assert condition.substatus == substatus
    assert condition.resource_reason == "%%2313"
    auth = SimpleNamespace(
        failure_status=condition.status,
        failure_substatus=condition.substatus,
        failure_reason=condition.resource_reason,
    )
    assert _ecar_failed_logon_reason(auth, "windows") == normalized


def test_native_locked_resource_is_not_normalized_as_disabled() -> None:
    assert (
        _ecar_failed_logon_reason(
            SimpleNamespace(failure_substatus="0x0", failure_reason="%%2307"), "windows"
        )
        == "account_locked"
    )
    assert (
        _ecar_failed_logon_reason(
            SimpleNamespace(failure_substatus="0x0", failure_reason="%%2313"), "windows"
        )
        == "authentication_failure"
    )
