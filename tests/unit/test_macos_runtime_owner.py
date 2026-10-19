# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import pytest

from evidenceforge.generation.actions.process_support.policy import _runtime_artifact_owner_kind


@pytest.mark.parametrize(
    "platform,principal,expected",
    [
        ("macos", "root", "system"),
        ("macos", "alex", "user"),
        ("linux", "root", "system"),
        ("linux", "alex", "user"),
        ("windows", "SYSTEM", "system"),
        ("windows", "root", "user"),
    ],
)
def test_runtime_owner_preserves_platform_identity(
    platform: str, principal: str, expected: str
) -> None:
    assert _runtime_artifact_owner_kind(platform, principal, "") == expected
