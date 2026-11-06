# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""SMB result certification excludes unknown, failed and truncated helpers."""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.generation.actions.smb_activity import SmbActivityActionBundle
from tests.unit.test_process_execution_state import _START, _process


@pytest.mark.parametrize(
    "kind", ["failed", "mixed", "empty", "too_early", "session_end", "linux", "windows"]
)
def test_smb_helper_nominal_result_requires_complete_natural_mac_success(kind: str) -> None:
    state, process = _process()
    completed = _START + timedelta(seconds=2)
    terminal = completed + timedelta(seconds=1)
    operations = ({"outcome": "success"},)
    platform = {"linux": "Ubuntu 24.04", "windows": "Windows 11"}.get(kind, "macOS 27")
    if kind == "failed":
        operations = ({"outcome": "access_denied"},)
    elif kind == "mixed":
        operations = ({"outcome": "success"}, {"outcome": "access_denied"})
    elif kind == "empty":
        operations = ()
    elif kind == "too_early":
        terminal = completed
    elif kind == "session_end":
        state.get_session_end_time = lambda _luid: terminal
    owner = SimpleNamespace(
        executor=SimpleNamespace(state_manager=state),
        _endpoint_platform=SmbActivityActionBundle._endpoint_platform,
    )
    assert (
        SmbActivityActionBundle._completed_smb_client_exit(
            owner,
            SimpleNamespace(hostname=process.hostname, os=platform),
            process.pid,
            completed,
            terminal,
            operations,
        )
        is None
    )
