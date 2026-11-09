# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Caller recovery retains the Mac receiver without changing existing source actions."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverProcesses,
    MacosSshReceiverStartup,
)
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _get_rng
from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture
from tests.unit.test_ssh_deferred_production import _START


@pytest.mark.parametrize("phase", range(11))
def test_mac_caller_retains_startup_after_each_lost_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: int
) -> None:
    fixture = _mac_fixture(tmp_path)
    original = MacosSshReceiverStartup.advance
    failed = False

    def inject(startup: MacosSshReceiverStartup) -> MacosSshReceiverProcesses | None:
        nonlocal failed
        prior = startup.completed_phases
        result = original(startup)
        if not failed and prior == phase:
            failed = True
            raise OSError("injected receiver phase lost return")
        return result

    monkeypatch.setattr(MacosSshReceiverStartup, "advance", inject)
    request = replace(fixture.request(), emit_session_close=True, defer_session_close=True)
    with pytest.raises(OSError, match="phase lost return"):
        SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    assert failed and fixture.generator.ssh_close_journal_census().exact_pending == 1
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(minutes=5))
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    rows, flows = fixture.close_and_read()
    assert len(flows) == 1
    sessions = [row for row in rows if row.get("object") == "USER_SESSION"]
    assert [row["action"] for row in sessions] == ["LOGIN", "LOGOUT"]


@pytest.mark.parametrize("damage", ["account", "parent", "closure", "source", "scp", "sftp"])
def test_mac_caller_preflight_fails_before_source_creation_or_rng_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    fixture = _mac_fixture(tmp_path)
    request = replace(fixture.request(), emit_session_close=True)
    if damage == "account":
        fixture.generator.identity_directory.macos_accounts.pop(("analyst", "db-01"))
    elif damage == "parent":
        fixture.state.get_process(fixture.target.hostname, 1).image = "/usr/sbin/sshd"
    elif damage == "closure":
        request = replace(request, emit_session_close=False)
    elif damage in {"scp", "sftp"}:
        request = replace(request, source=damage)
    else:
        request = replace(request, source_pid=12345)
    before = fixture.state.materialization_digest()
    rng = _get_rng().getstate()

    def forbidden(**kwargs: object) -> None:
        pytest.fail("preflight reached source process creation")

    monkeypatch.setattr(fixture.generator, "ensure_ssh_client_process", forbidden)
    with pytest.raises(StateError):
        SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    assert fixture.state.materialization_digest() == before
    assert _get_rng().getstate() == rng
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    fixture.close_and_read()
