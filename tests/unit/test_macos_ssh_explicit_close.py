# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit Mac logout retains the exact SSH owner across publication and recovery."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture
from tests.unit.test_ssh_deferred_production import _START


@pytest.mark.parametrize("collection", ["all", "network", "none"])
def test_explicit_mac_close_uses_retained_owner(tmp_path: Path, collection: str) -> None:
    fixture = _mac_fixture(tmp_path)
    if collection != "all":
        fixture.generator.dispatcher.emitters.pop("ecar")
    if collection == "none":
        fixture.generator.dispatcher.emitters.pop("zeek_conn")
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    fixture.generator.finalize_ssh_session_lifecycles(end.canonical_end + timedelta(minutes=1))
    assert fixture.state.get_session(logon) is not None
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    assert fixture.state.get_session(logon) is None
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    rows, _ = fixture.close_and_read()
    sessions = [row for row in rows if row.get("object") == "USER_SESSION"]
    assert [row["action"] for row in sessions] == (
        ["LOGIN", "LOGOUT"] if collection == "all" else []
    )


def test_changed_authored_close_rejects_before_state(tmp_path: Path) -> None:
    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    before = fixture.state.materialization_digest()
    with pytest.raises(StateError, match="exact authored close owner"):
        fixture.generator.generate_logoff(
            request.user,
            fixture.target,
            end.canonical_end + timedelta(seconds=1),
            logon,
            from_storyline=True,
            session_end_plan=end,
        )
    assert fixture.state.materialization_digest() == before
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()


@pytest.mark.parametrize("failed_row", [1, 2, 3, 4])
@pytest.mark.parametrize("after_write", [False, True])
def test_authored_close_retry_keeps_one_logout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_row: int, after_write: bool
) -> None:
    from evidenceforge.generation.checkpoints.activity_head import _capture_ssh_lifecycles
    from evidenceforge.generation.checkpoints.errors import CheckpointError
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    original = ExternalSortedLineWriter._commit_exact_row
    count = 0

    def inject(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal count
        count += 1
        if count == failed_row and not after_write:
            raise RuntimeError("injected authored close write failure")
        original(writer, *args)
        if count == failed_row:
            raise RuntimeError("injected authored close write failure")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", inject)
    with pytest.raises(RuntimeError, match="authored close write failure"):
        fixture.generator.generate_logoff(
            request.user,
            fixture.target,
            end.canonical_end,
            logon,
            from_storyline=True,
            session_end_plan=end,
        )
    with pytest.raises(CheckpointError):
        _capture_ssh_lifecycles(fixture.generator)
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    rows, _ = fixture.close_and_read()
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    assert sum(row["action"] == "LOGOUT" for row in rows) == 1
    assert (
        sum(row["action"] == "TERMINATE" for row in rows) == 4
    )  # pre-auth worker + 3 terminal processes


def test_authored_close_journal_restores_same_end_owner(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.activity_head import (
        _capture_ssh_lifecycles,
        _restore_ssh_lifecycles,
    )

    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    rows = _capture_ssh_lifecycles(fixture.generator)
    assert len(rows) == 1 and len(rows[0]) == 32
    fixture.generator._pending_ssh_session_closures.clear()
    _restore_ssh_lifecycles(fixture.generator, rows)
    assert fixture.generator._pending_ssh_session_closures[0].plan.authoritative_end_plan == end
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()


def test_changed_live_end_plan_rejects_without_closing(tmp_path: Path) -> None:
    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    session = fixture.state.get_session(logon)
    session.end_plan = replace(end, storyline_event_id="foreign-close")
    before = fixture.state.materialization_digest()
    with pytest.raises(StateError, match="live session end owner"):
        fixture.generator.generate_logoff(
            request.user,
            fixture.target,
            end.canonical_end,
            logon,
            from_storyline=True,
            session_end_plan=end,
        )
    assert fixture.state.materialization_digest() == before
    session.end_plan = end
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()


@pytest.mark.parametrize("damage", ["null", "foreign-storyline"])
def test_authored_close_journal_rejects_missing_or_changed_owner(
    tmp_path: Path, damage: str
) -> None:
    from evidenceforge.generation.checkpoints.activity_head import (
        _capture_ssh_lifecycles,
        _restore_ssh_lifecycles,
    )
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from evidenceforge.generation.checkpoints.state_values import encode_state_value

    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    rows = _capture_ssh_lifecycles(fixture.generator)
    rows[0][31] = encode_state_value(
        None if damage == "null" else replace(end, storyline_event_id="foreign")
    )
    original = fixture.generator._pending_ssh_session_closures[:]
    fixture.generator._pending_ssh_session_closures.clear()
    with pytest.raises(CheckpointCorruptionError):
        _restore_ssh_lifecycles(fixture.generator, rows)
    assert not fixture.generator._pending_ssh_session_closures
    fixture.generator._pending_ssh_session_closures.extend(original)
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()


@pytest.mark.parametrize(
    "image", ["/usr/bin/id", "/Applications/Example.app/Contents/MacOS/Example"]
)
def test_remote_mac_process_parent_preserves_ssh_audit_identity(tmp_path: Path, image: str) -> None:
    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    session = fixture.state.get_session(logon)
    assert session is not None and session.audit_origin is not None
    at = _START + timedelta(minutes=1)
    parent = fixture.generator._process_parents()._macos_existing_parent(
        fixture.target, at, logon, process_name=image
    )
    assert parent == session.session_shell_pid
    credentials = fixture.generator._process_credentials(
        fixture.target, request.user.username, parent, at
    )
    assert credentials.audit_uid == session.audit_origin.audit_uid
    assert credentials.audit_session_id == session.audit_origin.audit_session_id
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()


@pytest.mark.parametrize(
    "platform,kind,expected",
    [
        ("macOS 26", "ssh", True),
        ("macOS 26", "interactive", False),
        ("Ubuntu 24.04", "ssh", False),
        ("Windows 11", "rdp", False),
    ],
)
def test_mac_ssh_persona_does_not_reuse_assigned_desktop_profile(
    platform: str, kind: str, expected: bool
) -> None:
    from types import SimpleNamespace

    from evidenceforge.generation.engine.baseline import BaselineMixin

    engine = SimpleNamespace(_is_server_admin_persona_source=lambda system: False)
    system = SimpleNamespace(os=platform, type="workstation", assigned_user="alex")
    session = SimpleNamespace(username="alex", session_kind=kind, logon_type=10)
    assert BaselineMixin._use_server_admin_persona(engine, system, session) is expected


def test_mac_ssh_missing_ready_shell_cannot_fall_back_to_launchd(tmp_path: Path) -> None:
    fixture = _mac_fixture(tmp_path)
    end = SessionEndPlan(_START + timedelta(minutes=3), "explicit_storyline", "close-mac")
    request = replace(
        fixture.request(), emit_session_close=True, defer_session_close=True, session_end_plan=end
    )
    _, logon = SshSessionActionBundle(request, fixture.generator)._execute_macos_receiver()
    before = fixture.state.materialization_digest()
    with pytest.raises(StateError, match="live session shell"):
        fixture.generator._process_parents()._macos_existing_parent(
            fixture.target,
            _START - timedelta(seconds=1),
            logon,
            process_name="/Applications/Example.app/Contents/MacOS/Example",
        )
    assert fixture.state.materialization_digest() == before
    fixture.generator.generate_logoff(
        request.user,
        fixture.target,
        end.canonical_end,
        logon,
        from_storyline=True,
        session_end_plan=end,
    )
    fixture.close_and_read()
