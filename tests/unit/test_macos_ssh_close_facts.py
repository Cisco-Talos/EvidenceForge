# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac close facts keep canonical ownership distinct from Linux logind observation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.generation.actions.ssh_session import (
    SshReceiverAuthentication,
    SshSessionActionBundle,
    _SshMacAuthState,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_macos_ssh_startup import _descriptor
from tests.unit.test_ssh_deferred_production import _fixture


def test_mac_close_plan_uses_common_receiver_facts_without_logind_time(tmp_path: Path) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(fixture.request(), emit_session_close=True, defer_session_close=True)
    SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    linux = fixture.generator._pending_ssh_session_closures[0].plan
    auth = _SshMacAuthState(
        receiver=linux.auth_state.receiver,
        initial_receiver_image=_descriptor("macos-sshd-keygen-wrapper").image_path,
        receiver_image=_descriptor("macos-sshd-session").image_path,
    )
    mac = replace(
        linux,
        auth_state=auth,
        logind_remove_time=None,
        target_host=replace(
            linux.target_host, os="macOS 26", os_category="macos", system_type="workstation"
        ),
        target_system=replace(
            linux.target_system, os="macOS 26", architecture="arm64", system_type="workstation"
        ),
    )
    assert mac.session_identity() == linux.session_identity()
    assert mac.initial_receiver_image == auth.initial_receiver_image
    assert mac.receiver_image == auth.receiver_image
    assert mac.logind_remove_time is None
    mac.require_terminal_tail(mac.terminal_window_end)
    with pytest.raises(ValueError, match="logind"):
        replace(mac, logind_remove_time=linux.logind_remove_time)
    with pytest.raises(ValueError, match="platform"):
        replace(mac, auth_state=linux.auth_state)
    with pytest.raises(ValueError, match="logind"):
        replace(linux, logind_remove_time=None)
    from evidenceforge.generation.actions.ssh_session import _PreparedSshCloseContinuation
    from evidenceforge.models.exceptions import StateError

    original = fixture.generator._pending_ssh_session_closures[0].prepared
    prepared = _PreparedSshCloseContinuation(
        plan=mac,
        identity_capture=original.identity_capture,
        dispatcher_owner=original.dispatcher_owner,
        ecar_owner=original.ecar_owner,
        zeek_owner=original.zeek_owner,
        ssh_manager_owner=original.ssh_manager_owner,
        application_registry_owner=original.application_registry_owner,
    )
    for operation in (
        prepared.require_projection_phase,
        prepared.mark_projection_complete,
        prepared.cancel_projection_phase,
    ):
        with pytest.raises(StateError, match="logind"):
            operation("logind-remove")
    assert not prepared._progress._completed
    prepared.require_projection_phase("logout")
    fixture.close_and_read()


def _auth() -> SshReceiverAuthentication:
    from datetime import UTC, datetime, timedelta

    from evidenceforge.generation.actions.ssh_session import SshReceiverAuthentication

    start = datetime(2026, 1, 1, tzinfo=UTC)
    return SshReceiverAuthentication(
        responder_pid=200,
        session_id=501,
        connection_time=start,
        authenticated_at=start + timedelta(seconds=1),
        session_open_time=start + timedelta(seconds=2),
        ready_at=start + timedelta(seconds=3),
    )


def test_auth_codec_keeps_linux_row_unchanged_and_tags_mac() -> None:
    from evidenceforge.generation.actions.ssh_session import _SshLinuxAuthState
    from evidenceforge.generation.checkpoints.activity_head import _decode_ssh_auth, _ssh_auth_row
    from evidenceforge.generation.checkpoints.state_values import encode_state_value

    receiver = _auth()
    linux = _SshLinuxAuthState(receiver, ("fixture", 200))
    row = _ssh_auth_row(linux)
    assert row == [
        200,
        501,
        encode_state_value(linux.syslog_seed),
        *[
            encode_state_value(time)
            for time in (
                receiver.connection_time,
                receiver.authenticated_at,
                receiver.session_open_time,
                receiver.ready_at,
            )
        ],
    ]
    assert _decode_ssh_auth(loads(dumps(row))) == linux
    mac = _SshMacAuthState(
        receiver, "/usr/libexec/sshd-keygen-wrapper", "/usr/libexec/sshd-session"
    )
    row = _ssh_auth_row(mac)
    assert row[0] == "macos-v1"
    assert _decode_ssh_auth(loads(dumps(row))) == mac
    grouped = replace(mac, owns_posix_session=True)
    grouped_row = _ssh_auth_row(grouped)
    assert grouped_row[0] == "macos-v2"
    assert _decode_ssh_auth(loads(dumps(grouped_row))) == grouped


@pytest.mark.parametrize(
    "index,value",
    [
        (0, "macos-v3"),
        (1, True),
        (1, 0),
        (2, -1),
        (2, False),
        (3, []),
        (3, [None] * 4),
        (4, "relative"),
        (5, "/bad\nimage"),
        (5, "/"),
    ],
)
def test_mac_auth_codec_rejects_malformed_facts(index: int, value: object) -> None:
    from evidenceforge.generation.checkpoints.activity_head import _decode_ssh_auth, _ssh_auth_row
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    mac = _SshMacAuthState(_auth(), "/usr/libexec/sshd-keygen-wrapper", "/usr/libexec/sshd-session")
    row = _ssh_auth_row(mac)
    row[index] = value
    with pytest.raises(CheckpointCorruptionError):
        _decode_ssh_auth(row)


@pytest.mark.parametrize("kind", ["inverted", "naive", "extra"])
def test_mac_auth_codec_rejects_invalid_timing_contract(kind: str) -> None:
    from evidenceforge.generation.checkpoints.activity_head import _decode_ssh_auth, _ssh_auth_row
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from evidenceforge.generation.checkpoints.state_values import encode_state_value

    receiver = _auth()
    mac = _SshMacAuthState(
        receiver, "/usr/libexec/sshd-keygen-wrapper", "/usr/libexec/sshd-session"
    )
    row = _ssh_auth_row(mac)
    if kind == "inverted":
        row[3][1] = row[3][3]
    elif kind == "naive":
        row[3][0] = encode_state_value(receiver.connection_time.replace(tzinfo=None))
    else:
        row[3].append(row[3][-1])
    with pytest.raises(CheckpointCorruptionError):
        _decode_ssh_auth(row)
