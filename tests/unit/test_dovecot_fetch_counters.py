# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native Dovecot count and byte fields describe the same fetched data."""

import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.models.scenario import System, User
from tests.network_factories import network_plan


@pytest.mark.parametrize("response_bytes", [0, 3000, 250000])
@pytest.mark.parametrize("message_ids", [(), ("mail-a", "mail-b")])
@pytest.mark.parametrize("offset", range(8))
def test_native_fetch_counts_agree_with_allocated_data_bytes(
    monkeypatch: pytest.MonkeyPatch,
    response_bytes: int,
    message_ids: tuple[str, ...],
    offset: int,
) -> None:
    generator = object.__new__(ActivityGenerator)
    generator.state_manager = SimpleNamespace(allocate_transient_linux_pid=Mock(return_value=2345))
    emit = Mock()
    monkeypatch.setattr(generator, "generate_syslog_event", emit)
    start = datetime(2026, 11, 2, 13, tzinfo=UTC) + timedelta(seconds=17 * offset)
    client = System(hostname="CLIENT", ip="10.0.0.10", os="Windows 11", type="workstation")
    server = System(hostname="MAIL", ip="10.0.0.20", os="Ubuntu 22.04", type="server")
    user = User(username="bob", full_name="Bob Brown", email="bob@example.test")
    transport = network_plan(
        src_ip=client.ip,
        src_port=54321,
        dst_ip=server.ip,
        dst_port=993,
        protocol="tcp",
        zeek_uid="imap-uid",
        duration=20.0,
        source_visible_start_time=start,
        orig_bytes=1500,
        resp_bytes=response_bytes + 1500,
        conn_state="SF",
    )
    generator._emit_dovecot_imap_syslog(
        user=user,
        client_system=client,
        server=server,
        time=start,
        duration=20.0,
        orig_bytes=1200,
        resp_bytes=response_bytes,
        message_ids=message_ids,
        master_pid=1234,
        transport=transport,
    )
    login, logout = emit.call_args_list
    assert start < login.args[1] < logout.args[1] < transport.closed_at
    values = {name: int(value) for name, value in re.findall(r"(\w+)=(\d+)", logout.args[3])}
    assert values["in"] == 1200 and values["out"] == response_bytes
    for prefix in ("hdr", "body"):
        count, size = values[prefix + "_count"], values[prefix + "_bytes"]
        # An empty/partial fetch may be counted without sending payload.
        # Positive fetched data cannot have zero associated fetched messages.
        assert count > 0 or size == 0, logout.args[3]
    assert values["hdr_bytes"] + values["body_bytes"] <= values["out"]
    assert values["body_count"] <= (len(message_ids) or 6)
