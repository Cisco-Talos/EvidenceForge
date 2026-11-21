# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A DNS tunnel owns its campaign, not unrelated fleet background activity."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models.scenario import DnsTunnelEventSpec, System, User
from evidenceforge.utils.rng import reset_thread_rng


def _campaign(
    peer_count: int, qtype: str, *, with_ids: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reset_thread_rng(217)
    engine = object.__new__(StorylineMixin)
    captured: list[dict[str, Any]] = []
    source = System(hostname="APP-01", ip="10.0.0.10", os="Ubuntu", type="server")
    peers = [
        System(hostname=f"PEER-{n}", ip=f"10.0.1.{n + 1}", os="Windows 11", type="workstation")
        for n in range(peer_count)
    ]
    engine.state_manager = SimpleNamespace(set_current_time=lambda _: None)
    engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[source, *peers]))
    engine.activity_generator = SimpleNamespace(
        _dns_server_ips=["10.0.0.53"], generate_connection=lambda **kw: captured.append(kw)
    )
    result = engine._execute_typed_event(
        spec=DnsTunnelEventSpec(
            base_domain="channel.example.test",
            qtype=qtype,
            interval="2s",
            duration="1m",
            payload_size=128,
            ids_alerts=[{"sid": 2029706}] if with_ids else [],
        ),
        actor=User(username="analyst", full_name="Analyst", email="a@example.test"),
        system=source,
        time=datetime(2026, 11, 2, 13, tzinfo=UTC),
        activity="Explicit DNS campaign",
        explicit_types={"dns_tunnel"},
    )
    assert isinstance(result, dict)
    return captured, result


@pytest.mark.parametrize("qtype", ["TXT", "CNAME", "NULL"])
def test_unrelated_hosts_do_not_change_campaign_or_create_background(qtype: str) -> None:
    isolated, isolated_truth = _campaign(0, qtype)
    populated, populated_truth = _campaign(20, qtype)
    assert isolated
    assert all(row["src_ip"] == "10.0.0.10" for row in populated)
    assert all(row["dns"].query.endswith("channel.example.test") for row in populated)
    assert populated == isolated
    assert populated_truth == isolated_truth
    assert populated_truth["total_queries"] == len(populated)
    assert populated_truth["bytes_exfiltrated"] > 0


def test_authored_ids_attachments_stay_on_campaign_transports() -> None:
    rows, truth = _campaign(20, "TXT", with_ids=True)
    assert rows
    assert all(row["src_ip"] == "10.0.0.10" for row in rows)
    assert all(len(row["ids_alerts"]) == 1 for row in rows)
    assert all(row["ids_alerts"][0].sid == 2029706 for row in rows)
    assert all(row["ids_alerts"][0].origin == "authored_attachment" for row in rows)
    assert truth["ids_alerts"][0]["sid"] == 2029706
