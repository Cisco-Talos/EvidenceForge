# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit proxy generation and visibility tests."""

from datetime import UTC, datetime
from unittest.mock import Mock

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)


def _system(hostname: str, ip: str, roles: list[str] | None = None) -> System:
    return System(
        hostname=hostname,
        ip=ip,
        os="Linux Ubuntu 22.04" if roles and "forward_proxy" in roles else "Windows 11",
        type="server" if roles and "forward_proxy" in roles else "workstation",
        roles=roles or [],
    )


def _emitters() -> dict[str, Mock]:
    emitters = {
        "zeek_conn": Mock(),
        "zeek_http": Mock(),
        "zeek_ssl": Mock(),
        "proxy_access": Mock(),
        "snort_alert": Mock(),
    }
    emitters["zeek_conn"].can_handle.side_effect = lambda event: event.network is not None
    emitters["zeek_http"].can_handle.side_effect = lambda event: event.http is not None
    emitters["zeek_ssl"].can_handle.side_effect = lambda event: event.ssl is not None
    emitters["proxy_access"].can_handle.side_effect = lambda event: event.proxy is not None
    emitters["snort_alert"].can_handle.side_effect = lambda event: event.ids is not None
    return emitters


def _generator(sensors: list[NetworkSensor]) -> tuple[ActivityGenerator, dict[str, Mock]]:
    workstation = _system("WKS-01", "10.0.1.10")
    proxy = _system("PROXY-01", "10.0.3.10", ["forward_proxy"])
    systems = [workstation, proxy]
    network = NetworkConfig(
        segments=[
            NetworkSegment(
                name="workstations",
                cidr="10.0.1.0/24",
                systems=["WKS-01"],
                exposure="internal",
            ),
            NetworkSegment(
                name="dmz",
                cidr="10.0.3.0/24",
                systems=["PROXY-01"],
                exposure="both",
            ),
        ],
        sensors=sensors,
    )
    visibility = NetworkVisibilityEngine(network, systems)
    state_manager = StateManager()
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
    emitters = _emitters()
    dispatcher = EventDispatcher(state_manager, emitters, visibility_engine=visibility)
    generator = ActivityGenerator(
        state_manager,
        emitters,
        network_visibility=visibility,
        dispatcher=dispatcher,
    )
    generator._ip_to_system = {system.ip: system for system in systems}
    generator._proxy_routes = {workstation.ip: [proxy]}
    generator._proxy_mode = "explicit"
    generator._proxy_listener_port = 8080
    generator._ad_domain = "example.org"
    return generator, emitters


def _conn_pairs(emitters: dict[str, Mock]) -> list[tuple[str, str, int]]:
    return [
        (
            call.args[0].network.src_ip,
            call.args[0].network.dst_ip,
            call.args[0].network.dst_port,
        )
        for call in emitters["zeek_conn"].emit.call_args_list
    ]


class TestExplicitProxyVisibility:
    """Explicit proxy mode emits concrete legs, not the logical direct connection."""

    def test_client_side_sensor_sees_client_to_proxy_only(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="client-tap",
                    monitoring_segments=["workstations"],
                    direction="outbound",
                    log_formats=["zeek"],
                )
            ]
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.1.10", "93.184.216.34", 443) not in pairs
        assert ("10.0.3.10", "93.184.216.34", 443) not in pairs
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.method == "CONNECT"
        assert proxy_event.proxy.host == "example.com"
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "CONNECT"
        assert not emitters["zeek_ssl"].emit.called

    def test_egress_sensor_sees_proxy_to_origin_only(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="egress-tap",
                    monitoring_segments=["dmz"],
                    direction="outbound",
                    log_formats=["zeek"],
                )
            ]
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
        )

        assert _conn_pairs(emitters) == [("10.0.3.10", "93.184.216.34", 443)]
        assert emitters["zeek_ssl"].emit.called

    def test_sensor_monitoring_both_sides_sees_both_proxy_legs(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="both-sides",
                    monitoring_segments=["workstations", "dmz"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                )
            ]
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", "93.184.216.34", 443) in pairs
        assert ("10.0.1.10", "93.184.216.34", 443) not in pairs
