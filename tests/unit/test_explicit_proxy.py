# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit proxy generation and visibility tests."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.events.contexts import FirewallContext, HttpContext, IdsContext, ProxyContext
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


def test_proxy_user_agent_selection_is_role_aware_for_servers():
    from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent

    rng = random.Random(42)
    web_server = System(
        hostname="web01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )

    user_agents = {pick_proxy_user_agent(rng, web_server) for _ in range(50)}

    assert user_agents
    assert all("Mozilla/" not in ua for ua in user_agents)
    assert any(token in ua for ua in user_agents for token in ("curl", "apt", "Wget", "requests"))


def test_server_proxy_package_user_agents_are_destination_aware():
    from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent

    generic_rng = random.Random(7)
    ubuntu_server = System(
        hostname="web01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )

    generic_user_agents = {
        pick_proxy_user_agent(generic_rng, ubuntu_server, hostname="login.microsoftonline.com")
        for _ in range(100)
    }
    package_tokens = ("apt", "APT", "dnf", "Fedora")
    assert all(
        not any(token in user_agent for token in package_tokens)
        for user_agent in generic_user_agents
    )

    package_rng = random.Random(11)
    package_user_agents = {
        pick_proxy_user_agent(package_rng, ubuntu_server, hostname="archive.ubuntu.com")
        for _ in range(40)
    }
    assert package_user_agents
    assert all("apt" in user_agent.lower() for user_agent in package_user_agents)
    assert all("Fedora" not in user_agent for user_agent in package_user_agents)


def test_server_proxy_package_user_agents_match_os_family():
    from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent

    fedora_server = System(
        hostname="app01",
        ip="10.0.3.30",
        os="Fedora Linux 39",
        type="server",
        roles=["app_server"],
    )
    ubuntu_server = System(
        hostname="web01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )

    fedora_user_agents = {
        pick_proxy_user_agent(
            random.Random(seed),
            fedora_server,
            hostname="download.fedoraproject.org",
        )
        for seed in range(20)
    }
    ubuntu_user_agents = {
        pick_proxy_user_agent(
            random.Random(seed),
            ubuntu_server,
            hostname="download.fedoraproject.org",
        )
        for seed in range(20)
    }

    assert fedora_user_agents == {"libdnf (Fedora Linux 39; server; Linux.x86_64)"}
    assert all("Fedora" not in user_agent for user_agent in ubuntu_user_agents)


def test_proxy_user_agent_overlay_adds_package_family(tmp_path, monkeypatch):
    import yaml

    from evidenceforge.generation.activity.proxy_user_agents import (
        pick_proxy_user_agent,
        reset_proxy_user_agents_cache,
    )

    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    overlay_path = overlay_dir / "proxy_user_agents.yaml"
    overlay_path.write_text(
        yaml.safe_dump(
            {
                "server": {
                    "package_managers": {
                        "custom_deb": {
                            "os_keywords": ["ubuntu"],
                            "hosts": ["updates.example.test"],
                            "user_agents": ["CustomPkg/1.0"],
                        }
                    }
                }
            },
            sort_keys=False,
        )
    )
    monkeypatch.chdir(tmp_path)
    reset_proxy_user_agents_cache()

    ubuntu_server = System(
        hostname="web01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )

    try:
        user_agent = pick_proxy_user_agent(
            random.Random(5),
            ubuntu_server,
            hostname="updates.example.test",
        )
    finally:
        reset_proxy_user_agents_cache()

    assert user_agent == "CustomPkg/1.0"


def test_server_ids_http_traffic_keeps_server_proxy_user_agent():
    generator, emitters = _generator(
        [
            NetworkSensor(
                type="network",
                name="dmz-tap",
                monitoring_segments=["dmz"],
                direction="bidirectional",
                log_formats=["zeek"],
            )
        ]
    )
    web_server = System(
        hostname="WEB-01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )
    generator._ip_to_system[web_server.ip] = web_server
    generator._proxy_routes[web_server.ip] = [generator._ip_to_system["10.0.3.10"]]

    generator.generate_connection(
        src_ip=web_server.ip,
        dst_ip="93.184.216.34",
        time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=5000,
        source_system=web_server,
        hostname="example.com",
        conn_state="SF",
        ids=IdsContext(
            sid=2013028,
            message="ET POLICY Suspicious HTTP Activity",
            classification="policy-violation",
            priority=2,
        ),
    )

    proxy_event = emitters["proxy_access"].emit.call_args.args[0]
    assert proxy_event.proxy.client_ip == web_server.ip
    assert "Mozilla/" not in proxy_event.proxy.user_agent
    assert proxy_event.proxy.user_agent


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
        "zeek_dns": Mock(),
        "zeek_http": Mock(),
        "zeek_ssl": Mock(),
        "proxy_access": Mock(),
        "snort_alert": Mock(),
        "cisco_asa": Mock(),
    }
    emitters["zeek_conn"].can_handle.side_effect = lambda event: event.network is not None
    emitters["zeek_dns"].can_handle.side_effect = lambda event: event.dns is not None
    emitters["zeek_http"].can_handle.side_effect = lambda event: event.http is not None
    emitters["zeek_ssl"].can_handle.side_effect = lambda event: event.ssl is not None
    emitters["proxy_access"].can_handle.side_effect = lambda event: event.proxy is not None
    emitters["snort_alert"].can_handle.side_effect = lambda event: event.ids is not None
    emitters["cisco_asa"].can_handle.side_effect = lambda event: event.network is not None
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
        assert proxy_event.proxy.cs_bytes > 0
        assert proxy_event.proxy.sc_bytes > 0
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "CONNECT"
        assert http_event.http.request_body_len == 0
        assert http_event.http.response_body_len == 0
        conn_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 8080
        )
        assert conn_event.network.orig_bytes >= proxy_event.proxy.cs_bytes
        assert conn_event.network.resp_bytes >= proxy_event.proxy.sc_bytes
        assert conn_event.network.orig_bytes >= proxy_event.proxy.cs_bytes + 500
        assert conn_event.network.resp_bytes >= proxy_event.proxy.sc_bytes + 5000
        assert conn_event.network.resp_pkts > 0
        assert not emitters["zeek_ssl"].emit.called

    def test_documentation_ip_with_external_hostname_routes_through_proxy(self):
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
            dst_ip="203.0.113.45",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="dynsync-update.net",
            http=HttpContext(
                method="GET",
                host="dynsync-update.net",
                uri="/jquery-3.3.1.min.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                status_code=200,
                status_msg="OK",
            ),
            conn_state="SF",
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", "203.0.113.45", 80) in pairs
        assert ("10.0.1.10", "203.0.113.45", 80) not in pairs
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.host == "dynsync-update.net"
        assert proxy_event.proxy.method == "GET"

    def test_auto_generated_proxy_get_has_no_zeek_request_body(self):
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
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
        )

        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "GET"
        assert http_event.http.request_body_len == 0
        assert http_event.network.orig_bytes > 0

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

        pairs = _conn_pairs(emitters)
        assert any(pair[0] == "10.0.3.10" and pair[2] == 53 for pair in pairs)
        assert ("10.0.3.10", "93.184.216.34", 443) in pairs
        assert ("10.0.1.10", "93.184.216.34", 443) not in pairs
        assert emitters["zeek_dns"].emit.called
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

    def test_https_subresources_reuse_active_connect_tunnel(self):
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
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        first_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start_time,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            emit_dns=True,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
            ),
        )
        pairs_after_first = list(_conn_pairs(emitters))
        proxy_calls_after_first = emitters["proxy_access"].emit.call_count
        ssl_calls_after_first = emitters["zeek_ssl"].emit.call_count
        reused_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start_time + timedelta(seconds=12),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=0.2,
            orig_bytes=200,
            resp_bytes=1200,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            emit_dns=True,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/app.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=1200,
                status_code=200,
                status_msg="OK",
            ),
        )

        assert reused_uid == first_uid
        assert _conn_pairs(emitters) == pairs_after_first
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs_after_first
        assert ("10.0.3.10", "93.184.216.34", 443) in pairs_after_first
        assert emitters["proxy_access"].emit.call_count == proxy_calls_after_first
        assert emitters["zeek_ssl"].emit.call_count == ssl_calls_after_first

    def test_denied_request_stops_before_origin_side_sources(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="client-tap",
                    monitoring_segments=["workstations"],
                    direction="outbound",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="network",
                    name="egress-tap",
                    monitoring_segments=["dmz"],
                    direction="outbound",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="ids",
                    name="egress-ids",
                    monitoring_segments=["dmz"],
                    direction="outbound",
                    log_formats=["snort_alert"],
                ),
                NetworkSensor(
                    type="firewall",
                    name="egress-fw",
                    monitoring_segments=["dmz"],
                    direction="outbound",
                    log_formats=["cisco_asa"],
                ),
            ]
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="GET",
                url="http://example.com/private",
                host="example.com",
                status_code=403,
                sc_bytes=1200,
                cs_bytes=420,
                time_taken=250,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="DENIED",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/private",
                version="1.1",
                status_code=200,
                status_msg="OK",
            ),
            ids=IdsContext(
                sid=2013028,
                message="ET POLICY Suspicious HTTP Activity",
                classification="policy-violation",
                priority=2,
            ),
            firewall=FirewallContext(
                action="permit",
                msg_id=302013,
                connection_id=12345,
                src_interface="dmz",
                dst_interface="outside",
            ),
        )

        pairs = _conn_pairs(emitters)
        assert pairs
        assert all(pair == ("10.0.1.10", "10.0.3.10", 8080) for pair in pairs)
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 403
        assert proxy_event.proxy.cache_result == "DENIED"
        assert emitters["zeek_http"].emit.called
        assert all(
            call.args[0].network.dst_ip == "10.0.3.10"
            for call in emitters["zeek_http"].emit.call_args_list
        )
        assert not emitters["zeek_ssl"].emit.called
        assert not emitters["snort_alert"].emit.called
        assert not emitters["cisco_asa"].emit.called

    def test_auth_required_connect_stops_before_origin_side_sources(self):
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
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=407,
                sc_bytes=700,
                cs_bytes=320,
                time_taken=250,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="AUTH_REQUIRED",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
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
        assert ("10.0.3.10", "93.184.216.34", 443) not in pairs
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 407
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "CONNECT"
        assert http_event.http.status_code == 407
        assert http_event.http.request_body_len == 0
        assert http_event.http.response_body_len == 0
        assert not emitters["zeek_ssl"].emit.called

    def test_supplied_denied_proxy_context_stops_before_origin_side_sources(self):
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
            proxy=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=403,
                sc_bytes=700,
                cs_bytes=320,
                time_taken=250,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="DENIED",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            ),
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", "93.184.216.34", 443) not in pairs
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 403
        assert not emitters["zeek_ssl"].emit.called

    def test_port_only_web_connection_resolves_origin_from_proxy(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="client-tap",
                    monitoring_segments=["workstations"],
                    direction="outbound",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="network",
                    name="egress-tap",
                    monitoring_segments=["dmz"],
                    direction="outbound",
                    log_formats=["zeek"],
                ),
            ]
        )
        generator._dns_server_ips = ["10.0.0.1"]

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="10.0.0.1",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service=None,
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            emit_dns=True,
            conn_state="SF",
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        origin_pairs = [pair for pair in pairs if pair[0] == "10.0.3.10" and pair[2] == 443]
        assert origin_pairs
        assert all(pair[1] != "10.0.0.1" for pair in origin_pairs)
        assert all(pair[0] != "10.0.1.10" or pair[1] == "10.0.3.10" for pair in pairs)
        dns_events = [call.args[0] for call in emitters["zeek_dns"].emit.call_args_list]
        assert dns_events
        assert all(event.network.src_ip == "10.0.3.10" for event in dns_events)
        assert all("10.0.0.1" not in event.dns.answers for event in dns_events)
        assert all(event.dns.query != "PROXY-01.example.org" for event in dns_events)
        assert any(event.dns.query == "example.com" for event in dns_events)

    def test_private_destination_without_hostname_does_not_invent_public_dns(self):
        workstation = _system("WKS-01", "10.0.1.10")
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        emitters = _emitters()
        generator = ActivityGenerator(state_manager, emitters)
        generator._ip_to_system = {workstation.ip: workstation}
        generator._dns_server_ips = ["10.0.0.1"]
        generator._ad_domain = "example.org"

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="10.0.0.1",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service=None,
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=workstation,
            emit_dns=True,
            conn_state="SF",
        )

        dns_events = [call.args[0] for call in emitters["zeek_dns"].emit.call_args_list]
        assert dns_events
        assert all(event.network.src_ip == "10.0.1.10" for event in dns_events)
        queries = {event.dns.query for event in dns_events}
        assert any(query.endswith(".example.org") for query in queries)
        assert not any(
            public_hint in query
            for query in queries
            for public_hint in ("hotjar", "hubspot", "amplitude", "intercom", "linkedin")
        )

    def test_established_ssl_connection_always_has_ssl_context(self):
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        emitters = _emitters()
        generator = ActivityGenerator(state_manager, emitters)

        generator.generate_connection(
            src_ip="10.0.3.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            hostname="example.com",
            conn_state="S0",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                version="1.1",
                status_code=200,
                status_msg="OK",
            ),
        )

        conn_event = emitters["zeek_conn"].emit.call_args.args[0]
        assert conn_event.network.conn_state == "SF"
        assert conn_event.network.orig_bytes > 0
        assert conn_event.network.resp_bytes > 0
        assert conn_event.network.orig_pkts > 0
        assert conn_event.network.resp_pkts > 0
        assert conn_event.ssl is not None
        assert conn_event.ssl.established is True
        assert conn_event.x509 is not None
        assert conn_event.ssl.cert_chain_fuids == [conn_event.x509.fuid]
