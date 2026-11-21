# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Literal CLI request intent retains the canonical explicit-proxy actor."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.contexts import HttpContext, ProxyContext
from evidenceforge.generation.activity.network_http import (
    _extract_http_url_from_command,
    _http_method_for_process_command,
    _literal_http_process_owns_request,
)
from evidenceforge.models.scenario import NetworkSensor
from tests.unit.test_explicit_proxy import (
    _generator,
    _seed_linux_proxy_client_user_session,
    _seed_proxy_client_user_session,
)


@pytest.mark.parametrize(
    "prefix",
    [
        "curl -x http://proxy:8080",
        "curl --proxy=http://proxy:8080",
        "wget -e http_proxy=http://proxy:8080",
        'curl -H "Referer: https://other.example/"',
        "curl -e https://other.example/",
        'curl -o "https://output.example/file"',
        'wget -O "https://output.example/file"',
        "curl -O",
        "curl --url",
    ],
)
def test_request_url_excludes_configuration_urls(prefix: str) -> None:
    assert (
        _extract_http_url_from_command(prefix + " https://origin.example/a?x=1")
        == "https://origin.example/a?x=1"
    )


@pytest.mark.parametrize(
    ("flag", "method"),
    [
        ("-I", "HEAD"),
        ("-fsSI", "HEAD"),
        ("-fsSi", "GET"),
        ("-i", "GET"),
        ("--head", "HEAD"),
        ("--request=DELETE", "DELETE"),
        ("-X OPTIONS", "OPTIONS"),
        ("--data https://body.example/", "POST"),
    ],
)
def test_cli_effective_method_is_case_sensitive(flag: str, method: str) -> None:
    assert _http_method_for_process_command("curl " + flag + " https://origin.example/a") == method


@pytest.mark.parametrize(
    ("uri", "port", "method", "body", "expected"),
    [
        ("/tools/a?x=1", 443, "GET", 0, True),
        ("/tools/A?x=1", 443, "GET", 0, False),
        ("/tools/a?x=2", 443, "GET", 0, False),
        ("/tools/a?x=1", 80, "GET", 0, False),
        ("/tools/a?x=1", 443, "HEAD", 0, False),
        ("/tools/a?x=1", 443, "GET", 12, False),
        (None, 443, "CONNECT", 0, True),
    ],
)
def test_literal_caller_request_contract(
    uri: str | None, port: int, method: str, body: int, expected: bool
) -> None:
    assert (
        _literal_http_process_owns_request(
            image="/usr/bin/curl",
            command_line="curl -o /tmp/a https://origin.example/tools/a?x=1",
            hostname="origin.example",
            dst_port=port,
            method=method,
            uri=uri,
            request_body_len=body,
        )
        is expected
    )


@pytest.mark.parametrize("linux", [False, True])
@pytest.mark.parametrize("tool", ["curl", "wget"])
def test_proxy_download_uses_original_downloader_as_socket_owner(linux: bool, tool: str) -> None:
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
    if linux:
        user, source, parent = _seed_linux_proxy_client_user_session(generator)
        image = "/usr/bin/" + tool
        output = "/tmp/package.bin"
    else:
        user, _, parent = _seed_proxy_client_user_session(generator)
        source = generator._ip_to_system["10.0.1.10"]
        image = "C:\\Windows\\System32\\" + tool + ".exe"
        output = "C:\\Users\\alex.morgan\\Downloads\\package.bin"
    start = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
    generator.state_manager.set_current_time(start)
    session = generator.state_manager.get_process(source.hostname, parent).logon_id
    command = (
        f"{tool} "
        + ("-o" if tool == "curl" else "-O")
        + f' "{output}" https://download.example/tools/package.bin?build=7'
    )
    pid = generator.state_manager.create_process(
        system=source.hostname,
        parent_pid=parent,
        image=image,
        command_line=command,
        username=user.username,
        integrity_level="Medium",
        logon_id=session,
    )
    generator.generate_connection(
        src_ip=source.ip,
        dst_ip="203.0.113.88",
        time=start + timedelta(seconds=1),
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=2.0,
        orig_bytes=600,
        resp_bytes=12000,
        pid=pid,
        source_system=source,
        hostname="download.example",
        conn_state="SF",
        process_image=image,
        http=HttpContext(
            method="GET",
            host="download.example",
            uri="/tools/package.bin?build=7",
            user_agent="curl/7.88.1" if tool == "curl" else "Wget/1.21.3",
            status_code=200,
            response_body_len=10000,
        ),
    )
    client = [
        c.args[0]
        for c in emitters["zeek_conn"].emit.call_args_list
        if c.args[0].network.src_ip == source.ip and c.args[0].network.dst_port == 8080
    ]
    assert client
    assert all(e.process is not None and e.process.pid == pid for e in client)
    assert all(e.process.command_line == command for e in client)


@pytest.mark.parametrize(
    "command",
    [
        "curl --config .curlrc https://origin.example/a",
        "curl --request-target /different https://origin.example/a",
        "curl --get --data x=y https://origin.example/a",
        "curl -d payload https://origin.example/a",
        "curl https://other.example/a",
    ],
)
def test_unsupported_or_different_effective_intent_is_not_reused(command: str) -> None:
    assert not _literal_http_process_owns_request(
        image="/usr/bin/curl",
        command_line=command,
        hostname="origin.example",
        dst_port=443,
        method="GET",
        uri="/a",
    )


@pytest.mark.parametrize("linux", [False, True])
def test_fallback_cli_command_preserves_known_origin_resource(linux: bool) -> None:
    generator, _ = _generator([])
    if linux:
        _, source, _ = _seed_linux_proxy_client_user_session(generator)
    else:
        _seed_proxy_client_user_session(generator)
        source = generator._ip_to_system["10.0.1.10"]
    proxy = generator._ip_to_system["10.0.3.10"]
    context = ProxyContext(
        client_ip=source.ip,
        method="HEAD",
        url="https://download.example/tools/a?version=9",
        host="download.example",
        status_code=200,
        user_agent="curl/7.88.1",
        proxy_fqdn="proxy.example",
    )
    pid, _ = generator._ensure_explicit_proxy_client_process(
        source_system=source,
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        proxy_context=context,
        proxy_sys=proxy,
        dst_port=443,
    )
    process = generator.state_manager.get_process(source.hostname, pid)
    assert process is not None
    assert (
        _extract_http_url_from_command(process.command_line)
        == "https://download.example/tools/a?version=9"
    )
    assert _http_method_for_process_command(process.command_line) == "HEAD"


@pytest.mark.parametrize("state", ["S0", "REJ", "RSTO", "RSTR"])
@pytest.mark.parametrize("port", [80, 443])
def test_proxy_gateway_attempt_cannot_inherit_application_payload(
    monkeypatch: pytest.MonkeyPatch, state: str, port: int
) -> None:
    from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner

    monkeypatch.setattr(ProxyPhasePlanner, "_gateway_conn_state", staticmethod(lambda *_: state))
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
    source = generator._ip_to_system["10.0.1.10"]
    generator.generate_connection(
        src_ip=source.ip,
        dst_ip="203.0.113.88",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=port,
        service="ssl" if port == 443 else "http",
        duration=1.0,
        orig_bytes=2000,
        resp_bytes=20000,
        source_system=source,
        hostname="download.example",
        conn_state="SF",
        proxy=ProxyContext(
            client_ip=source.ip,
            method="CONNECT" if port == 443 else "GET",
            url="download.example:443" if port == 443 else "http://download.example/a",
            host="download.example",
            status_code=502,
            cs_bytes=300,
            sc_bytes=700,
            cache_result="GATEWAY_ERROR",
            proxy_fqdn="proxy.example",
        ),
    )
    origins = [
        c.args[0]
        for c in emitters["zeek_conn"].emit.call_args_list
        if c.args[0].network.src_ip == "10.0.3.10" and c.args[0].network.dst_port == port
    ]
    assert len(origins) == 1
    event = origins[0]
    assert event.network.conn_state == state
    assert event.network.orig_bytes == event.network.resp_bytes == 0
    assert "D" not in event.network.history and "d" not in event.network.history
    assert event.protocol.http is None and event.protocol.ssl is None
    assert event.network.service == ""
    assert emitters["proxy_access"].emit.call_args.args[0].protocol.proxy.status_code == 502
