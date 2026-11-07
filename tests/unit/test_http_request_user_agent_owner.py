# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical selected request headers survive process attribution defaults."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HttpContext
from evidenceforge.generation.actions.network_transaction_planner import (
    NetworkTransactionPlanner,
    _NetworkOccurrenceDraft,
)
from evidenceforge.models import System


@pytest.mark.parametrize(
    "user_agent",
    ["curl/8.7.1", "Microsoft-CryptoAPI/10.0", "Mozilla/5.0 Chrome/121.0", "Custom spoofed agent"],
)
@pytest.mark.parametrize("method", ["GET", "CONNECT", "POST"])
@pytest.mark.parametrize("finalized", [False, True])
def test_process_attribution_preserves_bundle_finalized_wire_header(
    user_agent: str, method: str, finalized: bool
) -> None:
    executor = SimpleNamespace(browser_user_agent_for_process=Mock(return_value="Other browser"))
    planner = NetworkTransactionPlanner(executor)
    http = HttpContext(user_agent=user_agent, method=method)
    event = _NetworkOccurrenceDraft(
        timestamp=datetime(2026, 11, 2, tzinfo=UTC),
        http=http,
        network=SimpleNamespace(initiating_pid=42),
    )
    planner._bind_browser_user_agent_to_process(
        event=event,
        source_system=System(hostname="client", ip="10.0.0.1", os="Windows 11", type="workstation"),
        hostname="example.test",
        request_header_finalized=finalized,
    )
    assert event.http is http
    executor.browser_user_agent_for_process.assert_not_called()


@pytest.mark.parametrize("known_absent,expected", [(True, ""), (False, "Process browser")])
def test_only_unspecified_header_uses_process_default(known_absent: bool, expected: str) -> None:
    executor = SimpleNamespace(browser_user_agent_for_process=Mock(return_value="Process browser"))
    planner = NetworkTransactionPlanner(executor)
    event = _NetworkOccurrenceDraft(
        timestamp=datetime(2026, 11, 2, tzinfo=UTC),
        http=HttpContext(user_agent_known_absent=known_absent),
        network=SimpleNamespace(initiating_pid=42),
    )
    planner._bind_browser_user_agent_to_process(
        event=event,
        source_system=System(hostname="client", ip="10.0.0.1", os="macOS 27", type="workstation"),
        hostname="example.test",
    )
    assert event.http.user_agent == expected
    assert executor.browser_user_agent_for_process.call_count == int(not known_absent)


@pytest.mark.parametrize(
    "image,family",
    [
        ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "chrome"),
        (
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            "chrome",
        ),
        (
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper (Renderer)",
            "chrome",
        ),
        (r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "edge"),
        ("/usr/bin/firefox", "firefox"),
        ("/Applications/zoom.us.app/Contents/MacOS/zoom.us", ""),
    ],
)
def test_browser_identity_includes_native_network_helpers(image: str, family: str) -> None:
    from evidenceforge.generation.activity.proxy_user_agents import _browser_family_for_process

    assert _browser_family_for_process(image) == family


def test_owner_browser_header_is_selected_before_proxy_wire_budget() -> None:
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.state_manager import StateManager

    generator = ActivityGenerator(StateManager(), {})
    source = System(hostname="client", ip="10.0.0.1", os="macOS 27", type="workstation")
    proxy = System(
        hostname="proxy", ip="10.0.0.2", os="Ubuntu 24.04", type="server", roles=["forward_proxy"]
    )
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/155.0.0.0 Safari/537.36"
    context = generator._build_proxy_context(
        src_ip=source.ip,
        dst_ip="93.184.216.34",
        dst_port=443,
        service="ssl",
        duration=2,
        orig_bytes=1000,
        resp_bytes=5000,
        hostname="example.com",
        source_system=source,
        proxy_sys=proxy,
        explicit_mode=True,
        client_user_agent=ua,
    )
    assert context.user_agent == ua
    assert context.method == "CONNECT"
    assert context.cs_bytes >= len(ua) + len("example.com:443")


@pytest.mark.parametrize(
    "user_agent", ["Mozilla/5.0 (Windows NT 10.0) Firefox/158.0", "curl/8.7.1", ""]
)
def test_explicit_request_header_survives_host_and_domain_defaults(user_agent: str) -> None:
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.state_manager import StateManager

    generator = ActivityGenerator(StateManager(), {})
    source = System(hostname="client", ip="10.0.0.1", os="macOS 27", type="workstation")
    proxy = System(
        hostname="proxy", ip="10.0.0.2", os="Ubuntu 24.04", type="server", roles=["forward_proxy"]
    )
    context = generator._build_proxy_context(
        src_ip=source.ip,
        dst_ip="93.184.216.34",
        dst_port=443,
        service="ssl",
        duration=2,
        orig_bytes=1000,
        resp_bytes=5000,
        hostname="example.com",
        source_system=source,
        proxy_sys=proxy,
        explicit_mode=True,
        http=HttpContext(
            host="example.com", user_agent=user_agent, user_agent_known_absent=not user_agent
        ),
    )
    assert context.user_agent == user_agent


@pytest.mark.parametrize(
    "image,expected",
    [
        ("chrome.exe", "chrome"),
        ("chromium-browser", "chrome"),
        ("msedge.exe", "edge"),
        ("firefox", "firefox"),
        ("Safari", "safari"),
        ("opera.exe", "opera"),
        ("Google Chrome Helper", ""),
    ],
)
def test_historical_frozen_user_agent_catalog_keeps_prior_classification(
    monkeypatch: pytest.MonkeyPatch, image: str, expected: str
) -> None:
    from evidenceforge.generation.activity import proxy_user_agents

    monkeypatch.setattr(proxy_user_agents, "load_proxy_user_agents", lambda: {"workstation": {}})
    assert proxy_user_agents._browser_family_for_process(image) == expected
