# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Wire metadata omits client fragments while preserving higher-level intent."""

import random
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HttpContext, ProxyContext
from evidenceforge.events.http_semantics import http_wire_referrer, http_wire_target
from evidenceforge.generation.actions.browser_session import (
    BrowserSessionActionBundle,
    BrowserSessionRequest,
)
from evidenceforge.generation.activity.browsing_session import BrowsingRequest
from evidenceforge.generation.activity.network_http import _http_context_from_process_command


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("/docs#section", "/docs"),
        ("https://example.test/a?b=1&b=2#x", "https://example.test/a?b=1&b=2"),
        ("/a%23b?q=%23value#tab", "/a%23b?q=%23value"),
        ("/a?#", "/a?"),
        ("example.test:443", "example.test:443"),
        ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ("*", "*"),
        ("/", "/"),
        ("", ""),
    ],
)
def test_target_normalization_preserves_wire_uri_form(reference: str, expected: str) -> None:
    assert http_wire_target(reference) == expected
    assert HttpContext(uri=reference).uri == expected
    assert ProxyContext(client_ip="192.0.2.1", url=reference).url == expected


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        (
            "https://user:pass@example.test:8443/a?q=%23#private",
            "https://example.test:8443/a?q=%23",
        ),
        ("https://u:p@[2001:db8::1]:443/a?#x", "https://[2001:db8::1]:443/a?"),
        ("//u@example.test/p#x", "//example.test/p"),
        ("/partial?q=1#fragment", "/partial?q=1"),
        ("https://example.test/p%23text", "https://example.test/p%23text"),
        ("https://[invalid", ""),
    ],
)
def test_referrer_omits_userinfo_and_fragment(reference: str, expected: str) -> None:
    assert http_wire_referrer(reference) == expected
    assert HttpContext(referrer=reference).referrer == expected
    assert ProxyContext(client_ip="192.0.2.1", referrer=reference).referrer == expected


def test_context_replacement_keeps_wire_semantics() -> None:
    http = replace(HttpContext(), uri="/a%23b?q=1#nav", referrer="https://u:p@ref.test/#x")
    proxy = replace(ProxyContext(client_ip="192.0.2.1"), url="http://origin.test/a#nav")
    assert http.uri == "/a%23b?q=1" and http.referrer == "https://ref.test/"
    assert proxy.url == "http://origin.test/a"


def test_process_command_keeps_navigation_intent_but_sends_only_wire_target() -> None:
    command = "curl 'https://example.test/file?q=%23keep#client-state'"
    result = _http_context_from_process_command("curl", command, response_body_len=123)
    assert result is not None
    assert result[0].uri == "/file?q=%23keep"
    assert command.endswith("#client-state'")


def test_browser_cache_uses_wire_resource_while_navigation_keeps_fragment() -> None:
    request = BrowserSessionRequest(
        "192.0.2.1", "192.0.2.2", datetime(2026, 1, 1, tzinfo=UTC), "example.test", 443
    )
    bundle = BrowserSessionActionBundle(request, Mock(), random.Random(12), static_cache_seen={})
    first = BrowsingRequest(
        0, "example.test", "/asset.js#one", "GET", "application/javascript", "", 1, False, 100, 0
    )
    second = replace(first, path="/asset.js#two")
    assert not bundle._is_cached_static_asset(first)
    assert bundle._is_cached_static_asset(second)
    assert first.path == "/asset.js#one" and second.path == "/asset.js#two"
