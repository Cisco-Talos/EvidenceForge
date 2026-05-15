# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for shared HTTP content helpers."""

import random

from evidenceforge.generation.activity.http_content import (
    infer_mime_type_from_path,
    is_health_endpoint_path,
    is_stable_resource_path,
    normalize_mime_type_for_path,
    response_size_for_health_endpoint,
    response_size_for_mime,
    response_size_for_status,
)


def test_infer_mime_type_strips_query_and_fragment():
    assert infer_mime_type_from_path("/assets/status.gif?cache=1#view") == "image/gif"


def test_known_extension_overrides_supplied_content_type():
    assert normalize_mime_type_for_path("/status.gif", "text/html") == "image/gif"


def test_unknown_extension_keeps_supplied_content_type():
    assert normalize_mime_type_for_path("/download/custom.blob", "application/octet-stream") == (
        "application/octet-stream"
    )


def test_response_size_for_gif_uses_image_range():
    size = response_size_for_mime(random.Random(42), "image/gif")
    assert 500 <= size <= 50_000


def test_error_response_size_is_template_stable_by_status_host_and_uri():
    first = response_size_for_status(404, "portal.example.com", "/.git/HEAD")
    second = response_size_for_status(404, "portal.example.com", "/.git/HEAD")
    sibling = response_size_for_status(404, "portal.example.com", "/admin")

    assert first == second
    assert 128 <= first <= 2000
    assert abs(first - sibling) < 2000


def test_stable_resource_path_identifies_static_web_content():
    assert is_stable_resource_path("/assets/main.css")
    assert is_stable_resource_path("/assets/vendor.js?cache=1")
    assert is_stable_resource_path("/robots.txt")
    assert is_stable_resource_path("/index.html")
    assert is_stable_resource_path("/api/v1/health")
    assert not is_stable_resource_path("/api/v1/events")


def test_success_response_size_is_stable_for_same_resource():
    first = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    second = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    sibling = response_size_for_status(200, "portal.example.com", "/assets/vendor.js")

    assert first == second
    assert first != sibling


def test_health_endpoint_response_sizes_are_small_and_stable():
    assert is_health_endpoint_path("/api/v1/health?probe=1")

    first = response_size_for_health_endpoint(200, "portal.example.com", "/api/v1/health")
    second = response_size_for_status(200, "portal.example.com", "/api/v1/health")
    status = response_size_for_status(200, "portal.example.com", "/status")

    assert first == second
    assert 42 <= first <= 720
    assert 18 <= status <= 180
